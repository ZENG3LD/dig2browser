use std::time::Duration;

use tokio::sync::{mpsc, oneshot, watch};

use crate::detect::LaunchConfig;
use crate::identity::IdentityProfile;
use crate::stealth::StealthConfig;

use super::contract::{
    validate_selector, AgentCommand, AgentReply, BrowserSnapshot, Capability, CapabilitySet,
    ContractError, DocumentState, ElementRef, RuntimeFailureKind, WorkerLifecycle,
};
use super::mobile::MobileLayout;
use super::runtime::{BrowserRuntime, RealBrowserRuntime, RuntimeError};

const MAX_QUEUE_CAPACITY: usize = 256;
const MAX_KEY_BYTES: usize = 64;
const MAX_TEXT_BYTES: usize = 64 * 1024;
const MAX_SCRIPT_BYTES: usize = 64 * 1024;
const MAX_SCRIPT_RESULT_BYTES: usize = 4 * 1024 * 1024;
const DEFAULT_COMMAND_TIMEOUT: Duration = Duration::from_secs(90);
const MIN_COMMAND_TIMEOUT: Duration = Duration::from_millis(100);
const MAX_COMMAND_TIMEOUT: Duration = Duration::from_secs(15 * 60);

#[derive(Debug, Clone)]
pub struct BrowserWorkerConfig {
    pub queue_capacity: usize,
    pub command_timeout: Duration,
    pub launch: LaunchConfig,
    pub stealth: StealthConfig,
    pub mobile_layout: Option<MobileLayout>,
}

impl Default for BrowserWorkerConfig {
    fn default() -> Self {
        Self {
            queue_capacity: 32,
            command_timeout: DEFAULT_COMMAND_TIMEOUT,
            launch: LaunchConfig::default(),
            stealth: StealthConfig::default(),
            mobile_layout: None,
        }
    }
}

/// Cloneable command handle for a single-owner browser actor.
#[derive(Clone)]
pub struct BrowserWorker {
    commands: mpsc::Sender<Envelope>,
    snapshot: watch::Receiver<BrowserSnapshot>,
    stopped: watch::Receiver<bool>,
}

impl BrowserWorker {
    pub fn spawn(
        identity: IdentityProfile,
        capabilities: CapabilitySet,
        config: BrowserWorkerConfig,
    ) -> Result<Self, WorkerError> {
        validate_queue_capacity(config.queue_capacity)?;
        validate_command_timeout(config.command_timeout)?;
        let runtime = RealBrowserRuntime::new(
            identity.clone(),
            config.launch,
            config.stealth,
            config.mobile_layout,
        )?;
        Self::spawn_with_runtime_and_timeout(
            identity,
            capabilities,
            config.queue_capacity,
            config.command_timeout,
            runtime,
        )
    }

    pub fn spawn_with_runtime<R>(
        identity: IdentityProfile,
        capabilities: CapabilitySet,
        queue_capacity: usize,
        runtime: R,
    ) -> Result<Self, WorkerError>
    where
        R: BrowserRuntime,
    {
        Self::spawn_with_runtime_and_timeout(
            identity,
            capabilities,
            queue_capacity,
            DEFAULT_COMMAND_TIMEOUT,
            runtime,
        )
    }

    pub fn spawn_with_runtime_and_timeout<R>(
        identity: IdentityProfile,
        capabilities: CapabilitySet,
        queue_capacity: usize,
        command_timeout: Duration,
        runtime: R,
    ) -> Result<Self, WorkerError>
    where
        R: BrowserRuntime,
    {
        validate_queue_capacity(queue_capacity)?;
        validate_command_timeout(command_timeout)?;
        let initial = BrowserSnapshot::starting(identity.id().to_owned());
        let (commands, receiver) = mpsc::channel(queue_capacity);
        let (snapshot_tx, snapshot) = watch::channel(initial.clone());
        let (stopped_tx, stopped) = watch::channel(false);
        tokio::spawn(run_actor(
            Box::new(runtime),
            capabilities,
            receiver,
            snapshot_tx,
            initial,
            command_timeout,
            stopped_tx,
        ));
        Ok(Self {
            commands,
            snapshot,
            stopped,
        })
    }

    pub async fn execute(&self, command: AgentCommand) -> Result<AgentReply, WorkerError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.commands
            .send(Envelope {
                command,
                reply: reply_tx,
            })
            .await
            .map_err(|_| WorkerError::QueueClosed)?;
        reply_rx.await.map_err(|_| WorkerError::WorkerStopped)?
    }

    pub fn snapshot(&self) -> BrowserSnapshot {
        self.snapshot.borrow().clone()
    }

    pub fn subscribe(&self) -> watch::Receiver<BrowserSnapshot> {
        self.snapshot.clone()
    }

    pub async fn wait_until_settled(&self) -> Result<BrowserSnapshot, WorkerError> {
        let mut receiver = self.snapshot.clone();
        loop {
            let snapshot = receiver.borrow().clone();
            match snapshot.lifecycle {
                WorkerLifecycle::Ready | WorkerLifecycle::Degraded => return Ok(snapshot),
                WorkerLifecycle::Stopped => return Err(WorkerError::WorkerStopped),
                _ => receiver
                    .changed()
                    .await
                    .map_err(|_| WorkerError::WorkerStopped)?,
            }
        }
    }

    pub async fn shutdown(&self) -> Result<(), WorkerError> {
        if *self.stopped.borrow() {
            return Ok(());
        }
        let command_result = self.execute(AgentCommand::Shutdown).await.map(|_| ());
        let stopped_result = self.wait_stopped().await;
        match (command_result, stopped_result) {
            (Err(error), _) | (Ok(()), Err(error)) => Err(error),
            (Ok(()), Ok(())) => Ok(()),
        }
    }

    /// Wait until the actor has closed and dropped its runtime, including all
    /// protocol transports and owned process-containment handles.
    pub async fn wait_stopped(&self) -> Result<(), WorkerError> {
        let mut stopped = self.stopped.clone();
        while !*stopped.borrow() {
            stopped
                .changed()
                .await
                .map_err(|_| WorkerError::WorkerStopped)?;
        }
        Ok(())
    }
}

struct Envelope {
    command: AgentCommand,
    reply: oneshot::Sender<Result<AgentReply, WorkerError>>,
}

async fn run_actor(
    mut runtime: Box<dyn BrowserRuntime>,
    capabilities: CapabilitySet,
    mut commands: mpsc::Receiver<Envelope>,
    snapshots: watch::Sender<BrowserSnapshot>,
    mut snapshot: BrowserSnapshot,
    command_timeout: Duration,
    stopped: watch::Sender<bool>,
) {
    match tokio::time::timeout(command_timeout, runtime.start()).await {
        Ok(Ok(())) => {
            snapshot.lifecycle = WorkerLifecycle::Ready;
            snapshot.last_failure = None;
        }
        Ok(Err(error)) => mark_degraded(&mut snapshot, error),
        Err(_) => mark_timeout_degraded(&mut snapshot),
    }
    snapshots.send_replace(snapshot.clone());

    while let Some(envelope) = commands.recv().await {
        let is_shutdown = matches!(envelope.command, AgentCommand::Shutdown);
        let result = match tokio::time::timeout(
            command_timeout,
            handle_command(
                &mut *runtime,
                &capabilities,
                &mut snapshot,
                &snapshots,
                envelope.command,
            ),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => {
                mark_timeout_degraded(&mut snapshot);
                snapshots.send_replace(snapshot.clone());
                Err(WorkerError::CommandTimeout(command_timeout))
            }
        };
        let _ = envelope.reply.send(result);
        if is_shutdown {
            break;
        }
    }

    if snapshot.lifecycle != WorkerLifecycle::Stopped {
        snapshot.lifecycle = WorkerLifecycle::ShuttingDown;
        snapshots.send_replace(snapshot.clone());
        match tokio::time::timeout(command_timeout, runtime.close()).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => snapshot.last_failure = Some(error.kind()),
            Err(_) => snapshot.last_failure = Some(RuntimeFailureKind::Timeout),
        }
        snapshot.lifecycle = WorkerLifecycle::Stopped;
        snapshot.current_origin = None;
        snapshots.send_replace(snapshot);
    }
    drop(runtime);
    stopped.send_replace(true);
}

async fn handle_command(
    runtime: &mut dyn BrowserRuntime,
    capabilities: &CapabilitySet,
    snapshot: &mut BrowserSnapshot,
    snapshots: &watch::Sender<BrowserSnapshot>,
    command: AgentCommand,
) -> Result<AgentReply, WorkerError> {
    let required = command.required_capability();
    if !capabilities.contains(required) {
        return Err(WorkerError::CapabilityDenied(required));
    }

    if snapshot.lifecycle == WorkerLifecycle::Degraded
        && !matches!(command, AgentCommand::Restart | AgentCommand::Shutdown)
    {
        return Err(WorkerError::Unavailable);
    }

    // Rotate before the next navigation, never after it. Restarting after a
    // successful navigation would discard the page before capture/extraction.
    if matches!(&command, AgentCommand::Navigate { .. }) && runtime.needs_restart() {
        restart_runtime(runtime, snapshot, snapshots).await?;
    }

    let result = match command {
        AgentCommand::ClickAt { x, y } => {
            validate_finite(&[x, y])?;
            runtime
                .click_at(x, y)
                .await
                .map(|_| AgentReply::Acknowledged)
        }
        AgentCommand::Wheel {
            x,
            y,
            delta_x,
            delta_y,
        } => {
            validate_finite(&[x, y, delta_x, delta_y])?;
            runtime
                .wheel(x, y, delta_x, delta_y)
                .await
                .map(|_| AgentReply::Acknowledged)
        }
        AgentCommand::KeyPress { key } => {
            if key.is_empty() || key.len() > MAX_KEY_BYTES || key.contains('\0') {
                return Err(WorkerError::InvalidInput);
            }
            runtime
                .key_press(&key)
                .await
                .map(|_| AgentReply::Acknowledged)
        }
        AgentCommand::ResolveElement { selector } => {
            validate_selector(&selector)?;
            runtime.resolve_element(&selector).await.map(|_| {
                AgentReply::Element(
                    ElementRef::new(selector, snapshot.page_epoch)
                        .expect("selector was validated before runtime call"),
                )
            })
        }
        AgentCommand::ClickElement { element } => {
            validate_element_epoch(&element, snapshot.page_epoch)?;
            runtime
                .click_element(element.selector())
                .await
                .map(|_| AgentReply::Acknowledged)
        }
        AgentCommand::TypeElement { element, text } => {
            validate_element_epoch(&element, snapshot.page_epoch)?;
            if text.len() > MAX_TEXT_BYTES || text.contains('\0') {
                return Err(WorkerError::InvalidInput);
            }
            runtime
                .type_element(element.selector(), &text)
                .await
                .map(|_| AgentReply::Acknowledged)
        }
        AgentCommand::ReadElementText { element } => {
            validate_element_epoch(&element, snapshot.page_epoch)?;
            runtime
                .read_element_text(element.selector())
                .await
                .map(AgentReply::Text)
        }
        AgentCommand::Evaluate { script } => {
            if script.is_empty() || script.len() > MAX_SCRIPT_BYTES || script.contains('\0') {
                return Err(WorkerError::InvalidInput);
            }
            runtime.evaluate(&script).await.and_then(|value| {
                let encoded = serde_json::to_vec(&value)
                    .map_err(|_| RuntimeError::new(RuntimeFailureKind::Protocol))?;
                if encoded.len() > MAX_SCRIPT_RESULT_BYTES {
                    return Err(RuntimeError::new(RuntimeFailureKind::Protocol));
                }
                Ok(AgentReply::ScriptValue(value))
            })
        }
        AgentCommand::Navigate { url } => {
            validate_navigation_url(&url)?;
            runtime.navigate(&url).await.map(|state| {
                snapshot.page_epoch = snapshot.page_epoch.saturating_add(1);
                snapshot.current_origin = sanitized_origin(&state);
                AgentReply::Acknowledged
            })
        }
        AgentCommand::Capture { policy } => runtime.capture(policy).await.map(AgentReply::Capture),
        AgentCommand::Restart => {
            return restart_runtime(runtime, snapshot, snapshots)
                .await
                .map(|_| AgentReply::Acknowledged);
        }
        AgentCommand::Shutdown => {
            snapshot.lifecycle = WorkerLifecycle::ShuttingDown;
            snapshots.send_replace(snapshot.clone());
            let close_result = runtime.close().await;
            snapshot.lifecycle = WorkerLifecycle::Stopped;
            snapshot.current_origin = None;
            if let Err(error) = close_result {
                snapshot.last_failure = Some(error.kind());
                snapshots.send_replace(snapshot.clone());
                return Err(WorkerError::Runtime(error));
            }
            snapshot.last_failure = None;
            snapshots.send_replace(snapshot.clone());
            return Ok(AgentReply::Acknowledged);
        }
    };

    let reply = match result {
        Ok(reply) => reply,
        Err(error) if error.kind() == RuntimeFailureKind::ObservationMissing => {
            snapshot.lifecycle = WorkerLifecycle::Ready;
            snapshot.last_failure = None;
            snapshots.send_replace(snapshot.clone());
            return Err(WorkerError::Runtime(error));
        }
        Err(error) => {
            mark_degraded(snapshot, error);
            snapshots.send_replace(snapshot.clone());
            return Err(WorkerError::Runtime(error));
        }
    };

    snapshot.lifecycle = WorkerLifecycle::Ready;
    snapshot.last_failure = None;
    snapshots.send_replace(snapshot.clone());
    Ok(reply)
}

async fn restart_runtime(
    runtime: &mut dyn BrowserRuntime,
    snapshot: &mut BrowserSnapshot,
    snapshots: &watch::Sender<BrowserSnapshot>,
) -> Result<(), WorkerError> {
    snapshot.lifecycle = WorkerLifecycle::Restarting;
    snapshot.page_epoch = snapshot.page_epoch.saturating_add(1);
    snapshot.current_origin = None;
    snapshots.send_replace(snapshot.clone());
    match runtime.restart().await {
        Ok(()) => {
            snapshot.lifecycle = WorkerLifecycle::Ready;
            snapshot.restart_count = snapshot.restart_count.saturating_add(1);
            snapshot.last_failure = None;
            snapshots.send_replace(snapshot.clone());
            Ok(())
        }
        Err(error) => {
            mark_degraded(snapshot, error);
            snapshots.send_replace(snapshot.clone());
            Err(WorkerError::Runtime(error))
        }
    }
}

fn mark_degraded(snapshot: &mut BrowserSnapshot, error: RuntimeError) {
    snapshot.lifecycle = WorkerLifecycle::Degraded;
    snapshot.current_origin = None;
    snapshot.last_failure = Some(error.kind());
}

fn mark_timeout_degraded(snapshot: &mut BrowserSnapshot) {
    snapshot.lifecycle = WorkerLifecycle::Degraded;
    snapshot.current_origin = None;
    snapshot.last_failure = Some(RuntimeFailureKind::Timeout);
}

fn validate_queue_capacity(capacity: usize) -> Result<(), WorkerError> {
    if !(1..=MAX_QUEUE_CAPACITY).contains(&capacity) {
        return Err(WorkerError::InvalidQueueCapacity);
    }
    Ok(())
}

fn validate_command_timeout(timeout: Duration) -> Result<(), WorkerError> {
    if (MIN_COMMAND_TIMEOUT..=MAX_COMMAND_TIMEOUT).contains(&timeout) {
        Ok(())
    } else {
        Err(WorkerError::InvalidCommandTimeout)
    }
}

fn validate_finite(values: &[f64]) -> Result<(), WorkerError> {
    if values.iter().all(|value| value.is_finite()) {
        Ok(())
    } else {
        Err(WorkerError::InvalidInput)
    }
}

fn validate_element_epoch(element: &ElementRef, current_epoch: u64) -> Result<(), WorkerError> {
    if element.page_epoch() == current_epoch {
        Ok(())
    } else {
        Err(WorkerError::StaleElement {
            element_epoch: element.page_epoch(),
            current_epoch,
        })
    }
}

fn validate_navigation_url(value: &str) -> Result<(), WorkerError> {
    let url = url::Url::parse(value).map_err(|_| WorkerError::InvalidInput)?;
    if matches!(url.scheme(), "http" | "https") && url.host_str().is_some() {
        Ok(())
    } else {
        Err(WorkerError::InvalidInput)
    }
}

fn sanitized_origin(state: &DocumentState) -> Option<String> {
    let url = url::Url::parse(&state.url).ok()?;
    let host = url.host_str()?;
    let mut origin = format!("{}://{}", url.scheme(), host);
    if let Some(port) = url.port() {
        origin.push(':');
        origin.push_str(&port.to_string());
    }
    Some(origin)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkerError {
    InvalidQueueCapacity,
    InvalidCommandTimeout,
    QueueClosed,
    WorkerStopped,
    CapabilityDenied(Capability),
    Unavailable,
    InvalidInput,
    CommandTimeout(Duration),
    StaleElement {
        element_epoch: u64,
        current_epoch: u64,
    },
    Contract(ContractError),
    Runtime(RuntimeError),
}

impl std::fmt::Display for WorkerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidQueueCapacity => write!(formatter, "queue capacity must be 1 to 256"),
            Self::InvalidCommandTimeout => write!(
                formatter,
                "command timeout must be between 100 milliseconds and 15 minutes"
            ),
            Self::QueueClosed => write!(formatter, "browser worker queue is closed"),
            Self::WorkerStopped => write!(formatter, "browser worker stopped"),
            Self::CapabilityDenied(capability) => {
                write!(
                    formatter,
                    "browser capability {capability:?} is not granted"
                )
            }
            Self::Unavailable => write!(formatter, "browser worker is degraded"),
            Self::InvalidInput => write!(formatter, "browser command input is invalid"),
            Self::CommandTimeout(timeout) => {
                write!(formatter, "browser command timed out after {timeout:?}")
            }
            Self::StaleElement {
                element_epoch,
                current_epoch,
            } => write!(
                formatter,
                "element belongs to page epoch {element_epoch}; current epoch is {current_epoch}"
            ),
            Self::Contract(error) => write!(formatter, "{error}"),
            Self::Runtime(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for WorkerError {}

impl From<ContractError> for WorkerError {
    fn from(error: ContractError) -> Self {
        Self::Contract(error)
    }
}

impl From<RuntimeError> for WorkerError {
    fn from(error: RuntimeError) -> Self {
        Self::Runtime(error)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use futures::future::BoxFuture;

    use crate::identity::{BrowserBackend, DevicePersona, IdentityClass};

    use super::*;
    use crate::agentic::contract::{
        CaptureArtifact, CapturePolicy, L2Capability, L3Capability, RuntimeFailureKind,
    };
    use crate::agentic::runtime::{BrowserRuntime, RuntimeResult};

    #[derive(Default)]
    struct FakeState {
        starts: u32,
        restarts: u32,
        closes: u32,
        navigations: Vec<String>,
        fail_navigation: bool,
        restart_needed: bool,
        navigation_delay: Option<Duration>,
        missing_selector: bool,
    }

    struct FakeRuntime {
        state: Arc<Mutex<FakeState>>,
    }

    impl BrowserRuntime for FakeRuntime {
        fn start(&mut self) -> BoxFuture<'_, RuntimeResult<()>> {
            self.state.lock().unwrap().starts += 1;
            Box::pin(async { Ok(()) })
        }

        fn restart(&mut self) -> BoxFuture<'_, RuntimeResult<()>> {
            let mut state = self.state.lock().unwrap();
            state.restarts += 1;
            state.restart_needed = false;
            Box::pin(async { Ok(()) })
        }

        fn close(&mut self) -> BoxFuture<'_, RuntimeResult<()>> {
            self.state.lock().unwrap().closes += 1;
            Box::pin(async { Ok(()) })
        }

        fn needs_restart(&self) -> bool {
            self.state.lock().unwrap().restart_needed
        }

        fn navigate<'a>(&'a mut self, url: &'a str) -> BoxFuture<'a, RuntimeResult<DocumentState>> {
            let mut state = self.state.lock().unwrap();
            if state.fail_navigation {
                return Box::pin(async { Err(RuntimeError::new(RuntimeFailureKind::Navigation)) });
            }
            state.navigations.push(url.to_owned());
            let navigation_delay = state.navigation_delay;
            let url = url.to_owned();
            Box::pin(async move {
                if let Some(delay) = navigation_delay {
                    tokio::time::sleep(delay).await;
                }
                Ok(DocumentState {
                    url,
                    title: "page".into(),
                    ready_state: "complete".into(),
                    http_status: Some(200),
                })
            })
        }

        fn click_at(&mut self, _x: f64, _y: f64) -> BoxFuture<'_, RuntimeResult<()>> {
            Box::pin(async { Ok(()) })
        }

        fn wheel(
            &mut self,
            _x: f64,
            _y: f64,
            _delta_x: f64,
            _delta_y: f64,
        ) -> BoxFuture<'_, RuntimeResult<()>> {
            Box::pin(async { Ok(()) })
        }

        fn key_press<'a>(&'a mut self, _key: &'a str) -> BoxFuture<'a, RuntimeResult<()>> {
            Box::pin(async { Ok(()) })
        }

        fn resolve_element<'a>(
            &'a mut self,
            _selector: &'a str,
        ) -> BoxFuture<'a, RuntimeResult<()>> {
            if self.state.lock().unwrap().missing_selector {
                return Box::pin(async {
                    Err(RuntimeError::new(RuntimeFailureKind::ObservationMissing))
                });
            }
            Box::pin(async { Ok(()) })
        }

        fn click_element<'a>(&'a mut self, _selector: &'a str) -> BoxFuture<'a, RuntimeResult<()>> {
            Box::pin(async { Ok(()) })
        }

        fn type_element<'a>(
            &'a mut self,
            _selector: &'a str,
            _text: &'a str,
        ) -> BoxFuture<'a, RuntimeResult<()>> {
            Box::pin(async { Ok(()) })
        }

        fn read_element_text<'a>(
            &'a mut self,
            _selector: &'a str,
        ) -> BoxFuture<'a, RuntimeResult<String>> {
            Box::pin(async { Ok("text".into()) })
        }

        fn evaluate<'a>(
            &'a mut self,
            script: &'a str,
        ) -> BoxFuture<'a, RuntimeResult<serde_json::Value>> {
            let script = script.to_owned();
            Box::pin(async move { Ok(serde_json::json!({ "script": script })) })
        }

        fn capture(
            &mut self,
            _policy: CapturePolicy,
        ) -> BoxFuture<'_, RuntimeResult<CaptureArtifact>> {
            Box::pin(async {
                Ok(CaptureArtifact::StateOnly(DocumentState {
                    url: "https://example.test/private?token=secret".into(),
                    title: "page".into(),
                    ready_state: "complete".into(),
                    http_status: Some(200),
                }))
            })
        }
    }

    fn identity() -> IdentityProfile {
        IdentityProfile::new(
            std::env::temp_dir(),
            "agentic-test",
            IdentityClass::Public,
            BrowserBackend::Chromium,
            DevicePersona::DesktopNative,
        )
        .unwrap()
    }

    fn capabilities() -> CapabilitySet {
        CapabilitySet::new([
            Capability::L2(L2Capability::Inspect),
            Capability::L2(L2Capability::Interact),
            Capability::L3(L3Capability::Navigate),
            Capability::L3(L3Capability::Capture),
            Capability::L3(L3Capability::Lifecycle),
        ])
        .unwrap()
    }

    #[tokio::test]
    async fn actor_updates_sanitized_snapshot_and_rejects_stale_element() {
        let state = Arc::new(Mutex::new(FakeState::default()));
        let worker = BrowserWorker::spawn_with_runtime(
            identity(),
            capabilities(),
            4,
            FakeRuntime {
                state: Arc::clone(&state),
            },
        )
        .unwrap();
        assert_eq!(
            worker.wait_until_settled().await.unwrap().lifecycle,
            WorkerLifecycle::Ready
        );

        let element = match worker
            .execute(AgentCommand::ResolveElement {
                selector: "#submit".into(),
            })
            .await
            .unwrap()
        {
            AgentReply::Element(element) => element,
            reply => panic!("unexpected reply: {reply:?}"),
        };

        worker
            .execute(AgentCommand::Navigate {
                url: "https://example.test/private?token=secret".into(),
            })
            .await
            .unwrap();
        let snapshot = worker.snapshot();
        assert_eq!(
            snapshot.current_origin.as_deref(),
            Some("https://example.test")
        );
        assert!(!format!("{snapshot:?}").contains("token"));

        let error = worker
            .execute(AgentCommand::ClickElement { element })
            .await
            .unwrap_err();
        assert!(matches!(error, WorkerError::StaleElement { .. }));
        worker.shutdown().await.unwrap();
        assert_eq!(state.lock().unwrap().closes, 1);
    }

    #[tokio::test]
    async fn runtime_failure_degrades_until_explicit_restart() {
        let state = Arc::new(Mutex::new(FakeState {
            fail_navigation: true,
            ..FakeState::default()
        }));
        let worker = BrowserWorker::spawn_with_runtime(
            identity(),
            capabilities(),
            4,
            FakeRuntime {
                state: Arc::clone(&state),
            },
        )
        .unwrap();
        worker.wait_until_settled().await.unwrap();

        let error = worker
            .execute(AgentCommand::Navigate {
                url: "https://example.test".into(),
            })
            .await
            .unwrap_err();
        assert!(matches!(error, WorkerError::Runtime(_)));
        assert_eq!(worker.snapshot().lifecycle, WorkerLifecycle::Degraded);

        worker.execute(AgentCommand::Restart).await.unwrap();
        assert_eq!(worker.snapshot().lifecycle, WorkerLifecycle::Ready);
        assert_eq!(state.lock().unwrap().restarts, 1);
        worker.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn missing_observation_does_not_degrade_resident_worker() {
        let state = Arc::new(Mutex::new(FakeState {
            missing_selector: true,
            ..FakeState::default()
        }));
        let worker = BrowserWorker::spawn_with_runtime(
            identity(),
            capabilities(),
            4,
            FakeRuntime { state },
        )
        .unwrap();
        worker.wait_until_settled().await.unwrap();

        let error = worker
            .execute(AgentCommand::ResolveElement {
                selector: "#missing".into(),
            })
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            WorkerError::Runtime(error)
                if error.kind() == RuntimeFailureKind::ObservationMissing
        ));
        let snapshot = worker.snapshot();
        assert_eq!(snapshot.lifecycle, WorkerLifecycle::Ready);
        assert_eq!(snapshot.last_failure, None);
        worker.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn capability_is_checked_before_runtime() {
        let state = Arc::new(Mutex::new(FakeState::default()));
        let worker = BrowserWorker::spawn_with_runtime(
            identity(),
            CapabilitySet::monitoring(),
            1,
            FakeRuntime { state },
        )
        .unwrap();
        worker.wait_until_settled().await.unwrap();

        let error = worker
            .execute(AgentCommand::ClickAt { x: 1.0, y: 1.0 })
            .await
            .unwrap_err();
        assert_eq!(
            error,
            WorkerError::CapabilityDenied(Capability::L1(
                crate::agentic::contract::L1Capability::Pointer
            ))
        );
        worker.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn page_limit_restart_invalidates_epoch_without_replaying_command() {
        let state = Arc::new(Mutex::new(FakeState {
            restart_needed: true,
            ..FakeState::default()
        }));
        let worker = BrowserWorker::spawn_with_runtime(
            identity(),
            capabilities(),
            4,
            FakeRuntime {
                state: Arc::clone(&state),
            },
        )
        .unwrap();
        worker.wait_until_settled().await.unwrap();

        worker
            .execute(AgentCommand::Navigate {
                url: "https://example.test".into(),
            })
            .await
            .unwrap();

        let snapshot = worker.snapshot();
        assert_eq!(snapshot.lifecycle, WorkerLifecycle::Ready);
        assert_eq!(snapshot.restart_count, 1);
        assert_eq!(snapshot.page_epoch, 2);
        let state = state.lock().unwrap();
        assert_eq!(state.navigations.len(), 1);
        assert_eq!(state.restarts, 1);
        drop(state);
        worker.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn delayed_runtime_command_times_out_and_degrades_worker() {
        let state = Arc::new(Mutex::new(FakeState {
            navigation_delay: Some(Duration::from_millis(300)),
            ..FakeState::default()
        }));
        let command_timeout = Duration::from_millis(100);
        let worker = BrowserWorker::spawn_with_runtime_and_timeout(
            identity(),
            capabilities(),
            4,
            command_timeout,
            FakeRuntime { state },
        )
        .unwrap();
        worker.wait_until_settled().await.unwrap();

        let error = worker
            .execute(AgentCommand::Navigate {
                url: "https://example.test".into(),
            })
            .await
            .unwrap_err();

        assert_eq!(error, WorkerError::CommandTimeout(command_timeout));
        let snapshot = worker.snapshot();
        assert_eq!(snapshot.lifecycle, WorkerLifecycle::Degraded);
        assert_eq!(snapshot.last_failure, Some(RuntimeFailureKind::Timeout));
        worker.shutdown().await.unwrap();
    }
}
