use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, oneshot, watch, Mutex};

use crate::browser::PageDevTools;
use crate::detect::LaunchConfig;
use crate::identity::IdentityProfile;
use crate::process_isolation::BrowserProcessIsolation;
use crate::stealth::StealthConfig;

use super::contract::{
    validate_selector, AgentCommand, AgentReply, BrowserSnapshot, Capability, CapabilitySet,
    ContractError, CookieSpec, DocumentState, ElementRef, L3Capability, RuntimeFailureKind,
    WorkerLifecycle,
};
use super::mobile::MobileLayout;
use super::navigation::NavigationPolicy;
use super::runtime::{BrowserRuntime, RealBrowserRuntime, RuntimeError};

const MAX_QUEUE_CAPACITY: usize = 256;
const MAX_KEY_BYTES: usize = 64;
const MAX_TEXT_BYTES: usize = 64 * 1024;
const MAX_SCRIPT_BYTES: usize = 64 * 1024;
const MAX_SCRIPT_RESULT_BYTES: usize = 4 * 1024 * 1024;
const MAX_UPLOAD_PATH_BYTES: usize = 4 * 1024;
const MAX_TAB_ID_BYTES: usize = 1024;
const MAX_IMPORT_COOKIES: usize = 512;
const MAX_COOKIE_NAME_BYTES: usize = 4 * 1024;
const MAX_COOKIE_VALUE_BYTES: usize = 8 * 1024;
const MAX_COOKIE_DOMAIN_BYTES: usize = 256;
const MAX_COOKIE_PATH_BYTES: usize = 4 * 1024;
const DEFAULT_COMMAND_TIMEOUT: Duration = Duration::from_secs(90);
const MIN_COMMAND_TIMEOUT: Duration = Duration::from_millis(100);
const MAX_COMMAND_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const EMERGENCY_CLOSE_TIMEOUT: Duration = Duration::from_secs(12);
const EMERGENCY_ACTOR_EXIT_TIMEOUT: Duration = Duration::from_secs(13);

#[derive(Debug, Clone)]
pub struct BrowserWorkerConfig {
    pub queue_capacity: usize,
    /// Bounds a single task/command execution (navigate, click, evaluate,
    /// etc.), including the initial runtime startup.
    pub command_timeout: Duration,
    /// Bounds the worker close/drain/teardown budget, distinct from
    /// [`command_timeout`](Self::command_timeout). `None` falls back to
    /// `command_timeout`, matching prior behavior when this budget is
    /// unset.
    pub close_timeout: Option<Duration>,
    pub launch: LaunchConfig,
    pub stealth: StealthConfig,
    pub mobile_layout: Option<MobileLayout>,
}

impl Default for BrowserWorkerConfig {
    fn default() -> Self {
        Self {
            queue_capacity: 32,
            command_timeout: DEFAULT_COMMAND_TIMEOUT,
            close_timeout: None,
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
    devtools: mpsc::Sender<DevToolsRequest>,
    snapshot: watch::Receiver<BrowserSnapshot>,
    stopped: watch::Receiver<bool>,
    actor: Arc<ActorControl>,
    navigation_policy: NavigationPolicy,
}

struct ActorControl {
    abort: tokio::task::AbortHandle,
    emergency: watch::Sender<bool>,
    join: Mutex<Option<tokio::task::JoinHandle<()>>>,
    finished: watch::Receiver<bool>,
}

impl BrowserWorker {
    pub fn spawn(
        identity: IdentityProfile,
        capabilities: CapabilitySet,
        config: BrowserWorkerConfig,
    ) -> Result<Self, WorkerError> {
        Self::spawn_with_navigation_policy(
            identity,
            capabilities,
            config,
            NavigationPolicy::default(),
        )
    }

    pub fn spawn_with_navigation_policy(
        identity: IdentityProfile,
        capabilities: CapabilitySet,
        config: BrowserWorkerConfig,
        navigation_policy: NavigationPolicy,
    ) -> Result<Self, WorkerError> {
        Self::spawn_with_navigation_policy_and_process_isolation(
            identity,
            capabilities,
            config,
            navigation_policy,
            BrowserProcessIsolation::Native,
        )
    }

    pub fn spawn_with_navigation_policy_and_process_isolation(
        identity: IdentityProfile,
        capabilities: CapabilitySet,
        config: BrowserWorkerConfig,
        navigation_policy: NavigationPolicy,
        process_isolation: BrowserProcessIsolation,
    ) -> Result<Self, WorkerError> {
        validate_queue_capacity(config.queue_capacity)?;
        validate_command_timeout(config.command_timeout)?;
        let close_timeout = config.close_timeout.unwrap_or(config.command_timeout);
        validate_close_timeout(close_timeout)?;
        let runtime = RealBrowserRuntime::new_with_navigation_policy_and_process_isolation(
            identity.clone(),
            config.launch,
            config.stealth,
            config.mobile_layout,
            navigation_policy.clone(),
            process_isolation,
        )?;
        Self::spawn_with_runtime_and_timeouts_and_navigation_policy(
            identity,
            capabilities,
            config.queue_capacity,
            config.command_timeout,
            close_timeout,
            navigation_policy,
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
        Self::spawn_with_runtime_and_timeout_and_navigation_policy(
            identity,
            capabilities,
            queue_capacity,
            command_timeout,
            NavigationPolicy::default(),
            runtime,
        )
    }

    pub fn spawn_with_runtime_and_timeout_and_navigation_policy<R>(
        identity: IdentityProfile,
        capabilities: CapabilitySet,
        queue_capacity: usize,
        command_timeout: Duration,
        navigation_policy: NavigationPolicy,
        runtime: R,
    ) -> Result<Self, WorkerError>
    where
        R: BrowserRuntime,
    {
        Self::spawn_with_runtime_and_timeouts_and_navigation_policy(
            identity,
            capabilities,
            queue_capacity,
            command_timeout,
            command_timeout,
            navigation_policy,
            runtime,
        )
    }

    /// Spawn with separately bounded task-execution and worker-close
    /// budgets. `close_timeout` bounds the worker close/drain/teardown
    /// path only; `command_timeout` continues to bound task/command
    /// execution, including the initial runtime startup.
    pub fn spawn_with_runtime_and_timeouts_and_navigation_policy<R>(
        identity: IdentityProfile,
        capabilities: CapabilitySet,
        queue_capacity: usize,
        command_timeout: Duration,
        close_timeout: Duration,
        navigation_policy: NavigationPolicy,
        runtime: R,
    ) -> Result<Self, WorkerError>
    where
        R: BrowserRuntime,
    {
        validate_queue_capacity(queue_capacity)?;
        validate_command_timeout(command_timeout)?;
        validate_close_timeout(close_timeout)?;
        let initial = BrowserSnapshot::starting(identity.id().to_owned());
        let (commands, receiver) = mpsc::channel(queue_capacity);
        let (devtools, devtools_requests) = mpsc::channel(4);
        let (snapshot_tx, snapshot) = watch::channel(initial.clone());
        let (stopped_tx, stopped) = watch::channel(false);
        let (emergency_tx, emergency_rx) = watch::channel(false);
        let (finished_tx, finished) = watch::channel(false);
        let actor = tokio::spawn(async move {
            run_actor(
                Box::new(runtime),
                ActorContext {
                    capabilities,
                    commands: receiver,
                    devtools_requests,
                    snapshots: snapshot_tx,
                    snapshot: initial,
                    command_timeout,
                    close_timeout,
                    stopped: stopped_tx,
                    emergency: emergency_rx,
                },
            )
            .await;
            finished_tx.send_replace(true);
        });
        let actor = Arc::new(ActorControl {
            abort: actor.abort_handle(),
            emergency: emergency_tx,
            join: Mutex::new(Some(actor)),
            finished,
        });
        Ok(Self {
            commands,
            devtools,
            snapshot,
            stopped,
            actor,
            navigation_policy,
        })
    }

    pub async fn execute(&self, command: AgentCommand) -> Result<AgentReply, WorkerError> {
        if let AgentCommand::Navigate { url } = &command {
            self.navigation_policy
                .validate(url)
                .map_err(|_| WorkerError::InvalidInput)?;
        }
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

    /// Subscribe to this worker's live DevTools event stream. Requires
    /// `L3Capability::Capture` and the actor to currently be `Ready` (same
    /// readiness gate as ordinary commands) — checked inside the actor, not
    /// here, so it stays correct even if the actor is mid-restart.
    ///
    /// This is independent of the queued [`AgentCommand`]/[`AgentReply`]
    /// pipeline (a `broadcast::Receiver` is not comparable, so it cannot be
    /// carried as an [`AgentReply`] variant): it uses its own small
    /// side-channel into the same single-owner actor loop. It still shares
    /// the actor's single-threaded serialization (it cannot run concurrently
    /// with an in-flight command and waits for one to finish), but arriving
    /// on its own channel means it does not have to wait behind an entire
    /// backlog of already-queued `AgentCommand`s the way a new command sent
    /// through [`execute`](Self::execute) would.
    pub async fn subscribe_devtools(&self) -> Result<PageDevTools, WorkerError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.devtools
            .send(DevToolsRequest { reply: reply_tx })
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
            self.wait_actor_finished().await;
            return match self.snapshot().last_failure {
                Some(kind) => Err(WorkerError::Runtime(RuntimeError::new(kind))),
                None => Ok(()),
            };
        }
        let command_result = self.execute(AgentCommand::Shutdown).await.map(|_| ());
        let stopped_result = self.wait_stopped().await;
        self.wait_actor_finished().await;
        match (command_result, stopped_result) {
            (Err(error), _) | (Ok(()), Err(error)) => Err(error),
            (Ok(()), Ok(())) => Ok(()),
        }
    }

    /// Interrupt the current actor operation and start its bounded emergency
    /// runtime close. `wait_aborted` applies a final task abort if that close
    /// path does not finish within its hard deadline.
    pub fn abort_now(&self) {
        self.actor.emergency.send_replace(true);
    }

    /// Wait until emergency close has dropped the runtime, with a hard actor
    /// cancellation fallback so containment-loss handling cannot hang.
    pub async fn wait_aborted(&self) {
        let mut finished = self.actor.finished.clone();
        let notified = tokio::time::timeout(EMERGENCY_ACTOR_EXIT_TIMEOUT, async {
            while !*finished.borrow() {
                if finished.changed().await.is_err() {
                    break;
                }
            }
        })
        .await;
        if notified.is_err() {
            self.actor.abort.abort();
        }
        self.wait_actor_finished().await;
    }

    async fn wait_actor_finished(&self) {
        let mut join = self.actor.join.lock().await;
        if let Some(join) = join.take() {
            let _ = join.await;
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

struct DevToolsRequest {
    reply: oneshot::Sender<Result<PageDevTools, WorkerError>>,
}

/// One unit of work delivered to the actor's main loop: either a queued
/// [`AgentCommand`] envelope, or a devtools subscription request arriving on
/// its own side-channel.
enum ActorEvent {
    Command(Envelope),
    DevTools(DevToolsRequest),
}

struct ActorContext {
    capabilities: CapabilitySet,
    commands: mpsc::Receiver<Envelope>,
    devtools_requests: mpsc::Receiver<DevToolsRequest>,
    snapshots: watch::Sender<BrowserSnapshot>,
    snapshot: BrowserSnapshot,
    command_timeout: Duration,
    close_timeout: Duration,
    stopped: watch::Sender<bool>,
    emergency: watch::Receiver<bool>,
}

async fn run_actor(
    mut runtime: Box<dyn BrowserRuntime>,
    context: ActorContext,
) {
    let ActorContext {
        capabilities,
        mut commands,
        mut devtools_requests,
        snapshots,
        mut snapshot,
        command_timeout,
        close_timeout,
        stopped,
        mut emergency,
    } = context;
    let start_result = tokio::select! {
        biased;
        _ = wait_for_emergency(&mut emergency) => {
            snapshot.last_failure = Some(RuntimeFailureKind::Shutdown);
            emergency_close_runtime(
                &mut *runtime,
                &mut snapshot,
                &snapshots,
                close_timeout,
            ).await;
            drop(runtime);
            stopped.send_replace(true);
            return;
        }
        result = tokio::time::timeout(command_timeout, runtime.start()) => result,
    };
    let startup_unconfirmed = match start_result {
        Ok(Ok(())) => {
            snapshot.lifecycle = WorkerLifecycle::Ready;
            snapshot.last_failure = None;
            false
        }
        Ok(Err(error)) => {
            mark_degraded(&mut snapshot, error);
            true
        }
        Err(_) => {
            mark_timeout_degraded(&mut snapshot);
            true
        }
    };
    snapshots.send_replace(snapshot.clone());

    let mut shutdown_attempted = false;
    let mut emergency_requested = false;
    loop {
        let event = tokio::select! {
            biased;
            _ = wait_for_emergency(&mut emergency) => {
                emergency_requested = true;
                break;
            }
            envelope = commands.recv() => match envelope {
                Some(envelope) => ActorEvent::Command(envelope),
                None => break,
            },
            request = devtools_requests.recv() => match request {
                Some(request) => ActorEvent::DevTools(request),
                // The devtools sender is co-owned by every `BrowserWorker`
                // clone alongside `commands` and always closes together with
                // it; if it somehow closes first, keep serving commands.
                None => continue,
            },
        };
        let envelope = match event {
            ActorEvent::Command(envelope) => envelope,
            ActorEvent::DevTools(request) => {
                let result =
                    handle_devtools_subscription(&mut *runtime, &capabilities, &snapshot).await;
                let _ = request.reply.send(result);
                continue;
            }
        };
        let is_shutdown = matches!(envelope.command, AgentCommand::Shutdown);
        shutdown_attempted |= is_shutdown
            && capabilities.contains(envelope.command.required_capability());
        // A Shutdown command's own runtime.close() runs inside
        // handle_command below; bound it by the close/teardown budget
        // rather than the task-execution budget so a slow close cannot
        // silently borrow extra time from (or steal too little time from)
        // command_timeout.
        let envelope_timeout = if is_shutdown {
            close_timeout
        } else {
            command_timeout
        };
        let command_result = tokio::select! {
            biased;
            _ = wait_for_emergency(&mut emergency) => {
                emergency_requested = true;
                break;
            }
            result = tokio::time::timeout(
                envelope_timeout,
                handle_command(
                    &mut *runtime,
                    &capabilities,
                    &mut snapshot,
                    &snapshots,
                    startup_unconfirmed,
                    envelope.command,
                ),
            ) => result,
        };
        let result = match command_result {
            Ok(result) => result,
            Err(_) => {
                mark_timeout_degraded(&mut snapshot);
                snapshots.send_replace(snapshot.clone());
                Err(WorkerError::CommandTimeout(envelope_timeout))
            }
        };
        let _ = envelope.reply.send(result);
        if is_shutdown {
            break;
        }
    }

    if emergency_requested {
        emergency_close_runtime(
            &mut *runtime,
            &mut snapshot,
            &snapshots,
            close_timeout,
        )
        .await;
    } else if snapshot.lifecycle != WorkerLifecycle::Stopped {
        snapshot.lifecycle = WorkerLifecycle::ShuttingDown;
        snapshots.send_replace(snapshot.clone());
        if !shutdown_attempted {
            match tokio::time::timeout(close_timeout, runtime.close()).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => snapshot.last_failure = Some(error.kind()),
                Err(_) => snapshot.last_failure = Some(RuntimeFailureKind::Timeout),
            }
        }
        snapshot.lifecycle = WorkerLifecycle::Stopped;
        snapshot.current_origin = None;
        snapshots.send_replace(snapshot);
    }
    drop(runtime);
    stopped.send_replace(true);
}

async fn wait_for_emergency(emergency: &mut watch::Receiver<bool>) {
    loop {
        if *emergency.borrow() {
            return;
        }
        if emergency.changed().await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

async fn emergency_close_runtime(
    runtime: &mut dyn BrowserRuntime,
    snapshot: &mut BrowserSnapshot,
    snapshots: &watch::Sender<BrowserSnapshot>,
    close_timeout: Duration,
) {
    snapshot.lifecycle = WorkerLifecycle::ShuttingDown;
    snapshots.send_replace(snapshot.clone());
    let timeout = close_timeout.min(EMERGENCY_CLOSE_TIMEOUT);
    match tokio::time::timeout(timeout, runtime.close()).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => snapshot.last_failure = Some(error.kind()),
        Err(_) => snapshot.last_failure = Some(RuntimeFailureKind::Timeout),
    }
    snapshot.lifecycle = WorkerLifecycle::Stopped;
    snapshot.current_origin = None;
    snapshots.send_replace(snapshot.clone());
}

async fn handle_devtools_subscription(
    runtime: &mut dyn BrowserRuntime,
    capabilities: &CapabilitySet,
    snapshot: &BrowserSnapshot,
) -> Result<PageDevTools, WorkerError> {
    let required = Capability::L3(L3Capability::Capture);
    if !capabilities.contains(required) {
        return Err(WorkerError::CapabilityDenied(required));
    }
    if snapshot.lifecycle != WorkerLifecycle::Ready {
        return Err(WorkerError::Unavailable);
    }
    runtime.subscribe_devtools().await.map_err(WorkerError::from)
}

async fn handle_command(
    runtime: &mut dyn BrowserRuntime,
    capabilities: &CapabilitySet,
    snapshot: &mut BrowserSnapshot,
    snapshots: &watch::Sender<BrowserSnapshot>,
    startup_unconfirmed: bool,
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
    if startup_unconfirmed && matches!(command, AgentCommand::Restart) {
        return Err(WorkerError::Unavailable);
    }

    if !matches!(&command, AgentCommand::Restart | AgentCommand::Shutdown)
        && !runtime.navigation_policy_healthy()
    {
        let error = RuntimeError::new(RuntimeFailureKind::Protocol);
        mark_degraded(snapshot, error);
        snapshots.send_replace(snapshot.clone());
        return Err(WorkerError::Runtime(error));
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
        AgentCommand::SelectOption { element, value } => {
            validate_element_epoch(&element, snapshot.page_epoch)?;
            if value.is_empty() || value.len() > MAX_TEXT_BYTES || value.contains('\0') {
                return Err(WorkerError::InvalidInput);
            }
            runtime
                .select_option(element.selector(), &value)
                .await
                .map(|_| AgentReply::Acknowledged)
        }
        AgentCommand::UploadFile { element, path } => {
            validate_element_epoch(&element, snapshot.page_epoch)?;
            if path.is_empty() || path.len() > MAX_UPLOAD_PATH_BYTES || path.contains('\0') {
                return Err(WorkerError::InvalidInput);
            }
            runtime
                .set_file_input(element.selector(), &path)
                .await
                .map(|_| AgentReply::Acknowledged)
        }
        AgentCommand::WaitForDownload { timeout } => runtime
            .wait_for_download(timeout)
            .await
            .map(|(suggested_filename, bytes)| AgentReply::Download {
                suggested_filename,
                bytes,
            }),
        AgentCommand::ReadElementText { element } => {
            validate_element_epoch(&element, snapshot.page_epoch)?;
            runtime
                .read_element_text(element.selector())
                .await
                .map(AgentReply::Text)
        }
        AgentCommand::ObserveDocument => runtime
            .observe_document()
            .await
            .map(|state| AgentReply::Text(state.ready_state)),
        AgentCommand::ReadInteractiveElements => runtime
            .read_interactive_elements()
            .await
            .map(AgentReply::ScriptValue),
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
        AgentCommand::SetCookies { cookies } => {
            validate_cookies(&cookies)?;
            runtime
                .set_cookies(cookies)
                .await
                .map(|_| AgentReply::Acknowledged)
        }
        AgentCommand::ListTabs => runtime.list_tabs().await.map(AgentReply::Tabs),
        AgentCommand::SwitchToTab { id } => {
            if id.is_empty() || id.len() > MAX_TAB_ID_BYTES || id.contains('\0') {
                return Err(WorkerError::InvalidInput);
            }
            runtime.switch_to_tab(&id).await.map(|_| {
                // Switching the active page invalidates any `ElementRef`
                // resolved against the previous tab, exactly as `Navigate`
                // invalidates references to the pre-navigation document.
                snapshot.page_epoch = snapshot.page_epoch.saturating_add(1);
                snapshot.current_origin = None;
                AgentReply::Acknowledged
            })
        }
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
            let shutdown_failure = close_result.err().or_else(|| {
                startup_unconfirmed
                    .then(|| RuntimeError::new(RuntimeFailureKind::Shutdown))
            });
            if let Some(error) = shutdown_failure {
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

    if !runtime.navigation_policy_healthy() {
        let error = RuntimeError::new(RuntimeFailureKind::Protocol);
        mark_degraded(snapshot, error);
        snapshots.send_replace(snapshot.clone());
        return Err(WorkerError::Runtime(error));
    }

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

fn validate_close_timeout(timeout: Duration) -> Result<(), WorkerError> {
    if (MIN_COMMAND_TIMEOUT..=MAX_COMMAND_TIMEOUT).contains(&timeout) {
        Ok(())
    } else {
        Err(WorkerError::InvalidCloseTimeout)
    }
}

fn validate_finite(values: &[f64]) -> Result<(), WorkerError> {
    if values.iter().all(|value| value.is_finite()) {
        Ok(())
    } else {
        Err(WorkerError::InvalidInput)
    }
}

fn validate_cookies(cookies: &[CookieSpec]) -> Result<(), WorkerError> {
    if cookies.is_empty() || cookies.len() > MAX_IMPORT_COOKIES {
        return Err(WorkerError::InvalidInput);
    }
    for cookie in cookies {
        if cookie.name.is_empty()
            || cookie.name.len() > MAX_COOKIE_NAME_BYTES
            || cookie.value.len() > MAX_COOKIE_VALUE_BYTES
            || cookie.domain.is_empty()
            || cookie.domain.len() > MAX_COOKIE_DOMAIN_BYTES
            || cookie.path.len() > MAX_COOKIE_PATH_BYTES
            || cookie.name.contains('\0')
            || cookie.value.contains('\0')
            || cookie.domain.contains('\0')
            || cookie.path.contains('\0')
        {
            return Err(WorkerError::InvalidInput);
        }
    }
    Ok(())
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
    NavigationPolicy::default()
        .validate(value)
        .map_err(|_| WorkerError::InvalidInput)
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
    InvalidCloseTimeout,
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
            Self::InvalidCloseTimeout => write!(
                formatter,
                "close timeout must be between 100 milliseconds and 15 minutes"
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

    fn cookie(name: &str, value: &str) -> CookieSpec {
        CookieSpec {
            name: name.to_owned(),
            value: value.to_owned(),
            domain: ".example.test".to_owned(),
            path: "/".to_owned(),
            secure: true,
            http_only: true,
            expires_unix: None,
        }
    }

    #[test]
    fn validate_cookies_bounds_and_rejects_malformed() {
        assert!(validate_cookies(&[cookie("sid", "abc")]).is_ok());
        assert!(validate_cookies(&[]).is_err());
        assert!(validate_cookies(&[cookie("", "abc")]).is_err());
        let mut no_domain = cookie("sid", "abc");
        no_domain.domain = String::new();
        assert!(validate_cookies(&[no_domain]).is_err());
        assert!(validate_cookies(&[cookie("sid", "a\0b")]).is_err());
        let many = vec![cookie("sid", "abc"); MAX_IMPORT_COOKIES + 1];
        assert!(validate_cookies(&many).is_err());
        let mut big = cookie("sid", "");
        big.value = "x".repeat(MAX_COOKIE_VALUE_BYTES + 1);
        assert!(validate_cookies(&[big]).is_err());
    }

    #[derive(Default)]
    struct FakeState {
        starts: u32,
        restarts: u32,
        closes: u32,
        drops: u32,
        navigations: Vec<String>,
        start_delay: Option<Duration>,
        fail_navigation: bool,
        restart_needed: bool,
        navigation_delay: Option<Duration>,
        close_delay: Option<Duration>,
        missing_selector: bool,
    }

    struct FakeRuntime {
        state: Arc<Mutex<FakeState>>,
    }

    impl Drop for FakeRuntime {
        fn drop(&mut self) {
            self.state.lock().unwrap().drops += 1;
        }
    }

    impl BrowserRuntime for FakeRuntime {
        fn start(&mut self) -> BoxFuture<'_, RuntimeResult<()>> {
            let start_delay = {
                let mut state = self.state.lock().unwrap();
                state.starts += 1;
                state.start_delay
            };
            Box::pin(async move {
                if let Some(delay) = start_delay {
                    tokio::time::sleep(delay).await;
                }
                Ok(())
            })
        }

        fn restart(&mut self) -> BoxFuture<'_, RuntimeResult<()>> {
            let mut state = self.state.lock().unwrap();
            state.restarts += 1;
            state.restart_needed = false;
            Box::pin(async { Ok(()) })
        }

        fn close(&mut self) -> BoxFuture<'_, RuntimeResult<()>> {
            let close_delay = {
                let mut state = self.state.lock().unwrap();
                state.closes += 1;
                state.close_delay
            };
            Box::pin(async move {
                if let Some(delay) = close_delay {
                    tokio::time::sleep(delay).await;
                }
                Ok(())
            })
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
    async fn emergency_abort_interrupts_active_command_and_closes_runtime() {
        let state = Arc::new(Mutex::new(FakeState::default()));
        state.lock().unwrap().navigation_delay = Some(Duration::from_secs(60));
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

        let command_worker = worker.clone();
        let command = tokio::spawn(async move {
            command_worker
                .execute(AgentCommand::Navigate {
                    url: "https://example.test".into(),
                })
                .await
        });
        while state.lock().unwrap().navigations.is_empty() {
            tokio::task::yield_now().await;
        }
        worker.abort_now();
        tokio::time::timeout(Duration::from_secs(1), worker.wait_aborted())
            .await
            .expect("emergency abort must close and drop the runtime promptly");
        assert!(matches!(command.await.unwrap(), Err(WorkerError::WorkerStopped)));

        let state = state.lock().unwrap();
        assert_eq!(state.closes, 1);
        assert_eq!(state.drops, 1);
    }

    #[tokio::test]
    async fn emergency_close_timeout_still_drops_runtime() {
        let command_timeout = Duration::from_millis(100);
        let state = Arc::new(Mutex::new(FakeState {
            close_delay: Some(Duration::from_secs(60)),
            ..FakeState::default()
        }));
        let worker = BrowserWorker::spawn_with_runtime_and_timeout(
            identity(),
            capabilities(),
            4,
            command_timeout,
            FakeRuntime {
                state: Arc::clone(&state),
            },
        )
        .unwrap();
        worker.wait_until_settled().await.unwrap();

        worker.abort_now();
        tokio::time::timeout(Duration::from_secs(1), worker.wait_aborted())
            .await
            .expect("emergency close must honor its hard deadline");

        let snapshot = worker.snapshot();
        assert_eq!(snapshot.lifecycle, WorkerLifecycle::Stopped);
        assert_eq!(snapshot.last_failure, Some(RuntimeFailureKind::Timeout));
        assert!(matches!(
            worker.shutdown().await,
            Err(WorkerError::Runtime(error))
                if error.kind() == RuntimeFailureKind::Timeout
        ));
        let state = state.lock().unwrap();
        assert_eq!(state.closes, 1);
        assert_eq!(state.drops, 1);
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
    async fn startup_timeout_cannot_be_reported_as_clean_shutdown() {
        let command_timeout = Duration::from_millis(100);
        let state = Arc::new(Mutex::new(FakeState {
            start_delay: Some(Duration::from_secs(60)),
            ..FakeState::default()
        }));
        let worker = BrowserWorker::spawn_with_runtime_and_timeout(
            identity(),
            capabilities(),
            4,
            command_timeout,
            FakeRuntime {
                state: Arc::clone(&state),
            },
        )
        .unwrap();

        let snapshot = worker.wait_until_settled().await.unwrap();
        assert_eq!(snapshot.lifecycle, WorkerLifecycle::Degraded);
        assert_eq!(snapshot.last_failure, Some(RuntimeFailureKind::Timeout));
        assert!(matches!(
            worker.execute(AgentCommand::Restart).await,
            Err(WorkerError::Unavailable)
        ));
        assert!(matches!(
            worker.shutdown().await,
            Err(WorkerError::Runtime(error))
                if error.kind() == RuntimeFailureKind::Shutdown
        ));
        let state = state.lock().unwrap();
        assert_eq!(state.starts, 1);
        assert_eq!(state.closes, 1);
        assert_eq!(state.drops, 1);
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
    async fn devtools_subscription_is_capability_gated_and_unsupported_by_default() {
        let state = Arc::new(Mutex::new(FakeState::default()));
        let ungated_worker = BrowserWorker::spawn_with_runtime(
            identity(),
            CapabilitySet::monitoring(),
            4,
            FakeRuntime {
                state: Arc::clone(&state),
            },
        )
        .unwrap();
        ungated_worker.wait_until_settled().await.unwrap();
        // `FakeRuntime` never overrides `BrowserRuntime::subscribe_devtools`,
        // so the default trait implementation reports it as unsupported
        // rather than the request silently no-opping.
        assert!(matches!(
            ungated_worker.subscribe_devtools().await,
            Err(WorkerError::Runtime(error))
                if error.kind() == RuntimeFailureKind::Protocol
        ));
        ungated_worker.shutdown().await.unwrap();

        let denied_worker = BrowserWorker::spawn_with_runtime(
            identity(),
            CapabilitySet::new([Capability::L3(L3Capability::Lifecycle)]).unwrap(),
            4,
            FakeRuntime { state },
        )
        .unwrap();
        denied_worker.wait_until_settled().await.unwrap();
        match denied_worker.subscribe_devtools().await {
            Err(WorkerError::CapabilityDenied(capability)) => {
                assert_eq!(capability, Capability::L3(L3Capability::Capture));
            }
            Err(other) => panic!("expected capability denial, got a different error: {other:?}"),
            Ok(_) => panic!("expected capability denial, got a subscription"),
        }
        denied_worker.shutdown().await.unwrap();
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
        {
            let state = state.lock().unwrap();
            assert_eq!(state.navigations.len(), 1);
            assert_eq!(state.restarts, 1);
        }
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

    #[tokio::test]
    async fn timed_out_shutdown_attempts_runtime_close_only_once_and_stops_actor() {
        let command_timeout = Duration::from_millis(100);
        let state = Arc::new(Mutex::new(FakeState {
            close_delay: Some(Duration::from_secs(60)),
            ..FakeState::default()
        }));
        let worker = BrowserWorker::spawn_with_runtime_and_timeout(
            identity(),
            capabilities(),
            4,
            command_timeout,
            FakeRuntime {
                state: Arc::clone(&state),
            },
        )
        .unwrap();
        worker.wait_until_settled().await.unwrap();

        let error = worker.shutdown().await.unwrap_err();

        assert_eq!(error, WorkerError::CommandTimeout(command_timeout));
        tokio::time::timeout(Duration::from_secs(1), worker.wait_stopped())
            .await
            .expect("worker actor did not stop after timed-out shutdown")
            .expect("worker actor stopped without publishing completion");
        let snapshot = worker.snapshot();
        assert_eq!(snapshot.lifecycle, WorkerLifecycle::Stopped);
        assert_eq!(snapshot.last_failure, Some(RuntimeFailureKind::Timeout));
        assert_eq!(state.lock().unwrap().closes, 1);
    }

    #[tokio::test]
    async fn capability_denied_shutdown_still_closes_runtime_once() {
        let state = Arc::new(Mutex::new(FakeState::default()));
        let worker = BrowserWorker::spawn_with_runtime(
            identity(),
            CapabilitySet::new([]).unwrap(),
            4,
            FakeRuntime {
                state: Arc::clone(&state),
            },
        )
        .unwrap();
        worker.wait_until_settled().await.unwrap();

        let error = worker.shutdown().await.unwrap_err();

        assert_eq!(
            error,
            WorkerError::CapabilityDenied(Capability::L3(L3Capability::Lifecycle))
        );
        assert_eq!(worker.snapshot().lifecycle, WorkerLifecycle::Stopped);
        assert_eq!(state.lock().unwrap().closes, 1);
    }
}
