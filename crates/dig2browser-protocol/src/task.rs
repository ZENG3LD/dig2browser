use std::time::Duration;

use dig2browser_core::{
    ControlTransport, EngineFamily, FeatureSupport, ResolvedRuntime,
    RuntimeFeature, RuntimeKind, RuntimeLimitation, RuntimeRequirements,
    RuntimeSelector, SupportLevel,
};

use crate::{
    validate_http_url, ProtocolError, MAX_HTML_BYTES, MAX_PNG_BYTES,
    MAX_REQUEST_BYTES, PROTOCOL_VERSION,
};

pub const MAX_TASK_STEPS: usize = 64;
pub const MAX_TASK_WAIT: Duration = Duration::from_secs(2 * 60);
pub const MAX_TASK_RESULT_BYTES: usize = MAX_HTML_BYTES;

const TASK_MAGIC: [u8; 4] = *b"D2TK";
const TASK_RESULT_MAGIC: [u8; 4] = *b"D2TR";
const RUNTIME_RECORD_MAGIC: [u8; 4] = *b"D2RR";
const RUNTIME_RECORD_SCHEMA_VERSION: u16 = 1;
const TASK_SCHEMA_VERSION_V1: u16 = 1;
const TASK_SCHEMA_VERSION_V2: u16 = 2;
const MAX_RUNTIME_FEATURES: usize = 16;
const MAX_RUNTIME_LIMITATIONS: usize = 8;
const MAX_RUNTIME_VERSION_BYTES: usize = 128;
pub const MAX_SELECTOR_BYTES: usize = 4_096;
/// Upper bound on elements returned by one `ReadInteractiveElements` step.
pub const MAX_INTERACTIVE_ELEMENTS: usize = 256;
/// Upper bound on an interactive element's `role` label.
pub const MAX_ELEMENT_ROLE_BYTES: usize = 64;
/// Upper bound on an interactive element's accessible `name`.
pub const MAX_ELEMENT_NAME_BYTES: usize = 1_024;
const MAX_KEY_BYTES: usize = 64;
const MAX_TEXT_BYTES: usize = 64 * 1024;
const MAX_SCRIPT_BYTES: usize = 64 * 1024;
const MAX_SCRIPT_RESULT_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_COLLECTOR_VERSION_BYTES: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TaskCapturePolicy {
    StateOnly = 0,
    HtmlOnly = 1,
    EvidenceViewport = 2,
}

impl TaskCapturePolicy {
    fn from_wire(value: u8) -> Result<Self, ProtocolError> {
        match value {
            0 => Ok(Self::StateOnly),
            1 => Ok(Self::HtmlOnly),
            2 => Ok(Self::EvidenceViewport),
            _ => Err(ProtocolError::InvalidTaskPayload),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum TaskStep {
    Navigate { url: String },
    Wait { duration: Duration },
    Wheel {
        x: f64,
        y: f64,
        delta_x: f64,
        delta_y: f64,
    },
    KeyPress { key: String },
    ClickSelector { selector: String },
    TypeSelector { selector: String, text: String },
    ReadSelectorText { selector: String },
    Evaluate { script: String },
    Capture { policy: TaskCapturePolicy },
    /// Block until `selector` resolves in the DOM, or `timeout` elapses.
    ///
    /// Inspect-only (never interaction or script): it lets an agent wait for a
    /// dynamic element without a blind `Wait { duration }` and without needing
    /// the scripted-task gate. `timeout` counts against the same cumulative
    /// wait budget as `Wait` (`MAX_TASK_WAIT`).
    WaitForSelector { selector: String, timeout: Duration },
    /// Block until the document reaches (at least) `state`
    /// (`document.readyState`), or `timeout` elapses.
    ///
    /// Inspect-only (a fixed internal `readyState` read, never a consumer
    /// script): it lets an agent wait for a client-side navigation to settle
    /// without racing the load and without the scripted-task gate. `timeout`
    /// counts against the same cumulative wait budget as `Wait`
    /// (`MAX_TASK_WAIT`).
    WaitForLoadState { state: LoadState, timeout: Duration },
    /// Enumerate the page's interactive elements (`a`, `button`, `input`,
    /// `select`, `textarea`, `[role]`) as typed `{role, name, selector}`
    /// records, so an agent can pick a target without shipping a consumer
    /// script.
    ///
    /// Inspect-only: it runs a fixed, station-authored `readyState`-style DOM
    /// read (never a caller-supplied script), so it needs only `L2::Inspect`
    /// and is ungated — the same footing as `WaitForSelector`. The selector it
    /// returns is directly usable by a later `ClickSelector`/`ReadSelectorText`
    /// step.
    ReadInteractiveElements,
}

/// A document load milestone (`document.readyState`), ordered
/// `Interactive < Complete`. `WaitForLoadState` blocks until the live state is
/// at least the requested one. `loading` is not a target — it is where a
/// document begins, so there is nothing to wait for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadState {
    Interactive,
    Complete,
}

impl LoadState {
    fn to_wire(self) -> u8 {
        match self {
            Self::Interactive => 1,
            Self::Complete => 2,
        }
    }

    fn from_wire(value: u8) -> Result<Self, ProtocolError> {
        match value {
            1 => Ok(Self::Interactive),
            2 => Ok(Self::Complete),
            _ => Err(ProtocolError::InvalidTaskPayload),
        }
    }
}

/// Opt-in runtime selection and capability requirements for a task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskRuntimeContract {
    selector: RuntimeSelector,
    requirements: RuntimeRequirements,
}

impl TaskRuntimeContract {
    pub fn new(
        selector: RuntimeSelector,
        requirements: RuntimeRequirements,
    ) -> Result<Self, ProtocolError> {
        let contract = Self {
            selector,
            requirements,
        };
        contract.validate()?;
        Ok(contract)
    }

    pub fn selector(&self) -> RuntimeSelector {
        self.selector
    }

    pub fn requirements(&self) -> &RuntimeRequirements {
        &self.requirements
    }

    fn validate(&self) -> Result<(), ProtocolError> {
        let features = self.requirements.features();
        if features.len() > MAX_RUNTIME_FEATURES
            || (features.is_empty() && self.requirements.allow_partial())
            || duplicate_runtime_feature(features.iter().copied())
        {
            return Err(ProtocolError::InvalidTaskPayload);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct CollectionTask {
    steps: Vec<TaskStep>,
    runtime: Option<TaskRuntimeContract>,
}

impl CollectionTask {
    pub fn new(steps: Vec<TaskStep>) -> Result<Self, ProtocolError> {
        let task = Self {
            steps,
            runtime: None,
        };
        task.validate()?;
        Ok(task)
    }

    pub fn new_with_runtime(
        steps: Vec<TaskStep>,
        runtime: TaskRuntimeContract,
    ) -> Result<Self, ProtocolError> {
        let task = Self {
            steps,
            runtime: Some(runtime),
        };
        task.validate()?;
        Ok(task)
    }

    pub fn with_runtime_contract(
        mut self,
        runtime: TaskRuntimeContract,
    ) -> Result<Self, ProtocolError> {
        self.runtime = Some(runtime);
        self.validate()?;
        Ok(self)
    }

    pub fn steps(&self) -> &[TaskStep] {
        &self.steps
    }

    pub fn runtime_contract(&self) -> Option<&TaskRuntimeContract> {
        self.runtime.as_ref()
    }

    pub fn requires_interaction(&self) -> bool {
        self.steps.iter().any(|step| {
            matches!(
                step,
                TaskStep::KeyPress { .. }
                    | TaskStep::ClickSelector { .. }
                    | TaskStep::TypeSelector { .. }
            )
        })
    }

    pub fn requires_script(&self) -> bool {
        self.steps
            .iter()
            .any(|step| matches!(step, TaskStep::Evaluate { .. }))
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.steps.is_empty() || self.steps.len() > MAX_TASK_STEPS {
            return Err(ProtocolError::InvalidTaskPayload);
        }
        if let Some(runtime) = &self.runtime {
            runtime.validate()?;
        }
        let mut total_wait = Duration::ZERO;
        let mut navigated = false;
        for step in &self.steps {
            match step {
                TaskStep::Navigate { url } => {
                    validate_http_url(url)?;
                    navigated = true;
                }
                TaskStep::Wait { duration } => {
                    if duration.is_zero() {
                        return Err(ProtocolError::InvalidTaskPayload);
                    }
                    total_wait = total_wait
                        .checked_add(*duration)
                        .ok_or(ProtocolError::InvalidTaskPayload)?;
                    if total_wait > MAX_TASK_WAIT {
                        return Err(ProtocolError::InvalidTaskPayload);
                    }
                }
                TaskStep::Wheel {
                    x,
                    y,
                    delta_x,
                    delta_y,
                } => {
                    if ![x, y, delta_x, delta_y]
                        .into_iter()
                        .all(|value| value.is_finite())
                    {
                        return Err(ProtocolError::InvalidTaskPayload);
                    }
                }
                TaskStep::KeyPress { key } => validate_text(key, MAX_KEY_BYTES, false)?,
                TaskStep::ClickSelector { selector }
                | TaskStep::ReadSelectorText { selector } => validate_selector(selector)?,
                TaskStep::TypeSelector { selector, text } => {
                    validate_selector(selector)?;
                    validate_text(text, MAX_TEXT_BYTES, true)?;
                }
                TaskStep::Evaluate { script } => {
                    validate_text(script, MAX_SCRIPT_BYTES, false)?;
                }
                TaskStep::Capture { .. } => {
                    if !navigated {
                        return Err(ProtocolError::InvalidTaskPayload);
                    }
                }
                TaskStep::WaitForSelector { selector, timeout } => {
                    validate_selector(selector)?;
                    if timeout.is_zero() {
                        return Err(ProtocolError::InvalidTaskPayload);
                    }
                    total_wait = total_wait
                        .checked_add(*timeout)
                        .ok_or(ProtocolError::InvalidTaskPayload)?;
                    if total_wait > MAX_TASK_WAIT {
                        return Err(ProtocolError::InvalidTaskPayload);
                    }
                }
                TaskStep::WaitForLoadState { timeout, .. } => {
                    if timeout.is_zero() {
                        return Err(ProtocolError::InvalidTaskPayload);
                    }
                    total_wait = total_wait
                        .checked_add(*timeout)
                        .ok_or(ProtocolError::InvalidTaskPayload)?;
                    if total_wait > MAX_TASK_WAIT {
                        return Err(ProtocolError::InvalidTaskPayload);
                    }
                }
                TaskStep::ReadInteractiveElements => {}
            }
        }
        Ok(())
    }

    pub(crate) fn encode_payload(&self) -> Result<Vec<u8>, ProtocolError> {
        self.validate()?;
        let mut output = Vec::new();
        output.extend_from_slice(&TASK_MAGIC);
        let schema_version = if self.runtime.is_some() {
            TASK_SCHEMA_VERSION_V2
        } else {
            TASK_SCHEMA_VERSION_V1
        };
        output.extend_from_slice(&schema_version.to_le_bytes());
        output.extend_from_slice(&(self.steps.len() as u16).to_le_bytes());
        if let Some(runtime) = &self.runtime {
            encode_runtime_contract(&mut output, runtime)?;
        }
        for step in &self.steps {
            match step {
                TaskStep::Navigate { url } => {
                    output.push(1);
                    put_u32_bytes(&mut output, url.as_bytes())?;
                }
                TaskStep::Wait { duration } => {
                    output.push(2);
                    let millis = u64::try_from(duration.as_millis())
                        .map_err(|_| ProtocolError::InvalidTaskPayload)?;
                    output.extend_from_slice(&millis.to_le_bytes());
                }
                TaskStep::Wheel {
                    x,
                    y,
                    delta_x,
                    delta_y,
                } => {
                    output.push(3);
                    for value in [x, y, delta_x, delta_y] {
                        output.extend_from_slice(&value.to_le_bytes());
                    }
                }
                TaskStep::KeyPress { key } => {
                    output.push(4);
                    put_u16_bytes(&mut output, key.as_bytes())?;
                }
                TaskStep::ClickSelector { selector } => {
                    output.push(5);
                    put_u16_bytes(&mut output, selector.as_bytes())?;
                }
                TaskStep::TypeSelector { selector, text } => {
                    output.push(6);
                    put_u16_bytes(&mut output, selector.as_bytes())?;
                    put_u32_bytes(&mut output, text.as_bytes())?;
                }
                TaskStep::ReadSelectorText { selector } => {
                    output.push(7);
                    put_u16_bytes(&mut output, selector.as_bytes())?;
                }
                TaskStep::Evaluate { script } => {
                    output.push(8);
                    put_u32_bytes(&mut output, script.as_bytes())?;
                }
                TaskStep::Capture { policy } => {
                    output.push(9);
                    output.push(*policy as u8);
                }
                TaskStep::WaitForSelector { selector, timeout } => {
                    output.push(10);
                    put_u16_bytes(&mut output, selector.as_bytes())?;
                    let millis = u64::try_from(timeout.as_millis())
                        .map_err(|_| ProtocolError::InvalidTaskPayload)?;
                    output.extend_from_slice(&millis.to_le_bytes());
                }
                TaskStep::WaitForLoadState { state, timeout } => {
                    output.push(11);
                    output.push(state.to_wire());
                    let millis = u64::try_from(timeout.as_millis())
                        .map_err(|_| ProtocolError::InvalidTaskPayload)?;
                    output.extend_from_slice(&millis.to_le_bytes());
                }
                TaskStep::ReadInteractiveElements => {
                    output.push(12);
                }
            }
        }
        if output.len() > MAX_REQUEST_BYTES {
            return Err(ProtocolError::InvalidTaskPayload);
        }
        Ok(output)
    }

    pub(crate) fn decode_payload(payload: &[u8]) -> Result<Self, ProtocolError> {
        let mut input = Input::new(payload);
        if payload.len() > MAX_REQUEST_BYTES || input.bytes(4)? != TASK_MAGIC {
            return Err(ProtocolError::InvalidTaskPayload);
        }
        let schema_version = input.u16()?;
        let count = usize::from(input.u16()?);
        if count == 0 || count > MAX_TASK_STEPS {
            return Err(ProtocolError::InvalidTaskPayload);
        }
        let runtime = match schema_version {
            TASK_SCHEMA_VERSION_V1 => None,
            TASK_SCHEMA_VERSION_V2 => Some(decode_runtime_contract(&mut input)?),
            _ => return Err(ProtocolError::InvalidTaskPayload),
        };
        let mut steps = Vec::with_capacity(count);
        for _ in 0..count {
            let step = match input.u8()? {
                1 => TaskStep::Navigate {
                    url: input.utf8_u32()?,
                },
                2 => TaskStep::Wait {
                    duration: Duration::from_millis(input.u64()?),
                },
                3 => TaskStep::Wheel {
                    x: input.f64()?,
                    y: input.f64()?,
                    delta_x: input.f64()?,
                    delta_y: input.f64()?,
                },
                4 => TaskStep::KeyPress {
                    key: input.utf8_u16()?,
                },
                5 => TaskStep::ClickSelector {
                    selector: input.utf8_u16()?,
                },
                6 => TaskStep::TypeSelector {
                    selector: input.utf8_u16()?,
                    text: input.utf8_u32()?,
                },
                7 => TaskStep::ReadSelectorText {
                    selector: input.utf8_u16()?,
                },
                8 => TaskStep::Evaluate {
                    script: input.utf8_u32()?,
                },
                9 => TaskStep::Capture {
                    policy: TaskCapturePolicy::from_wire(input.u8()?)?,
                },
                10 => TaskStep::WaitForSelector {
                    selector: input.utf8_u16()?,
                    timeout: Duration::from_millis(input.u64()?),
                },
                11 => TaskStep::WaitForLoadState {
                    state: LoadState::from_wire(input.u8()?)?,
                    timeout: Duration::from_millis(input.u64()?),
                },
                12 => TaskStep::ReadInteractiveElements,
                _ => return Err(ProtocolError::InvalidTaskPayload),
            };
            steps.push(step);
        }
        if !input.is_empty() {
            return Err(ProtocolError::InvalidTaskPayload);
        }
        match runtime {
            Some(runtime) => Self::new_with_runtime(steps, runtime),
            None => Self::new(steps),
        }
    }
}

fn encode_runtime_contract(
    output: &mut Vec<u8>,
    contract: &TaskRuntimeContract,
) -> Result<(), ProtocolError> {
    contract.validate()?;
    output.push(runtime_selector_to_wire(contract.selector));
    output.push(u8::from(contract.requirements.allow_partial()));
    output.push(contract.requirements.features().len() as u8);
    for feature in contract.requirements.features() {
        output.push(runtime_feature_to_wire(*feature));
    }
    Ok(())
}

fn decode_runtime_contract(input: &mut Input<'_>) -> Result<TaskRuntimeContract, ProtocolError> {
    let selector = runtime_selector_from_wire(input.u8()?)?;
    let allow_partial = match input.u8()? {
        0 => false,
        1 => true,
        _ => return Err(ProtocolError::InvalidTaskPayload),
    };
    let count = usize::from(input.u8()?);
    if count > MAX_RUNTIME_FEATURES || (count == 0 && allow_partial) {
        return Err(ProtocolError::InvalidTaskPayload);
    }
    let mut features = Vec::with_capacity(count);
    for _ in 0..count {
        features.push(runtime_feature_from_wire(input.u8()?)?);
    }
    let requirements = RuntimeRequirements::new(features, allow_partial)
        .map_err(|_| ProtocolError::InvalidTaskPayload)?;
    TaskRuntimeContract::new(selector, requirements)
}

fn runtime_selector_to_wire(selector: RuntimeSelector) -> u8 {
    match selector {
        RuntimeSelector::Auto => 0,
        RuntimeSelector::Exact(kind) => runtime_kind_to_wire(kind),
    }
}

fn runtime_selector_from_wire(value: u8) -> Result<RuntimeSelector, ProtocolError> {
    match value {
        0 => Ok(RuntimeSelector::Auto),
        value => runtime_kind_from_wire(value).map(RuntimeSelector::Exact),
    }
}

fn runtime_kind_to_wire(kind: RuntimeKind) -> u8 {
    match kind {
        RuntimeKind::Chrome => 1,
        RuntimeKind::Edge => 2,
        RuntimeKind::Firefox => 3,
        RuntimeKind::Lightweight => 4,
        RuntimeKind::Android => 5,
        RuntimeKind::WebView2 => 6,
        RuntimeKind::Servo => 7,
    }
}

fn runtime_kind_from_wire(value: u8) -> Result<RuntimeKind, ProtocolError> {
    match value {
        1 => Ok(RuntimeKind::Chrome),
        2 => Ok(RuntimeKind::Edge),
        3 => Ok(RuntimeKind::Firefox),
        4 => Ok(RuntimeKind::Lightweight),
        5 => Ok(RuntimeKind::Android),
        6 => Ok(RuntimeKind::WebView2),
        7 => Ok(RuntimeKind::Servo),
        _ => Err(ProtocolError::InvalidTaskPayload),
    }
}

fn runtime_feature_to_wire(feature: RuntimeFeature) -> u8 {
    match feature {
        RuntimeFeature::PointerInput => 1,
        RuntimeFeature::KeyboardInput => 2,
        RuntimeFeature::ScrollInput => 3,
        RuntimeFeature::DomInspect => 4,
        RuntimeFeature::DomInteract => 5,
        RuntimeFeature::ScriptEvaluate => 6,
        RuntimeFeature::Navigate => 7,
        RuntimeFeature::CaptureState => 8,
        RuntimeFeature::CaptureHtml => 9,
        RuntimeFeature::CaptureViewportPng => 10,
        RuntimeFeature::Lifecycle => 11,
        RuntimeFeature::PersistentProfile => 12,
        RuntimeFeature::HeadfulAuthentication => 13,
        RuntimeFeature::DesktopWeb => 14,
        RuntimeFeature::MobileWebEmulation => 15,
        RuntimeFeature::NativeMobileDevice => 16,
    }
}

fn runtime_feature_from_wire(value: u8) -> Result<RuntimeFeature, ProtocolError> {
    match value {
        1 => Ok(RuntimeFeature::PointerInput),
        2 => Ok(RuntimeFeature::KeyboardInput),
        3 => Ok(RuntimeFeature::ScrollInput),
        4 => Ok(RuntimeFeature::DomInspect),
        5 => Ok(RuntimeFeature::DomInteract),
        6 => Ok(RuntimeFeature::ScriptEvaluate),
        7 => Ok(RuntimeFeature::Navigate),
        8 => Ok(RuntimeFeature::CaptureState),
        9 => Ok(RuntimeFeature::CaptureHtml),
        10 => Ok(RuntimeFeature::CaptureViewportPng),
        11 => Ok(RuntimeFeature::Lifecycle),
        12 => Ok(RuntimeFeature::PersistentProfile),
        13 => Ok(RuntimeFeature::HeadfulAuthentication),
        14 => Ok(RuntimeFeature::DesktopWeb),
        15 => Ok(RuntimeFeature::MobileWebEmulation),
        16 => Ok(RuntimeFeature::NativeMobileDevice),
        _ => Err(ProtocolError::InvalidTaskPayload),
    }
}

fn duplicate_runtime_feature(features: impl IntoIterator<Item = RuntimeFeature>) -> bool {
    let mut seen = Vec::new();
    for feature in features {
        if seen.contains(&feature) {
            return true;
        }
        seen.push(feature);
    }
    false
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CaptureCompleteness {
    Complete = 0,
    Partial = 1,
    Unavailable = 2,
}

impl CaptureCompleteness {
    fn from_wire(value: u8) -> Result<Self, ProtocolError> {
        match value {
            0 => Ok(Self::Complete),
            1 => Ok(Self::Partial),
            2 => Ok(Self::Unavailable),
            _ => Err(ProtocolError::InvalidTaskResult),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceCapture {
    pub completeness: CaptureCompleteness,
    pub policy: TaskCapturePolicy,
    pub requested_url: String,
    pub final_url: String,
    pub captured_at_unix_ms: u64,
    pub duration_ms: u64,
    pub http_status: Option<u16>,
    pub title: String,
    pub ready_state: String,
    pub html: Vec<u8>,
    pub png: Vec<u8>,
    pub html_sha256: [u8; 32],
    pub png_sha256: Option<[u8; 32]>,
    pub collector_version: String,
    pub protocol_version: u16,
}

/// One interactive element discovered by `ReadInteractiveElements`.
///
/// `role` is the ARIA `role` attribute when present, else the lowercase tag
/// name; `name` is a best-effort accessible label (may be empty); `selector`
/// is a station-authored CSS path that resolves this element for a later
/// `ClickSelector`/`TypeSelector`/`ReadSelectorText` step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InteractiveElement {
    role: String,
    name: String,
    selector: String,
}

impl InteractiveElement {
    pub fn new(
        role: String,
        name: String,
        selector: String,
    ) -> Result<Self, ProtocolError> {
        let element = Self {
            role,
            name,
            selector,
        };
        element.validate()?;
        Ok(element)
    }

    pub fn role(&self) -> &str {
        &self.role
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn selector(&self) -> &str {
        &self.selector
    }

    fn validate(&self) -> Result<(), ProtocolError> {
        if self.role.is_empty()
            || self.role.len() > MAX_ELEMENT_ROLE_BYTES
            || self.role.contains('\0')
            || self.role.chars().any(char::is_control)
            || self.name.len() > MAX_ELEMENT_NAME_BYTES
            || self.name.contains('\0')
            || self.selector.is_empty()
            || self.selector.len() > MAX_SELECTOR_BYTES
            || self.selector.contains('\0')
        {
            return Err(ProtocolError::InvalidTaskResult);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskReply {
    Acknowledged,
    Text(String),
    ScriptJson(String),
    Capture(Box<EvidenceCapture>),
    /// Result of a `ReadInteractiveElements` step: the page's interactive
    /// elements as typed records (bounded to `MAX_INTERACTIVE_ELEMENTS`).
    Elements(Vec<InteractiveElement>),
}

/// The exact runtime identity and feature support granted for a task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedRuntimeRecord {
    kind: RuntimeKind,
    engine: EngineFamily,
    control: ControlTransport,
    version: Option<String>,
    granted: Vec<FeatureSupport>,
}

impl ResolvedRuntimeRecord {
    pub fn from_resolved(runtime: &ResolvedRuntime) -> Result<Self, ProtocolError> {
        let record = Self {
            kind: runtime.kind(),
            engine: runtime.engine(),
            control: runtime.control(),
            version: runtime.version().map(str::to_owned),
            granted: runtime.granted().to_vec(),
        };
        record.validate()?;
        Ok(record)
    }

    pub fn kind(&self) -> RuntimeKind {
        self.kind
    }

    pub fn engine(&self) -> EngineFamily {
        self.engine
    }

    pub fn control(&self) -> ControlTransport {
        self.control
    }

    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }

    pub fn granted(&self) -> &[FeatureSupport] {
        &self.granted
    }

    fn validate(&self) -> Result<(), ProtocolError> {
        if self.granted.len() > MAX_RUNTIME_FEATURES
            || duplicate_runtime_feature(self.granted.iter().map(FeatureSupport::feature))
        {
            return Err(ProtocolError::InvalidTaskResult);
        }
        if let Some(version) = &self.version {
            if version.is_empty()
                || version.len() > MAX_RUNTIME_VERSION_BYTES
                || version.contains('\0')
                || version.chars().any(char::is_control)
            {
                return Err(ProtocolError::InvalidTaskResult);
            }
        }
        for support in &self.granted {
            if support.level() == SupportLevel::Unsupported
                || support.limitations().len() > MAX_RUNTIME_LIMITATIONS
                || duplicate_runtime_limitation(support.limitations().iter().copied())
            {
                return Err(ProtocolError::InvalidTaskResult);
            }
        }
        Ok(())
    }
}

impl TryFrom<&ResolvedRuntime> for ResolvedRuntimeRecord {
    type Error = ProtocolError;

    fn try_from(runtime: &ResolvedRuntime) -> Result<Self, Self::Error> {
        Self::from_resolved(runtime)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectionTaskResult {
    replies: Vec<TaskReply>,
    runtime: Option<ResolvedRuntimeRecord>,
}

impl CollectionTaskResult {
    pub fn new(replies: Vec<TaskReply>) -> Result<Self, ProtocolError> {
        if replies.is_empty() || replies.len() > MAX_TASK_STEPS {
            return Err(ProtocolError::InvalidTaskResult);
        }
        let result = Self {
            replies,
            runtime: None,
        };
        result.validate()?;
        Ok(result)
    }

    pub fn new_with_runtime(
        replies: Vec<TaskReply>,
        runtime: ResolvedRuntimeRecord,
    ) -> Result<Self, ProtocolError> {
        let result = Self {
            replies,
            runtime: Some(runtime),
        };
        result.validate()?;
        Ok(result)
    }

    pub fn replies(&self) -> &[TaskReply] {
        &self.replies
    }

    pub fn runtime(&self) -> Option<&ResolvedRuntimeRecord> {
        self.runtime.as_ref()
    }

    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        self.validate()?;
        let mut output = Vec::new();
        output.extend_from_slice(&TASK_RESULT_MAGIC);
        let schema_version = if self.runtime.is_some() {
            TASK_SCHEMA_VERSION_V2
        } else {
            TASK_SCHEMA_VERSION_V1
        };
        output.extend_from_slice(&schema_version.to_le_bytes());
        output.extend_from_slice(&(self.replies.len() as u16).to_le_bytes());
        if let Some(runtime) = &self.runtime {
            encode_resolved_runtime(&mut output, runtime)?;
        }
        for reply in &self.replies {
            match reply {
                TaskReply::Acknowledged => output.push(1),
                TaskReply::Text(text) => {
                    output.push(2);
                    put_u32_bytes(&mut output, text.as_bytes())?;
                }
                TaskReply::ScriptJson(value) => {
                    output.push(3);
                    put_u32_bytes(&mut output, value.as_bytes())?;
                }
                TaskReply::Capture(capture) => {
                    output.push(4);
                    encode_capture(&mut output, capture)?;
                }
                TaskReply::Elements(elements) => {
                    output.push(5);
                    output.extend_from_slice(&(elements.len() as u16).to_le_bytes());
                    for element in elements {
                        put_result_u16_bytes(&mut output, element.role.as_bytes())?;
                        put_result_u16_bytes(&mut output, element.name.as_bytes())?;
                        put_result_u16_bytes(&mut output, element.selector.as_bytes())?;
                    }
                }
            }
            if output.len() > MAX_TASK_RESULT_BYTES {
                return Err(ProtocolError::ResponseTooLarge);
            }
        }
        Ok(output)
    }

    pub fn decode(payload: &[u8]) -> Result<Self, ProtocolError> {
        if payload.len() > MAX_TASK_RESULT_BYTES {
            return Err(ProtocolError::ResponseTooLarge);
        }
        let mut input = Input::new(payload);
        if input.bytes(4).map_err(|_| ProtocolError::InvalidTaskResult)?
            != TASK_RESULT_MAGIC
        {
            return Err(ProtocolError::InvalidTaskResult);
        }
        let schema_version = input.u16().map_err(|_| ProtocolError::InvalidTaskResult)?;
        let count = usize::from(input.u16()?);
        if count == 0 || count > MAX_TASK_STEPS {
            return Err(ProtocolError::InvalidTaskResult);
        }
        let runtime = match schema_version {
            TASK_SCHEMA_VERSION_V1 => None,
            TASK_SCHEMA_VERSION_V2 => Some(decode_resolved_runtime(&mut input)?),
            _ => return Err(ProtocolError::InvalidTaskResult),
        };
        let mut replies = Vec::with_capacity(count);
        for _ in 0..count {
            replies.push(match input.u8()? {
                1 => TaskReply::Acknowledged,
                2 => TaskReply::Text(input.utf8_u32_result()?),
                3 => TaskReply::ScriptJson(input.utf8_u32_result()?),
                4 => TaskReply::Capture(Box::new(decode_capture(&mut input)?)),
                5 => {
                    let count = usize::from(input.u16()?);
                    if count > MAX_INTERACTIVE_ELEMENTS {
                        return Err(ProtocolError::InvalidTaskResult);
                    }
                    let mut elements = Vec::with_capacity(count);
                    for _ in 0..count {
                        let role = input.utf8_u16_result()?;
                        let name = input.utf8_u16_result()?;
                        let selector = input.utf8_u16_result()?;
                        elements.push(
                            InteractiveElement::new(role, name, selector)
                                .map_err(|_| ProtocolError::InvalidTaskResult)?,
                        );
                    }
                    TaskReply::Elements(elements)
                }
                _ => return Err(ProtocolError::InvalidTaskResult),
            });
        }
        if !input.is_empty() {
            return Err(ProtocolError::InvalidTaskResult);
        }
        match runtime {
            Some(runtime) => Self::new_with_runtime(replies, runtime),
            None => Self::new(replies),
        }
    }

    fn validate(&self) -> Result<(), ProtocolError> {
        if self.replies.is_empty() || self.replies.len() > MAX_TASK_STEPS {
            return Err(ProtocolError::InvalidTaskResult);
        }
        if let Some(runtime) = &self.runtime {
            runtime.validate()?;
        }
        for reply in &self.replies {
            match reply {
                TaskReply::Acknowledged => {}
                TaskReply::Text(text) => validate_result_text(text, MAX_TEXT_BYTES)?,
                TaskReply::ScriptJson(value) => {
                    validate_result_text(value, MAX_SCRIPT_RESULT_BYTES)?;
                }
                TaskReply::Capture(capture) => validate_capture(capture)?,
                TaskReply::Elements(elements) => {
                    if elements.len() > MAX_INTERACTIVE_ELEMENTS {
                        return Err(ProtocolError::InvalidTaskResult);
                    }
                    for element in elements {
                        element.validate()?;
                    }
                }
            }
        }
        Ok(())
    }
}

fn encode_resolved_runtime(
    output: &mut Vec<u8>,
    runtime: &ResolvedRuntimeRecord,
) -> Result<(), ProtocolError> {
    runtime.validate()?;
    output.push(runtime_kind_to_wire(runtime.kind));
    output.push(engine_to_wire(runtime.engine));
    output.push(control_to_wire(runtime.control));
    output.push(u8::from(runtime.version.is_some()));
    if let Some(version) = &runtime.version {
        put_result_u16_bytes(output, version.as_bytes())?;
    }
    output.push(runtime.granted.len() as u8);
    for support in &runtime.granted {
        output.push(runtime_feature_to_wire(support.feature()));
        output.push(support_level_to_wire(support.level()));
        output.push(support.limitations().len() as u8);
        for limitation in support.limitations() {
            output.push(runtime_limitation_to_wire(*limitation));
        }
    }
    Ok(())
}

pub(crate) fn encode_runtime_record(
    runtime: &ResolvedRuntimeRecord,
) -> Result<Vec<u8>, ProtocolError> {
    let mut output = Vec::new();
    output.extend_from_slice(&RUNTIME_RECORD_MAGIC);
    output.extend_from_slice(&RUNTIME_RECORD_SCHEMA_VERSION.to_le_bytes());
    encode_resolved_runtime(&mut output, runtime)?;
    Ok(output)
}

pub(crate) fn decode_runtime_record(
    payload: &[u8],
) -> Result<ResolvedRuntimeRecord, ProtocolError> {
    let mut input = Input::new(payload);
    if input.bytes(4).map_err(|_| ProtocolError::InvalidTaskResult)?
        != RUNTIME_RECORD_MAGIC
        || input.u16().map_err(|_| ProtocolError::InvalidTaskResult)?
            != RUNTIME_RECORD_SCHEMA_VERSION
    {
        return Err(ProtocolError::InvalidTaskResult);
    }
    let runtime = decode_resolved_runtime(&mut input)?;
    if !input.is_empty() {
        return Err(ProtocolError::InvalidTaskResult);
    }
    Ok(runtime)
}

fn decode_resolved_runtime(input: &mut Input<'_>) -> Result<ResolvedRuntimeRecord, ProtocolError> {
    let kind = runtime_kind_from_wire(input.u8()?)
        .map_err(|_| ProtocolError::InvalidTaskResult)?;
    let engine = engine_from_wire(input.u8()?)?;
    let control = control_from_wire(input.u8()?)?;
    let version = match input.u8()? {
        0 => None,
        1 => Some(input.utf8_u16_result()?),
        _ => return Err(ProtocolError::InvalidTaskResult),
    };
    let count = usize::from(input.u8()?);
    if count > MAX_RUNTIME_FEATURES {
        return Err(ProtocolError::InvalidTaskResult);
    }
    let mut granted = Vec::with_capacity(count);
    for _ in 0..count {
        let feature = runtime_feature_from_wire(input.u8()?)
            .map_err(|_| ProtocolError::InvalidTaskResult)?;
        let level = support_level_from_wire(input.u8()?)?;
        let limitation_count = usize::from(input.u8()?);
        if limitation_count > MAX_RUNTIME_LIMITATIONS {
            return Err(ProtocolError::InvalidTaskResult);
        }
        let mut limitations = Vec::with_capacity(limitation_count);
        for _ in 0..limitation_count {
            limitations.push(runtime_limitation_from_wire(input.u8()?)?);
        }
        granted.push(FeatureSupport::new(feature, level, limitations));
    }
    let record = ResolvedRuntimeRecord {
        kind,
        engine,
        control,
        version,
        granted,
    };
    record.validate()?;
    Ok(record)
}

fn engine_to_wire(engine: EngineFamily) -> u8 {
    match engine {
        EngineFamily::Chromium => 1,
        EngineFamily::Gecko => 2,
        EngineFamily::Dig2Lightweight => 3,
        EngineFamily::AndroidChromium => 4,
        EngineFamily::WebView2 => 5,
        EngineFamily::Servo => 6,
    }
}

fn engine_from_wire(value: u8) -> Result<EngineFamily, ProtocolError> {
    match value {
        1 => Ok(EngineFamily::Chromium),
        2 => Ok(EngineFamily::Gecko),
        3 => Ok(EngineFamily::Dig2Lightweight),
        4 => Ok(EngineFamily::AndroidChromium),
        5 => Ok(EngineFamily::WebView2),
        6 => Ok(EngineFamily::Servo),
        _ => Err(ProtocolError::InvalidTaskResult),
    }
}

fn control_to_wire(control: ControlTransport) -> u8 {
    match control {
        ControlTransport::Cdp => 1,
        ControlTransport::WebDriverBidi => 2,
        ControlTransport::Native => 3,
        ControlTransport::Adb => 4,
        ControlTransport::Embedder => 5,
    }
}

fn control_from_wire(value: u8) -> Result<ControlTransport, ProtocolError> {
    match value {
        1 => Ok(ControlTransport::Cdp),
        2 => Ok(ControlTransport::WebDriverBidi),
        3 => Ok(ControlTransport::Native),
        4 => Ok(ControlTransport::Adb),
        5 => Ok(ControlTransport::Embedder),
        _ => Err(ProtocolError::InvalidTaskResult),
    }
}

fn support_level_to_wire(level: SupportLevel) -> u8 {
    match level {
        SupportLevel::Native => 1,
        SupportLevel::Emulated => 2,
        SupportLevel::Partial => 3,
        SupportLevel::Unsupported => 4,
    }
}

fn support_level_from_wire(value: u8) -> Result<SupportLevel, ProtocolError> {
    match value {
        1 => Ok(SupportLevel::Native),
        2 => Ok(SupportLevel::Emulated),
        3 => Ok(SupportLevel::Partial),
        4 => Ok(SupportLevel::Unsupported),
        _ => Err(ProtocolError::InvalidTaskResult),
    }
}

fn runtime_limitation_to_wire(limitation: RuntimeLimitation) -> u8 {
    match limitation {
        RuntimeLimitation::NoNativeMobileApis => 1,
        RuntimeLimitation::NoCarrierState => 2,
        RuntimeLimitation::NoHardwareAttestation => 3,
        RuntimeLimitation::NoScriptExecution => 4,
        RuntimeLimitation::NoVisualRendering => 5,
        RuntimeLimitation::NoInteractiveDom => 6,
        RuntimeLimitation::NoSubresourceLoading => 7,
        RuntimeLimitation::NoPersonaEmulation => 8,
        RuntimeLimitation::Utf8HtmlOnly => 9,
        RuntimeLimitation::NoBrowserSessionState => 10,
    }
}

fn runtime_limitation_from_wire(value: u8) -> Result<RuntimeLimitation, ProtocolError> {
    match value {
        1 => Ok(RuntimeLimitation::NoNativeMobileApis),
        2 => Ok(RuntimeLimitation::NoCarrierState),
        3 => Ok(RuntimeLimitation::NoHardwareAttestation),
        4 => Ok(RuntimeLimitation::NoScriptExecution),
        5 => Ok(RuntimeLimitation::NoVisualRendering),
        6 => Ok(RuntimeLimitation::NoInteractiveDom),
        7 => Ok(RuntimeLimitation::NoSubresourceLoading),
        8 => Ok(RuntimeLimitation::NoPersonaEmulation),
        9 => Ok(RuntimeLimitation::Utf8HtmlOnly),
        10 => Ok(RuntimeLimitation::NoBrowserSessionState),
        _ => Err(ProtocolError::InvalidTaskResult),
    }
}

fn duplicate_runtime_limitation(
    limitations: impl IntoIterator<Item = RuntimeLimitation>,
) -> bool {
    let mut seen = Vec::new();
    for limitation in limitations {
        if seen.contains(&limitation) {
            return true;
        }
        seen.push(limitation);
    }
    false
}

fn encode_capture(output: &mut Vec<u8>, capture: &EvidenceCapture) -> Result<(), ProtocolError> {
    validate_capture(capture)?;
    output.push(capture.completeness as u8);
    output.push(capture.policy as u8);
    output.extend_from_slice(&capture.http_status.unwrap_or(0).to_le_bytes());
    output.extend_from_slice(&capture.captured_at_unix_ms.to_le_bytes());
    output.extend_from_slice(&capture.duration_ms.to_le_bytes());
    output.extend_from_slice(&capture.protocol_version.to_le_bytes());
    put_u16_bytes(output, capture.collector_version.as_bytes())?;
    put_u32_bytes(output, capture.requested_url.as_bytes())?;
    put_u32_bytes(output, capture.final_url.as_bytes())?;
    put_u32_bytes(output, capture.title.as_bytes())?;
    put_u16_bytes(output, capture.ready_state.as_bytes())?;
    put_u64_bytes(output, &capture.html)?;
    put_u64_bytes(output, &capture.png)?;
    output.extend_from_slice(&capture.html_sha256);
    output.push(u8::from(capture.png_sha256.is_some()));
    output.extend_from_slice(&capture.png_sha256.unwrap_or([0; 32]));
    Ok(())
}

fn decode_capture(input: &mut Input<'_>) -> Result<EvidenceCapture, ProtocolError> {
    let completeness = CaptureCompleteness::from_wire(input.u8()?)?;
    let policy = TaskCapturePolicy::from_wire(input.u8()?)?;
    let http_status = match input.u16()? {
        0 => None,
        status @ 100..=599 => Some(status),
        _ => return Err(ProtocolError::InvalidTaskResult),
    };
    let captured_at_unix_ms = input.u64()?;
    let duration_ms = input.u64()?;
    let protocol_version = input.u16()?;
    let collector_version = input.utf8_u16_result()?;
    let requested_url = input.utf8_u32_result()?;
    let final_url = input.utf8_u32_result()?;
    let title = input.utf8_u32_result()?;
    let ready_state = input.utf8_u16_result()?;
    let html = input.bytes_u64()?.to_vec();
    let png = input.bytes_u64()?.to_vec();
    let html_sha256 = input.array_32()?;
    let png_sha256 = match input.u8()? {
        0 => {
            if input.array_32()? != [0; 32] {
                return Err(ProtocolError::InvalidTaskResult);
            }
            None
        }
        1 => Some(input.array_32()?),
        _ => return Err(ProtocolError::InvalidTaskResult),
    };
    let capture = EvidenceCapture {
        completeness,
        policy,
        requested_url,
        final_url,
        captured_at_unix_ms,
        duration_ms,
        http_status,
        title,
        ready_state,
        html,
        png,
        html_sha256,
        png_sha256,
        collector_version,
        protocol_version,
    };
    validate_capture(&capture)?;
    Ok(capture)
}

fn validate_capture(capture: &EvidenceCapture) -> Result<(), ProtocolError> {
    if capture.protocol_version != PROTOCOL_VERSION
        || capture.collector_version.is_empty()
        || capture.collector_version.len() > MAX_COLLECTOR_VERSION_BYTES
        || capture.collector_version.chars().any(char::is_control)
        || capture.final_url.len() > crate::MAX_FINAL_URL_BYTES
        || capture.title.len() > crate::MAX_TITLE_BYTES
        || capture.ready_state.len() > MAX_SELECTOR_BYTES
        || capture.html.len() > MAX_HTML_BYTES
        || capture.png.len() > MAX_PNG_BYTES
        || capture.requested_url.len() > crate::MAX_FINAL_URL_BYTES
    {
        return Err(ProtocolError::InvalidTaskResult);
    }
    if !capture.requested_url.is_empty() {
        validate_http_url(&capture.requested_url)
            .map_err(|_| ProtocolError::InvalidTaskResult)?;
    }
    if !capture.final_url.is_empty() {
        validate_http_url(&capture.final_url)
            .map_err(|_| ProtocolError::InvalidTaskResult)?;
    }
    if capture.png.is_empty() != capture.png_sha256.is_none() {
        return Err(ProtocolError::InvalidTaskResult);
    }
    Ok(())
}

fn validate_selector(value: &str) -> Result<(), ProtocolError> {
    validate_text(value, MAX_SELECTOR_BYTES, false)
}

fn validate_text(value: &str, maximum: usize, allow_empty: bool) -> Result<(), ProtocolError> {
    if (!allow_empty && value.is_empty()) || value.len() > maximum || value.contains('\0') {
        return Err(ProtocolError::InvalidTaskPayload);
    }
    Ok(())
}

fn validate_result_text(value: &str, maximum: usize) -> Result<(), ProtocolError> {
    if value.len() > maximum || value.contains('\0') {
        return Err(ProtocolError::InvalidTaskResult);
    }
    Ok(())
}

fn put_u16_bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<(), ProtocolError> {
    let len = u16::try_from(value.len()).map_err(|_| ProtocolError::InvalidTaskPayload)?;
    output.extend_from_slice(&len.to_le_bytes());
    output.extend_from_slice(value);
    Ok(())
}

fn put_result_u16_bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<(), ProtocolError> {
    let len = u16::try_from(value.len()).map_err(|_| ProtocolError::InvalidTaskResult)?;
    output.extend_from_slice(&len.to_le_bytes());
    output.extend_from_slice(value);
    Ok(())
}

fn put_u32_bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<(), ProtocolError> {
    let len = u32::try_from(value.len()).map_err(|_| ProtocolError::InvalidTaskPayload)?;
    output.extend_from_slice(&len.to_le_bytes());
    output.extend_from_slice(value);
    Ok(())
}

fn put_u64_bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<(), ProtocolError> {
    let len = u64::try_from(value.len()).map_err(|_| ProtocolError::ResponseTooLarge)?;
    output.extend_from_slice(&len.to_le_bytes());
    output.extend_from_slice(value);
    Ok(())
}

struct Input<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Input<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }

    fn bytes(&mut self, len: usize) -> Result<&'a [u8], ProtocolError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(ProtocolError::InvalidTaskPayload)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(ProtocolError::InvalidTaskPayload)?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, ProtocolError> {
        Ok(self.bytes(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, ProtocolError> {
        Ok(u16::from_le_bytes(self.bytes(2)?.try_into().unwrap()))
    }

    fn u32(&mut self) -> Result<u32, ProtocolError> {
        Ok(u32::from_le_bytes(self.bytes(4)?.try_into().unwrap()))
    }

    fn u64(&mut self) -> Result<u64, ProtocolError> {
        Ok(u64::from_le_bytes(self.bytes(8)?.try_into().unwrap()))
    }

    fn f64(&mut self) -> Result<f64, ProtocolError> {
        Ok(f64::from_le_bytes(self.bytes(8)?.try_into().unwrap()))
    }

    fn utf8_u16(&mut self) -> Result<String, ProtocolError> {
        let len = usize::from(self.u16()?);
        std::str::from_utf8(self.bytes(len)?)
            .map(str::to_owned)
            .map_err(|_| ProtocolError::InvalidTaskPayload)
    }

    fn utf8_u32(&mut self) -> Result<String, ProtocolError> {
        let len = usize::try_from(self.u32()?)
            .map_err(|_| ProtocolError::InvalidTaskPayload)?;
        std::str::from_utf8(self.bytes(len)?)
            .map(str::to_owned)
            .map_err(|_| ProtocolError::InvalidTaskPayload)
    }

    fn utf8_u16_result(&mut self) -> Result<String, ProtocolError> {
        self.utf8_u16()
            .map_err(|_| ProtocolError::InvalidTaskResult)
    }

    fn utf8_u32_result(&mut self) -> Result<String, ProtocolError> {
        self.utf8_u32()
            .map_err(|_| ProtocolError::InvalidTaskResult)
    }

    fn bytes_u64(&mut self) -> Result<&'a [u8], ProtocolError> {
        let len = usize::try_from(self.u64()?).map_err(|_| ProtocolError::InvalidTaskResult)?;
        self.bytes(len)
            .map_err(|_| ProtocolError::InvalidTaskResult)
    }

    fn array_32(&mut self) -> Result<[u8; 32], ProtocolError> {
        self.bytes(32)?
            .try_into()
            .map_err(|_| ProtocolError::InvalidTaskResult)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dig2browser_core::RuntimeDescriptor;

    fn navigate_step() -> TaskStep {
        TaskStep::Navigate {
            url: "https://example.test".to_owned(),
        }
    }

    #[test]
    fn legacy_task_keeps_v1_bytes_and_decodes_without_runtime() {
        let task = CollectionTask::new(vec![navigate_step()]).expect("valid task");
        let mut expected = Vec::from(*b"D2TK");
        expected.extend_from_slice(&1_u16.to_le_bytes());
        expected.extend_from_slice(&1_u16.to_le_bytes());
        expected.push(1);
        expected.extend_from_slice(&20_u32.to_le_bytes());
        expected.extend_from_slice(b"https://example.test");

        let encoded = task.encode_payload().expect("encode task");
        assert_eq!(encoded, expected);
        let decoded = CollectionTask::decode_payload(&encoded).expect("decode task");
        assert_eq!(decoded, task);
        assert_eq!(decoded.runtime_contract(), None);
    }

    #[test]
    fn wait_for_selector_round_trips_and_is_not_interaction_or_script() {
        let task = CollectionTask::new(vec![
            navigate_step(),
            TaskStep::WaitForSelector {
                selector: "#ready".to_owned(),
                timeout: Duration::from_secs(5),
            },
        ])
        .expect("valid task");

        let encoded = task.encode_payload().expect("encode task");
        let decoded = CollectionTask::decode_payload(&encoded).expect("decode task");
        assert_eq!(decoded, task);
        // Inspect-only: waiting for an element is neither interaction nor script.
        assert!(!task.requires_interaction());
        assert!(!task.requires_script());
    }

    #[test]
    fn wait_for_load_state_round_trips_and_is_not_interaction_or_script() {
        let task = CollectionTask::new(vec![
            navigate_step(),
            TaskStep::WaitForLoadState {
                state: LoadState::Interactive,
                timeout: Duration::from_secs(5),
            },
            TaskStep::WaitForLoadState {
                state: LoadState::Complete,
                timeout: Duration::from_secs(5),
            },
        ])
        .expect("valid task");

        let encoded = task.encode_payload().expect("encode task");
        let decoded = CollectionTask::decode_payload(&encoded).expect("decode task");
        assert_eq!(decoded, task);
        assert!(!task.requires_interaction());
        assert!(!task.requires_script());

        // A zero timeout is rejected, and the cumulative wait budget is enforced.
        assert!(CollectionTask::new(vec![
            navigate_step(),
            TaskStep::WaitForLoadState {
                state: LoadState::Complete,
                timeout: Duration::ZERO,
            },
        ])
        .is_err());
        assert!(CollectionTask::new(vec![
            navigate_step(),
            TaskStep::WaitForLoadState {
                state: LoadState::Complete,
                timeout: MAX_TASK_WAIT + Duration::from_millis(1),
            },
        ])
        .is_err());
    }

    #[test]
    fn read_interactive_elements_step_round_trips_and_is_not_interaction_or_script() {
        let task = CollectionTask::new(vec![
            navigate_step(),
            TaskStep::ReadInteractiveElements,
            TaskStep::ClickSelector {
                selector: "#submit".to_owned(),
            },
        ])
        .expect("valid task");

        let encoded = task.encode_payload().expect("encode task");
        let decoded = CollectionTask::decode_payload(&encoded).expect("decode task");
        assert_eq!(decoded, task);
        // Inspect-only: enumerating elements is neither interaction nor script.
        assert!(!task.requires_script());
    }

    #[test]
    fn elements_reply_round_trips_and_rejects_malformed() {
        let elements = vec![
            InteractiveElement::new(
                "button".to_owned(),
                "Sign in".to_owned(),
                "#submit".to_owned(),
            )
            .expect("valid element"),
            InteractiveElement::new(
                "link".to_owned(),
                String::new(),
                "nav > a:nth-of-type(2)".to_owned(),
            )
            .expect("empty name allowed"),
        ];
        let result = CollectionTaskResult::new(vec![
            TaskReply::Acknowledged,
            TaskReply::Elements(elements),
        ])
        .expect("valid result");

        let encoded = result.encode().expect("encode result");
        assert_eq!(
            CollectionTaskResult::decode(&encoded).expect("decode result"),
            result
        );

        // An empty role and an over-length selector are both rejected.
        assert!(InteractiveElement::new(
            String::new(),
            "x".to_owned(),
            "#a".to_owned()
        )
        .is_err());
        assert!(InteractiveElement::new(
            "button".to_owned(),
            "x".to_owned(),
            "a".repeat(MAX_SELECTOR_BYTES + 1),
        )
        .is_err());
    }

    #[test]
    fn wait_for_selector_rejects_zero_and_over_budget_timeout() {
        assert!(CollectionTask::new(vec![
            navigate_step(),
            TaskStep::WaitForSelector {
                selector: "#ready".to_owned(),
                timeout: Duration::ZERO,
            },
        ])
        .is_err());

        assert!(CollectionTask::new(vec![
            navigate_step(),
            TaskStep::WaitForSelector {
                selector: "#ready".to_owned(),
                timeout: MAX_TASK_WAIT + Duration::from_millis(1),
            },
        ])
        .is_err());

        // The timeout shares the cumulative wait budget with `Wait`.
        assert!(CollectionTask::new(vec![
            navigate_step(),
            TaskStep::Wait { duration: MAX_TASK_WAIT },
            TaskStep::WaitForSelector {
                selector: "#ready".to_owned(),
                timeout: Duration::from_millis(1),
            },
        ])
        .is_err());
    }

    #[test]
    fn runtime_task_uses_v2_and_round_trips() {
        let requirements = RuntimeRequirements::new(
            vec![RuntimeFeature::Navigate, RuntimeFeature::DomInspect],
            true,
        )
        .expect("valid requirements");
        let contract = TaskRuntimeContract::new(
            RuntimeSelector::Exact(RuntimeKind::Firefox),
            requirements,
        )
        .expect("valid runtime contract");
        let task = CollectionTask::new_with_runtime(vec![navigate_step()], contract)
            .expect("valid runtime task");

        let encoded = task.encode_payload().expect("encode task");
        assert_eq!(&encoded[4..6], &2_u16.to_le_bytes());
        assert_eq!(
            CollectionTask::decode_payload(&encoded).expect("decode task"),
            task
        );
    }

    #[test]
    fn runtime_task_decoder_rejects_unknown_flags_enums_and_duplicates() {
        let requirements = RuntimeRequirements::new(
            vec![RuntimeFeature::Navigate, RuntimeFeature::DomInspect],
            true,
        )
        .expect("valid requirements");
        let contract = TaskRuntimeContract::new(RuntimeSelector::Auto, requirements)
            .expect("valid runtime contract");
        let task = CollectionTask::new_with_runtime(vec![navigate_step()], contract)
            .expect("valid runtime task");
        let encoded = task.encode_payload().expect("encode task");

        let mut unknown_selector = encoded.clone();
        unknown_selector[8] = u8::MAX;
        assert!(CollectionTask::decode_payload(&unknown_selector).is_err());

        let mut unknown_flags = encoded.clone();
        unknown_flags[9] = 2;
        assert!(CollectionTask::decode_payload(&unknown_flags).is_err());

        let mut duplicate_feature = encoded;
        duplicate_feature[12] = duplicate_feature[11];
        assert!(CollectionTask::decode_payload(&duplicate_feature).is_err());
    }

    #[test]
    fn resolved_runtime_result_uses_v2_and_round_trips_exact_support() {
        let support = FeatureSupport::new(
            RuntimeFeature::MobileWebEmulation,
            SupportLevel::Partial,
            vec![
                RuntimeLimitation::NoNativeMobileApis,
                RuntimeLimitation::NoCarrierState,
            ],
        );
        let descriptor = RuntimeDescriptor::new(
            RuntimeKind::Chrome,
            EngineFamily::Chromium,
            ControlTransport::Cdp,
            vec![support],
        )
        .expect("valid descriptor");
        let requirements = RuntimeRequirements::new(
            vec![RuntimeFeature::MobileWebEmulation],
            true,
        )
        .expect("valid requirements");
        let resolved = descriptor
            .negotiate(&requirements, Some("127.0.6533.72".to_owned()))
            .expect("resolved runtime");
        let runtime = ResolvedRuntimeRecord::from_resolved(&resolved)
            .expect("valid runtime record");
        let result = CollectionTaskResult::new_with_runtime(
            vec![TaskReply::Acknowledged],
            runtime,
        )
        .expect("valid result");

        let encoded = result.encode().expect("encode result");
        assert_eq!(&encoded[4..6], &2_u16.to_le_bytes());
        let decoded = CollectionTaskResult::decode(&encoded).expect("decode result");
        assert_eq!(decoded, result);
        let decoded_runtime = decoded.runtime().expect("runtime record");
        assert_eq!(decoded_runtime.version(), Some("127.0.6533.72"));
        assert_eq!(decoded_runtime.granted(), resolved.granted());
    }

    #[test]
    fn lightweight_runtime_limitations_round_trip() {
        let limitations = vec![
            RuntimeLimitation::NoScriptExecution,
            RuntimeLimitation::NoVisualRendering,
            RuntimeLimitation::NoInteractiveDom,
            RuntimeLimitation::NoSubresourceLoading,
            RuntimeLimitation::NoPersonaEmulation,
            RuntimeLimitation::Utf8HtmlOnly,
            RuntimeLimitation::NoBrowserSessionState,
        ];
        let descriptor = RuntimeDescriptor::new(
            RuntimeKind::Lightweight,
            EngineFamily::Dig2Lightweight,
            ControlTransport::Native,
            vec![FeatureSupport::new(
                RuntimeFeature::DesktopWeb,
                SupportLevel::Partial,
                limitations.clone(),
            )],
        )
        .expect("valid lightweight descriptor");
        let requirements = RuntimeRequirements::new(
            vec![RuntimeFeature::DesktopWeb],
            true,
        )
        .expect("valid lightweight requirements");
        let resolved = descriptor
            .negotiate(&requirements, Some("0.1.0".to_owned()))
            .expect("resolve lightweight runtime");
        let runtime = ResolvedRuntimeRecord::from_resolved(&resolved)
            .expect("valid lightweight runtime record");

        let encoded = encode_runtime_record(&runtime).expect("encode runtime record");
        let decoded = decode_runtime_record(&encoded).expect("decode runtime record");

        assert_eq!(decoded.kind(), RuntimeKind::Lightweight);
        assert_eq!(decoded.engine(), EngineFamily::Dig2Lightweight);
        assert_eq!(decoded.control(), ControlTransport::Native);
        assert_eq!(decoded.granted()[0].limitations(), limitations);
    }

    #[test]
    fn runtime_result_decoder_rejects_unknown_flags_enums_and_duplicates() {
        let descriptor = RuntimeDescriptor::new(
            RuntimeKind::Chrome,
            EngineFamily::Chromium,
            ControlTransport::Cdp,
            vec![
                FeatureSupport::new(
                    RuntimeFeature::Navigate,
                    SupportLevel::Native,
                    Vec::new(),
                ),
                FeatureSupport::new(
                    RuntimeFeature::DomInspect,
                    SupportLevel::Native,
                    Vec::new(),
                ),
            ],
        )
        .expect("valid descriptor");
        let requirements = RuntimeRequirements::new(
            vec![RuntimeFeature::Navigate, RuntimeFeature::DomInspect],
            false,
        )
        .expect("valid requirements");
        let resolved = descriptor
            .negotiate(&requirements, None)
            .expect("resolved runtime");
        let runtime = ResolvedRuntimeRecord::from_resolved(&resolved)
            .expect("valid runtime record");
        let result = CollectionTaskResult::new_with_runtime(
            vec![TaskReply::Acknowledged],
            runtime,
        )
        .expect("valid result");
        let encoded = result.encode().expect("encode result");

        let mut unknown_kind = encoded.clone();
        unknown_kind[8] = u8::MAX;
        assert!(CollectionTaskResult::decode(&unknown_kind).is_err());

        let mut unknown_flags = encoded.clone();
        unknown_flags[11] = 2;
        assert!(CollectionTaskResult::decode(&unknown_flags).is_err());

        let mut unknown_level = encoded.clone();
        unknown_level[14] = u8::MAX;
        assert!(CollectionTaskResult::decode(&unknown_level).is_err());

        let mut duplicate_feature = encoded;
        duplicate_feature[16] = duplicate_feature[13];
        assert!(CollectionTaskResult::decode(&duplicate_feature).is_err());
    }

    #[test]
    fn legacy_result_keeps_v1_bytes_and_decodes_without_runtime() {
        let result = CollectionTaskResult::new(vec![TaskReply::Acknowledged])
            .expect("valid result");
        let encoded = result.encode().expect("encode result");
        assert_eq!(encoded, b"D2TR\x01\x00\x01\x00\x01");
        let decoded = CollectionTaskResult::decode(&encoded).expect("decode result");
        assert_eq!(decoded.runtime(), None);
        assert_eq!(decoded, result);
    }

    #[test]
    fn standalone_runtime_record_round_trips_and_rejects_malformed_payload() {
        let descriptor = RuntimeDescriptor::new(
            RuntimeKind::Chrome,
            EngineFamily::Chromium,
            ControlTransport::Cdp,
            vec![FeatureSupport::new(
                RuntimeFeature::Navigate,
                SupportLevel::Native,
                Vec::new(),
            )],
        )
        .expect("valid descriptor");
        let requirements = RuntimeRequirements::new(
            vec![RuntimeFeature::Navigate],
            false,
        )
        .expect("valid requirements");
        let resolved = descriptor
            .negotiate(&requirements, Some("runtime-v1".to_owned()))
            .expect("resolved runtime");
        let record = ResolvedRuntimeRecord::from_resolved(&resolved)
            .expect("runtime record");
        let encoded = encode_runtime_record(&record).expect("encode runtime record");
        assert_eq!(decode_runtime_record(&encoded).unwrap(), record);

        let mut unknown_version = encoded.clone();
        unknown_version[4..6].copy_from_slice(&2_u16.to_le_bytes());
        assert!(decode_runtime_record(&unknown_version).is_err());
        let mut trailing = encoded;
        trailing.push(0);
        assert!(decode_runtime_record(&trailing).is_err());
    }

    #[test]
    fn task_and_evidence_result_round_trip() {
        let task = CollectionTask::new(vec![
            TaskStep::Navigate {
                url: "https://example.test/reviews".to_owned(),
            },
            TaskStep::Wait {
                duration: Duration::from_millis(250),
            },
            TaskStep::ReadSelectorText {
                selector: "main".to_owned(),
            },
            TaskStep::Capture {
                policy: TaskCapturePolicy::EvidenceViewport,
            },
        ])
        .expect("valid task");
        assert_eq!(
            CollectionTask::decode_payload(&task.encode_payload().expect("encode task"))
                .expect("decode task"),
            task
        );

        let capture = EvidenceCapture {
            completeness: CaptureCompleteness::Complete,
            policy: TaskCapturePolicy::EvidenceViewport,
            requested_url: "https://example.test/reviews".to_owned(),
            final_url: "https://example.test/reviews".to_owned(),
            captured_at_unix_ms: 1_784_405_000_000,
            duration_ms: 21,
            http_status: Some(200),
            title: "Reviews".to_owned(),
            ready_state: "complete".to_owned(),
            html: b"<main>review</main>".to_vec(),
            png: b"png".to_vec(),
            html_sha256: [1; 32],
            png_sha256: Some([2; 32]),
            collector_version: "dig2browser-station/0.1.0".to_owned(),
            protocol_version: PROTOCOL_VERSION,
        };
        let result = CollectionTaskResult::new(vec![
            TaskReply::Text("review".to_owned()),
            TaskReply::Capture(Box::new(capture)),
        ])
        .expect("valid result");
        assert_eq!(
            CollectionTaskResult::decode(&result.encode().expect("encode result"))
                .expect("decode result"),
            result
        );
    }
}
