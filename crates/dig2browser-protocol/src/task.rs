use std::time::Duration;

use crate::{
    validate_http_url, ProtocolError, MAX_HTML_BYTES, MAX_PNG_BYTES,
    PROTOCOL_VERSION,
};

pub const MAX_TASK_STEPS: usize = 64;
pub const MAX_TASK_WAIT: Duration = Duration::from_secs(2 * 60);
pub const MAX_TASK_RESULT_BYTES: usize = MAX_HTML_BYTES;

const TASK_MAGIC: [u8; 4] = *b"D2TK";
const TASK_RESULT_MAGIC: [u8; 4] = *b"D2TR";
const TASK_SCHEMA_VERSION: u16 = 1;
const MAX_SELECTOR_BYTES: usize = 4_096;
const MAX_KEY_BYTES: usize = 64;
const MAX_TEXT_BYTES: usize = 64 * 1024;
const MAX_SCRIPT_BYTES: usize = 64 * 1024;
const MAX_SCRIPT_RESULT_BYTES: usize = 4 * 1024 * 1024;
const MAX_COLLECTOR_VERSION_BYTES: usize = 128;

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
}

#[derive(Debug, Clone, PartialEq)]
pub struct CollectionTask {
    steps: Vec<TaskStep>,
}

impl CollectionTask {
    pub fn new(steps: Vec<TaskStep>) -> Result<Self, ProtocolError> {
        let task = Self { steps };
        task.validate()?;
        Ok(task)
    }

    pub fn steps(&self) -> &[TaskStep] {
        &self.steps
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
            }
        }
        Ok(())
    }

    pub(crate) fn encode_payload(&self) -> Result<Vec<u8>, ProtocolError> {
        self.validate()?;
        let mut output = Vec::new();
        output.extend_from_slice(&TASK_MAGIC);
        output.extend_from_slice(&TASK_SCHEMA_VERSION.to_le_bytes());
        output.extend_from_slice(&(self.steps.len() as u16).to_le_bytes());
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
            }
        }
        Ok(output)
    }

    pub(crate) fn decode_payload(payload: &[u8]) -> Result<Self, ProtocolError> {
        let mut input = Input::new(payload);
        if input.bytes(4)? != TASK_MAGIC
            || input.u16()? != TASK_SCHEMA_VERSION
        {
            return Err(ProtocolError::InvalidTaskPayload);
        }
        let count = usize::from(input.u16()?);
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
                _ => return Err(ProtocolError::InvalidTaskPayload),
            };
            steps.push(step);
        }
        if !input.is_empty() {
            return Err(ProtocolError::InvalidTaskPayload);
        }
        Self::new(steps)
    }
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskReply {
    Acknowledged,
    Text(String),
    ScriptJson(String),
    Capture(Box<EvidenceCapture>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectionTaskResult {
    replies: Vec<TaskReply>,
}

impl CollectionTaskResult {
    pub fn new(replies: Vec<TaskReply>) -> Result<Self, ProtocolError> {
        if replies.is_empty() || replies.len() > MAX_TASK_STEPS {
            return Err(ProtocolError::InvalidTaskResult);
        }
        let result = Self { replies };
        result.validate()?;
        Ok(result)
    }

    pub fn replies(&self) -> &[TaskReply] {
        &self.replies
    }

    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        self.validate()?;
        let mut output = Vec::new();
        output.extend_from_slice(&TASK_RESULT_MAGIC);
        output.extend_from_slice(&TASK_SCHEMA_VERSION.to_le_bytes());
        output.extend_from_slice(&(self.replies.len() as u16).to_le_bytes());
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
        if input.bytes(4)? != TASK_RESULT_MAGIC
            || input.u16()? != TASK_SCHEMA_VERSION
        {
            return Err(ProtocolError::InvalidTaskResult);
        }
        let count = usize::from(input.u16()?);
        let mut replies = Vec::with_capacity(count);
        for _ in 0..count {
            replies.push(match input.u8()? {
                1 => TaskReply::Acknowledged,
                2 => TaskReply::Text(input.utf8_u32_result()?),
                3 => TaskReply::ScriptJson(input.utf8_u32_result()?),
                4 => TaskReply::Capture(Box::new(decode_capture(&mut input)?)),
                _ => return Err(ProtocolError::InvalidTaskResult),
            });
        }
        if !input.is_empty() {
            return Err(ProtocolError::InvalidTaskResult);
        }
        Self::new(replies)
    }

    fn validate(&self) -> Result<(), ProtocolError> {
        for reply in &self.replies {
            match reply {
                TaskReply::Acknowledged => {}
                TaskReply::Text(text) => validate_result_text(text, MAX_TEXT_BYTES)?,
                TaskReply::ScriptJson(value) => {
                    validate_result_text(value, MAX_SCRIPT_RESULT_BYTES)?;
                }
                TaskReply::Capture(capture) => validate_capture(capture)?,
            }
        }
        Ok(())
    }
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
