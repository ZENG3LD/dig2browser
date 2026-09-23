use super::AgentError;
use gate4agent::{
    pipe::{ClaudeOptions, PipeProcessOptions, PipeSession},
    AgentEvent, CliTool, SessionConfig,
};
use std::path::PathBuf;
use tracing::{debug, info, warn};

const DEFAULT_TIMEOUT_SECS: u64 = 600;

/// A multi-turn Claude session backed by gate4agent's `PipeSession`.
///
/// Each `send_prompt` call:
/// 1. Spawns a `PipeSession` with the prompt delivered via stdin
/// 2. Collects events from the broadcast channel until `SessionEnd` or `Exited`
/// 3. Captures the `session_id` from `SessionStart` for `--resume` on next call
/// 4. Accumulates all `Text` deltas into the full response string
/// 5. Returns the collected text
///
/// On the first call a fresh conversation is started. On subsequent calls
/// `--resume <session_id>` is added so Claude retains full prior context.
pub struct AgentSession {
    working_dir: PathBuf,
    resume_session_id: Option<String>,
    system_prompt: Option<String>,
    timeout_secs: u64,
    model: Option<String>,
}

impl AgentSession {
    /// Create a session handle. No process is spawned here.
    pub async fn start() -> Result<Self, AgentError> {
        let working_dir = std::env::current_dir()
            .map_err(|e| AgentError::Spawn(format!("cannot get cwd: {e}")))?;
        Ok(Self {
            working_dir,
            resume_session_id: None,
            system_prompt: None,
            timeout_secs: DEFAULT_TIMEOUT_SECS,
            model: None,
        })
    }

    /// Override the per-prompt timeout (default: 600 s).
    pub fn with_timeout(mut self, secs: u64) -> Self {
        self.timeout_secs = secs;
        self
    }

    /// Override the Claude model passed to `--model` (default: None = claude CLI default).
    pub fn with_model(mut self, model: String) -> Self {
        self.model = Some(model);
        self
    }

    /// Attach a system prompt that is appended via `--append-system-prompt`.
    pub fn with_system_prompt(mut self, prompt: String) -> Self {
        self.system_prompt = Some(prompt);
        self
    }

    /// Returns the Claude session_id captured from the last successful call.
    pub fn session_id(&self) -> Option<&str> {
        self.resume_session_id.as_deref()
    }

    /// Send a prompt to Claude and collect the full text response.
    ///
    /// The prompt is written to Claude's stdin (no file intermediary). Claude
    /// reads HTML/screenshot files referenced in the prompt via its Read tool.
    /// The response text is collected from `Text` events.
    ///
    /// On the first call a fresh session is started. On subsequent calls
    /// `--resume <session_id>` is passed so Claude retains full conversational context.
    pub async fn send_prompt(&mut self, prompt: &str) -> Result<String, AgentError> {
        let config = SessionConfig {
            tool: CliTool::ClaudeCode,
            working_dir: self.working_dir.clone(),
            env_vars: Vec::new(),
            name: None,
        };

        let options = PipeProcessOptions {
            extra_args: Vec::new(),
            claude: ClaudeOptions {
                resume_session_id: self.resume_session_id.clone(),
                append_system_prompt: self.system_prompt.clone(),
                model: self.model.clone(),
            },
        };

        info!(
            resume = ?self.resume_session_id,
            prompt_len = prompt.len(),
            "Spawning Claude pipe session"
        );

        let session = PipeSession::spawn(config, prompt, options)
            .await
            .map_err(|e| AgentError::Spawn(format!("gate4agent spawn failed: {e}")))?;

        let mut rx = session.subscribe();
        let mut collected_text = String::new();

        let timeout_duration = std::time::Duration::from_secs(self.timeout_secs);
        let deadline = tokio::time::Instant::now() + timeout_duration;

        loop {
            match tokio::time::timeout_at(deadline, rx.recv()).await {
                Ok(Ok(event)) => match event {
                    AgentEvent::SessionStart {
                        session_id,
                        model,
                        tools,
                    } => {
                        info!(
                            session_id = %session_id,
                            model = %model,
                            tools_count = tools.len(),
                            "Claude session started"
                        );
                        self.resume_session_id = Some(session_id);
                    }
                    AgentEvent::Text { text, is_delta } => {
                        debug!(is_delta, text_len = text.len(), "Text received");
                        collected_text.push_str(&text);
                    }
                    AgentEvent::ToolStart { name, .. } => {
                        debug!(tool = %name, "Claude calling tool");
                    }
                    AgentEvent::ToolResult {
                        is_error: true,
                        output,
                        ..
                    } => {
                        warn!(output = %output, "Tool call returned error");
                    }
                    AgentEvent::Thinking { text } => {
                        debug!(thinking_len = text.len(), "Claude thinking");
                    }
                    AgentEvent::TurnComplete {
                        input_tokens,
                        output_tokens,
                        ..
                    } => {
                        info!(input_tokens, output_tokens, "Turn complete");
                    }
                    AgentEvent::SessionEnd {
                        result,
                        cost_usd,
                        is_error,
                        ..
                    } => {
                        if is_error {
                            warn!(result = %result, "Session ended with error flag");
                        }
                        if let Some(cost) = cost_usd {
                            info!(cost_usd = cost, "Session cost");
                        }
                        break;
                    }
                    AgentEvent::Exited { code } => {
                        debug!(code, "Claude process exited");
                        break;
                    }
                    AgentEvent::Error { message } => {
                        warn!(message = %message, "Agent error event");
                    }
                    _ => {}
                },
                Ok(Err(tokio::sync::broadcast::error::RecvError::Closed)) => {
                    debug!("Broadcast channel closed");
                    break;
                }
                Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(n))) => {
                    warn!(n, "Broadcast channel lagged — some events dropped");
                }
                Err(_elapsed) => {
                    return Err(AgentError::Timeout {
                        secs: self.timeout_secs,
                    });
                }
            }
        }

        info!(
            response_len = collected_text.len(),
            session_id = ?self.resume_session_id,
            "Prompt complete"
        );

        Ok(collected_text)
    }

    /// No-op — there is no persistent process to kill.
    pub async fn close(self) {
        info!("AgentSession closed");
    }
}
