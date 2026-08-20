use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProviderId(pub String);

impl ProviderId {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TaskKey {
    pub client_id: String,
    pub provider: ProviderId,
    pub session_id: String,
    pub thread_id: String,
    pub turn_id: String,
}

impl TaskKey {
    #[must_use]
    pub fn task_ref(&self) -> String {
        format!("{}:{}:{}", self.session_id, self.thread_id, self.turn_id)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionSummary {
    pub task: TaskKey,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_turn_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_turn_id: Option<String>,
    pub first_seen_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskPhase {
    Running,
    AwaitingTool,
    Retrying,
    Terminal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskOutcome {
    Completed,
    Failed,
    Aborted,
    Terminated,
    Lost,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Completeness {
    Complete,
    Degraded,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptStatus {
    Running,
    Completed,
    Failed,
    Incomplete,
    Cancelled,
    TransportLost,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransitionCause {
    CaptureStarted,
    AttemptStarted,
    AttemptCompleted,
    ResponseEndTurn,
    ToolCallObserved,
    RetryScheduled,
    CodexTurnComplete,
    CodexTurnAborted,
    ProcessExited,
    CaptureLost,
    ClientRecovered,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderError {
    pub wire_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub param: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpError {
    pub status: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_error: Option<ProviderError>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncompleteResponse {
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodexTerminalError {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TurnAbort {
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessTermination {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signal: Option<i32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureLoss {
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lost_bytes: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnsupportedCodexBuild {
    pub executable_sha256: String,
    pub architecture: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub codex_version: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "error_kind", rename_all = "snake_case")]
pub enum StructuredError {
    Provider(ProviderError),
    Http(HttpError),
    Incomplete(IncompleteResponse),
    CodexTerminal(CodexTerminalError),
    TurnAborted(TurnAbort),
    ProcessTerminated(ProcessTermination),
    CaptureLost(CaptureLoss),
    UnsupportedCodexBuild(UnsupportedCodexBuild),
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenUsage {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_tokens: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_tokens: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cached_input_tokens: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasoning_tokens: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_tokens: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskTransition {
    pub event_id: Uuid,
    pub task: TaskKey,
    pub sequence: u64,
    pub observed_at: OffsetDateTime,
    pub phase: TaskPhase,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<TaskOutcome>,
    pub cause: TransitionCause,
    pub completeness: Completeness,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<StructuredError>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskSummary {
    pub task: TaskKey,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conversation_title: Option<String>,
    pub phase: TaskPhase,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<TaskOutcome>,
    pub sequence: u64,
    pub last_event_id: Uuid,
    pub started_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_at: Option<OffsetDateTime>,
    pub attempt_count: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(default)]
    pub tool_names: Vec<String>,
    #[serde(default)]
    pub response_ids: Vec<String>,
    #[serde(default)]
    pub usage: TokenUsage,
    pub completeness: Completeness,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<StructuredError>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttemptSummary {
    pub attempt_id: Uuid,
    pub task: TaskKey,
    pub ordinal: u32,
    pub status: AttemptStatus,
    pub started_at: OffsetDateTime,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<OffsetDateTime>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(default)]
    pub tool_names: Vec<String>,
    #[serde(default)]
    pub usage: TokenUsage,
    pub completeness: Completeness,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<StructuredError>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpExchangeSummary {
    pub exchange_id: Uuid,
    pub task: TaskKey,
    pub attempt_id: Uuid,
    pub observed_at: OffsetDateTime,
    pub method: String,
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    pub request_bytes: u64,
    pub response_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_sha256: Option<String>,
    pub completeness: Completeness,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureGapSummary {
    pub gap_id: Uuid,
    pub client_instance_id: Uuid,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task: Option<TaskKey>,
    pub observed_at: OffsetDateTime,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lost_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flow_id: Option<Uuid>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessSummary {
    pub process_instance_id: Uuid,
    pub client_instance_id: Uuid,
    pub pid: u32,
    pub executable_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub codex_version: Option<String>,
    pub started_at: OffsetDateTime,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exited_at: Option<OffsetDateTime>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signal: Option<i32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureHealth {
    pub af_packet_active: bool,
    pub uprobe_active: bool,
    pub profile_supported: bool,
    pub ring_buffer_drops: u64,
    pub active_flows: u32,
    pub outbox_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<StructuredError>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeartbeatSummary {
    pub client_instance_id: Uuid,
    pub observed_at: OffsetDateTime,
    pub client_version: String,
    pub health: CaptureHealth,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "record_type", content = "record", rename_all = "snake_case")]
pub enum SummaryRecord {
    Session(SessionSummary),
    Task(TaskSummary),
    TaskTransition(TaskTransition),
    Attempt(AttemptSummary),
    HttpExchange(HttpExchangeSummary),
    CaptureGap(CaptureGapSummary),
    Process(ProcessSummary),
    Heartbeat(HeartbeatSummary),
}
