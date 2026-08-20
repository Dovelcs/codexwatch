use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub type TimestampMs = i64;

pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_ERROR_MESSAGE_BYTES: usize = 32 * 1024;
pub const MAX_CONTENT_CHUNK_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientInstance {
    pub client_id: String,
    pub instance_id: Uuid,
    pub hostname: String,
    pub platform: String,
    pub codex_version: String,
    pub started_at_ms: TimestampMs,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IngestBatch {
    pub version: u16,
    pub batch_id: Uuid,
    pub generated_at_ms: TimestampMs,
    pub client: ClientInstance,
    pub tasks: Vec<TaskUpload>,
    pub heartbeats: Vec<Heartbeat>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Heartbeat {
    pub heartbeat_id: Uuid,
    pub client_id: String,
    pub instance_id: Uuid,
    pub observed_at_ms: TimestampMs,
    pub queue_depth: u32,
    pub active_task_count: u32,
    pub capture_health: IntegrityState,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TaskIdentity {
    pub provider: String,
    pub session_id: String,
    pub thread_id: String,
    pub turn_id: String,
}

impl TaskIdentity {
    #[must_use]
    pub fn task_ref(&self) -> String {
        format!("{}:{}:{}", self.session_id, self.thread_id, self.turn_id)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CodexTaskMetadata {
    pub request_kind: String,
    pub parent_turn_id: Option<String>,
    pub root_turn_id: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum TaskPhase {
    Running,
    AwaitingTool,
    Retrying,
    Terminal,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum TerminalOutcome {
    Completed,
    Failed,
    Aborted,
    Terminated,
    Lost,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum IntegrityState {
    Complete,
    Degraded,
    Lost,
    UnsupportedBuild,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum AttemptStatus {
    Running,
    Completed,
    Failed,
    Incomplete,
    Cancelled,
    TransportLost,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ErrorSource {
    ResponseFailed,
    ResponseIncomplete,
    ResponseCancelled,
    SseError,
    HttpStatus,
    TurnComplete,
    TurnAborted,
    ProcessExit,
    CaptureGap,
    UnsupportedCodexBuild,
    ContentExpired,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum FlowDirection {
    ClientToServer,
    ServerToClient,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct UsageSummary {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub reasoning_tokens: u64,
    pub total_tokens: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ErrorRecord {
    pub error_id: Uuid,
    pub task_ref: String,
    pub attempt_id: Option<Uuid>,
    pub occurred_at_ms: TimestampMs,
    pub source: ErrorSource,
    pub wire_type: Option<String>,
    pub code: Option<String>,
    pub message: String,
    pub param: Option<String>,
    pub reason: Option<String>,
    pub http_status: Option<u16>,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CaptureGapRecord {
    pub gap_id: Uuid,
    pub task_ref: Option<String>,
    pub flow_id: String,
    pub direction: FlowDirection,
    pub occurred_at_ms: TimestampMs,
    pub start_seq: u64,
    pub end_seq: u64,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TaskSnapshot {
    pub task_ref: String,
    pub identity: TaskIdentity,
    pub codex: CodexTaskMetadata,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conversation_title: Option<String>,
    pub sequence: u64,
    pub phase: TaskPhase,
    pub terminal: Option<TerminalOutcome>,
    pub integrity: IntegrityState,
    pub model: Option<String>,
    pub attempt_count: u32,
    pub tool_names: Vec<String>,
    pub response_ids: Vec<String>,
    pub usage: UsageSummary,
    pub started_at_ms: TimestampMs,
    pub updated_at_ms: TimestampMs,
    pub completed_at_ms: Option<TimestampMs>,
    pub last_error: Option<ErrorRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttemptRecord {
    pub attempt_id: Uuid,
    pub task_ref: String,
    pub ordinal: u32,
    pub response_id: Option<String>,
    pub transport: String,
    pub status: AttemptStatus,
    pub http_status: Option<u16>,
    pub model: Option<String>,
    pub tool_names: Vec<String>,
    pub usage: UsageSummary,
    pub error: Option<ErrorRecord>,
    pub request_object_sha256: Option<String>,
    pub response_object_sha256: Option<String>,
    pub started_at_ms: TimestampMs,
    pub ended_at_ms: Option<TimestampMs>,
    pub awaiting_tool: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum TaskEventKind {
    TaskObserved,
    AttemptStarted,
    AttemptCompleted,
    AttemptFailed,
    AttemptIncomplete,
    AttemptCancelled,
    AttemptLost,
    AwaitingTool,
    Retrying,
    TerminalCompleted,
    TerminalFailed,
    TerminalAborted,
    TerminalTerminated,
    TerminalLost,
    CaptureGap,
    UnsupportedBuild,
    ProcessExit,
}

impl TaskEventKind {
    #[must_use]
    pub fn phase_hint(self) -> TaskPhase {
        match self {
            Self::AwaitingTool => TaskPhase::AwaitingTool,
            Self::AttemptFailed
            | Self::AttemptIncomplete
            | Self::AttemptCancelled
            | Self::AttemptLost
            | Self::Retrying => TaskPhase::Retrying,
            Self::TerminalCompleted
            | Self::TerminalFailed
            | Self::TerminalAborted
            | Self::TerminalTerminated
            | Self::TerminalLost
            | Self::ProcessExit => TaskPhase::Terminal,
            _ => TaskPhase::Running,
        }
    }

    #[must_use]
    pub fn terminal_hint(self) -> Option<TerminalOutcome> {
        match self {
            Self::TerminalCompleted => Some(TerminalOutcome::Completed),
            Self::TerminalFailed => Some(TerminalOutcome::Failed),
            Self::TerminalAborted => Some(TerminalOutcome::Aborted),
            Self::TerminalTerminated | Self::ProcessExit => Some(TerminalOutcome::Terminated),
            Self::TerminalLost => Some(TerminalOutcome::Lost),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TaskEvent {
    pub event_id: Uuid,
    pub task_ref: String,
    pub sequence: u64,
    pub occurred_at_ms: TimestampMs,
    pub kind: TaskEventKind,
    pub phase: TaskPhase,
    pub terminal: Option<TerminalOutcome>,
    pub attempt_id: Option<Uuid>,
    pub response_id: Option<String>,
    pub model: Option<String>,
    pub tool_names: Vec<String>,
    pub usage: UsageSummary,
    pub error: Option<ErrorRecord>,
    pub http_status: Option<u16>,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TaskUpload {
    pub snapshot: TaskSnapshot,
    pub attempts: Vec<AttemptRecord>,
    pub events: Vec<TaskEvent>,
    pub errors: Vec<ErrorRecord>,
    pub gaps: Vec<CaptureGapRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContentRequest {
    pub request_id: Uuid,
    pub client_id: String,
    pub task_ref: String,
    pub session_id: String,
    pub thread_id: String,
    pub created_at_ms: TimestampMs,
    pub expires_at_ms: Option<TimestampMs>,
    pub parts: Vec<ContentPart>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ContentPart {
    Request,
    Response,
    ToolInput,
    ToolOutput,
    ModelText,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContentRequestCommand {
    pub command_id: Uuid,
    pub request: ContentRequest,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContentUploadChunk {
    pub request_id: Uuid,
    pub chunk_index: u32,
    pub chunk_count: u32,
    pub object_sha256: String,
    pub payload_sha256: String,
    pub payload_zstd: Vec<u8>,
    pub is_last: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContentObjectManifest {
    pub request_id: Uuid,
    pub task_ref: String,
    pub session_id: String,
    pub thread_id: String,
    pub part: ContentPart,
    pub object_sha256: String,
    pub media_type: String,
    pub uncompressed_bytes: u64,
    pub compressed_bytes: u64,
    pub chunk_count: u32,
    pub created_at_ms: TimestampMs,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContentUploadResult {
    pub request_id: Uuid,
    pub status: ContentUploadStatus,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ContentUploadStatus {
    Stored,
    ContentExpired,
    Rejected,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TaskDetail {
    pub snapshot: TaskSnapshot,
    pub attempts: Vec<AttemptRecord>,
    pub events: Vec<TaskEvent>,
    pub errors: Vec<ErrorRecord>,
    pub gaps: Vec<CaptureGapRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientCommand {
    RequestContent(ContentRequestCommand),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommandPollResponse {
    pub server_time_ms: TimestampMs,
    pub commands: Vec<ClientCommand>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IngestAck {
    pub batch_id: Uuid,
    pub payload_sha256: String,
    pub accepted_tasks: u32,
    pub accepted_heartbeats: u32,
    pub duplicate: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct TaskListQuery {
    pub client_id: Option<String>,
    pub provider: Option<String>,
    pub session_id: Option<String>,
    pub phase: Option<TaskPhase>,
    pub terminal: Option<TerminalOutcome>,
    pub cursor: Option<String>,
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TaskListResponse {
    pub tasks: Vec<TaskSnapshot>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionDetail {
    pub client_id: String,
    pub provider: String,
    pub session_id: String,
    pub thread_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conversation_title: Option<String>,
    pub tasks: Vec<TaskSnapshot>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EventListResponse {
    pub events: Vec<TaskEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ErrorListResponse {
    pub errors: Vec<ErrorRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CaptureHealthResponse {
    pub client_id: String,
    pub instance_id: Uuid,
    pub observed_at_ms: TimestampMs,
    pub integrity: IntegrityState,
}
