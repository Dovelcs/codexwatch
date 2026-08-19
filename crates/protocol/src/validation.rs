use std::collections::HashSet;

use crate::{
    AttemptRecord, AttemptStatus, CaptureGapRecord, ClientCommand, CommandPollResponse,
    ContentObjectManifest, ContentRequest, ContentUploadChunk, ErrorRecord, ErrorSource, Heartbeat,
    IngestBatch, MAX_CONTENT_CHUNK_BYTES, MAX_ERROR_MESSAGE_BYTES, PROTOCOL_VERSION, TaskEvent,
    TaskEventKind, TaskPhase, TaskSnapshot, TaskUpload, TerminalOutcome, sha256_hex,
};

const MAX_ID_BYTES: usize = 512;
const MAX_SHORT_TEXT_BYTES: usize = 4096;
const MAX_BATCH_TASKS: usize = 1024;
const MAX_BATCH_HEARTBEATS: usize = 1024;

pub trait Validate {
    /// Checks semantic invariants that serde alone cannot express.
    ///
    /// # Errors
    ///
    /// Returns the first field-level contract violation.
    fn validate(&self) -> Result<(), ValidationError>;
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{path}: {message}")]
pub struct ValidationError {
    pub path: String,
    pub message: String,
}

impl ValidationError {
    #[must_use]
    pub fn new(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            message: message.into(),
        }
    }

    fn under(self, prefix: impl AsRef<str>) -> Self {
        Self::new(format!("{}.{}", prefix.as_ref(), self.path), self.message)
    }
}

#[must_use]
pub fn is_uuid_v7(value: &uuid::Uuid) -> bool {
    value.get_version_num() == 7
}

fn validate_uuid_v7(path: &str, value: &uuid::Uuid) -> Result<(), ValidationError> {
    if is_uuid_v7(value) {
        Ok(())
    } else {
        Err(ValidationError::new(path, "must be a UUIDv7"))
    }
}

fn validate_text(path: &str, value: &str, max: usize) -> Result<(), ValidationError> {
    if value.trim().is_empty() {
        return Err(ValidationError::new(path, "must not be empty"));
    }
    if value.len() > max {
        return Err(ValidationError::new(
            path,
            format!("must not exceed {max} bytes"),
        ));
    }
    Ok(())
}

fn validate_sha256(path: &str, value: &str) -> Result<(), ValidationError> {
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(ValidationError::new(
            path,
            "must contain exactly 64 hexadecimal characters",
        ))
    }
}

impl Validate for ErrorRecord {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_uuid_v7("error_id", &self.error_id)?;
        validate_text("task_ref", &self.task_ref, MAX_ID_BYTES)?;
        validate_text("message", &self.message, MAX_ERROR_MESSAGE_BYTES)?;
        if let Some(wire_type) = &self.wire_type {
            validate_text("wire_type", wire_type, MAX_SHORT_TEXT_BYTES)?;
        }
        if let Some(code) = &self.code {
            validate_text("code", code, MAX_SHORT_TEXT_BYTES)?;
        }
        if let Some(param) = &self.param {
            validate_text("param", param, MAX_SHORT_TEXT_BYTES)?;
        }
        if let Some(reason) = &self.reason {
            validate_text("reason", reason, MAX_ERROR_MESSAGE_BYTES)?;
        }
        if let Some(status) = self.http_status
            && !(100..=599).contains(&status)
        {
            return Err(ValidationError::new(
                "http_status",
                "must be between 100 and 599",
            ));
        }

        let source_fields_valid = match self.source {
            ErrorSource::ResponseFailed
            | ErrorSource::ResponseCancelled
            | ErrorSource::SseError => self.wire_type.is_some(),
            ErrorSource::ResponseIncomplete => self.reason.is_some(),
            ErrorSource::HttpStatus => self.http_status.is_some(),
            ErrorSource::TurnComplete => self.http_status.is_none(),
            ErrorSource::TurnAborted | ErrorSource::CaptureGap | ErrorSource::ContentExpired => {
                self.reason.is_some()
            }
            ErrorSource::ProcessExit => self.exit_code.is_some() || self.signal.is_some(),
            ErrorSource::UnsupportedCodexBuild => self.code.as_ref().is_some_and(|digest| {
                digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
            }),
        };
        if !source_fields_valid {
            return Err(ValidationError::new(
                "source",
                "required structured fields are missing for this error source",
            ));
        }
        Ok(())
    }
}

impl Validate for TaskSnapshot {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_text("task_ref", &self.task_ref, MAX_ID_BYTES)?;
        validate_text("identity.provider", &self.identity.provider, 64)?;
        validate_text(
            "identity.session_id",
            &self.identity.session_id,
            MAX_ID_BYTES,
        )?;
        validate_text("identity.thread_id", &self.identity.thread_id, MAX_ID_BYTES)?;
        validate_text("identity.turn_id", &self.identity.turn_id, MAX_ID_BYTES)?;
        if self.identity.task_ref() != self.task_ref {
            return Err(ValidationError::new(
                "task_ref",
                "must match session_id:thread_id:turn_id",
            ));
        }
        if self.codex.request_kind != "turn" {
            return Err(ValidationError::new(
                "codex.request_kind",
                "only request_kind=turn may create a task",
            ));
        }
        if self.updated_at_ms < self.started_at_ms {
            return Err(ValidationError::new(
                "updated_at_ms",
                "must not predate started_at_ms",
            ));
        }
        match self.phase {
            TaskPhase::Terminal => {
                if self.terminal.is_none() || self.completed_at_ms.is_none() {
                    return Err(ValidationError::new(
                        "terminal",
                        "terminal phase requires outcome and completed_at_ms",
                    ));
                }
            }
            TaskPhase::Running | TaskPhase::AwaitingTool | TaskPhase::Retrying => {
                if self.terminal.is_some() || self.completed_at_ms.is_some() {
                    return Err(ValidationError::new(
                        "terminal",
                        "non-terminal phase forbids outcome and completed_at_ms",
                    ));
                }
            }
        }
        if let Some(error) = &self.last_error {
            error
                .validate()
                .map_err(|error| error.under("last_error"))?;
        }
        Ok(())
    }
}

impl Validate for AttemptRecord {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_uuid_v7("attempt_id", &self.attempt_id)?;
        validate_text("task_ref", &self.task_ref, MAX_ID_BYTES)?;
        validate_text("transport", &self.transport, 64)?;
        if self.ordinal == 0 {
            return Err(ValidationError::new("ordinal", "must be greater than zero"));
        }
        if self
            .ended_at_ms
            .is_some_and(|ended| ended < self.started_at_ms)
        {
            return Err(ValidationError::new(
                "ended_at_ms",
                "must not predate started_at_ms",
            ));
        }
        for (path, digest) in [
            ("request_object_sha256", &self.request_object_sha256),
            ("response_object_sha256", &self.response_object_sha256),
        ] {
            if let Some(digest) = digest {
                validate_sha256(path, digest)?;
            }
        }
        if let Some(error) = &self.error {
            error.validate().map_err(|error| error.under("error"))?;
        }

        let valid_terminal_fields = match self.status {
            AttemptStatus::Running => self.ended_at_ms.is_none() && self.error.is_none(),
            AttemptStatus::Completed => self.ended_at_ms.is_some() && self.error.is_none(),
            AttemptStatus::Failed => {
                self.ended_at_ms.is_some()
                    && self.error.as_ref().is_some_and(|error| {
                        matches!(
                            error.source,
                            ErrorSource::ResponseFailed
                                | ErrorSource::SseError
                                | ErrorSource::HttpStatus
                        )
                    })
            }
            AttemptStatus::Incomplete => {
                self.ended_at_ms.is_some()
                    && self
                        .error
                        .as_ref()
                        .is_some_and(|error| error.source == ErrorSource::ResponseIncomplete)
            }
            AttemptStatus::Cancelled => {
                self.ended_at_ms.is_some()
                    && self
                        .error
                        .as_ref()
                        .is_some_and(|error| error.source == ErrorSource::ResponseCancelled)
            }
            AttemptStatus::TransportLost => {
                self.ended_at_ms.is_some()
                    && self
                        .error
                        .as_ref()
                        .is_some_and(|error| error.source == ErrorSource::CaptureGap)
            }
        };
        if !valid_terminal_fields {
            return Err(ValidationError::new(
                "status",
                "attempt status, terminal time, and error evidence are inconsistent",
            ));
        }
        Ok(())
    }
}

impl Validate for TaskEvent {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_uuid_v7("event_id", &self.event_id)?;
        validate_text("task_ref", &self.task_ref, MAX_ID_BYTES)?;
        if self.sequence == 0 {
            return Err(ValidationError::new(
                "sequence",
                "must be greater than zero",
            ));
        }
        if let Some(error) = &self.error {
            error.validate().map_err(|error| error.under("error"))?;
            if error.task_ref != self.task_ref {
                return Err(ValidationError::new(
                    "error.task_ref",
                    "must match event task_ref",
                ));
            }
        }

        validate_event_projection(self)?;
        validate_event_evidence(self)
    }
}

fn validate_event_projection(event: &TaskEvent) -> Result<(), ValidationError> {
    let expected_terminal = match event.kind {
        TaskEventKind::TerminalCompleted => Some(TerminalOutcome::Completed),
        TaskEventKind::TerminalFailed => Some(TerminalOutcome::Failed),
        TaskEventKind::TerminalAborted => Some(TerminalOutcome::Aborted),
        TaskEventKind::TerminalTerminated | TaskEventKind::ProcessExit => {
            Some(TerminalOutcome::Terminated)
        }
        TaskEventKind::TerminalLost => Some(TerminalOutcome::Lost),
        _ => None,
    };
    if event.terminal != expected_terminal
        || (expected_terminal.is_some()) != (event.phase == TaskPhase::Terminal)
    {
        return Err(ValidationError::new(
            "terminal",
            "phase and outcome must match the event kind",
        ));
    }

    let phase_valid = match event.kind {
        TaskEventKind::TaskObserved | TaskEventKind::AttemptStarted => {
            event.phase == TaskPhase::Running
        }
        TaskEventKind::AttemptCompleted => {
            matches!(event.phase, TaskPhase::Running | TaskPhase::AwaitingTool)
        }
        TaskEventKind::AttemptFailed
        | TaskEventKind::AttemptIncomplete
        | TaskEventKind::AttemptCancelled
        | TaskEventKind::AttemptLost
        | TaskEventKind::Retrying => event.phase == TaskPhase::Retrying,
        TaskEventKind::AwaitingTool => event.phase == TaskPhase::AwaitingTool,
        TaskEventKind::CaptureGap | TaskEventKind::UnsupportedBuild => {
            event.phase != TaskPhase::Terminal
        }
        TaskEventKind::TerminalCompleted
        | TaskEventKind::TerminalFailed
        | TaskEventKind::TerminalAborted
        | TaskEventKind::TerminalTerminated
        | TaskEventKind::TerminalLost
        | TaskEventKind::ProcessExit => event.phase == TaskPhase::Terminal,
    };
    if !phase_valid {
        return Err(ValidationError::new(
            "phase",
            "is not valid for the event kind",
        ));
    }
    Ok(())
}

fn validate_event_evidence(event: &TaskEvent) -> Result<(), ValidationError> {
    let evidence_valid = match event.kind {
        TaskEventKind::TerminalCompleted => event.error.is_none(),
        TaskEventKind::TerminalFailed => event
            .error
            .as_ref()
            .is_some_and(|error| error.source == ErrorSource::TurnComplete),
        TaskEventKind::TerminalAborted => event
            .error
            .as_ref()
            .is_some_and(|error| error.source == ErrorSource::TurnAborted),
        TaskEventKind::TerminalTerminated | TaskEventKind::ProcessExit => event
            .error
            .as_ref()
            .is_some_and(|error| error.source == ErrorSource::ProcessExit),
        TaskEventKind::TerminalLost => event
            .error
            .as_ref()
            .is_some_and(|error| error.source == ErrorSource::CaptureGap),
        TaskEventKind::AttemptFailed => event.error.as_ref().is_some_and(|error| {
            matches!(
                error.source,
                ErrorSource::ResponseFailed | ErrorSource::SseError | ErrorSource::HttpStatus
            )
        }),
        TaskEventKind::AttemptIncomplete => event
            .error
            .as_ref()
            .is_some_and(|error| error.source == ErrorSource::ResponseIncomplete),
        TaskEventKind::AttemptCancelled => event
            .error
            .as_ref()
            .is_some_and(|error| error.source == ErrorSource::ResponseCancelled),
        TaskEventKind::AttemptLost => event
            .error
            .as_ref()
            .is_some_and(|error| error.source == ErrorSource::CaptureGap),
        TaskEventKind::UnsupportedBuild => event
            .error
            .as_ref()
            .is_some_and(|error| error.source == ErrorSource::UnsupportedCodexBuild),
        TaskEventKind::TaskObserved
        | TaskEventKind::AttemptStarted
        | TaskEventKind::AttemptCompleted
        | TaskEventKind::AwaitingTool
        | TaskEventKind::Retrying
        | TaskEventKind::CaptureGap => true,
    };
    if !evidence_valid {
        return Err(ValidationError::new(
            "error",
            "structured evidence does not match the event kind",
        ));
    }
    Ok(())
}

impl Validate for CaptureGapRecord {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_uuid_v7("gap_id", &self.gap_id)?;
        validate_text("flow_id", &self.flow_id, MAX_ID_BYTES)?;
        validate_text("reason", &self.reason, MAX_ERROR_MESSAGE_BYTES)?;
        if self.end_seq < self.start_seq {
            return Err(ValidationError::new(
                "end_seq",
                "must not be smaller than start_seq",
            ));
        }
        Ok(())
    }
}

impl Validate for TaskUpload {
    fn validate(&self) -> Result<(), ValidationError> {
        self.snapshot
            .validate()
            .map_err(|error| error.under("snapshot"))?;
        let task_ref = &self.snapshot.task_ref;
        let mut attempt_ids = HashSet::new();
        let mut ordinals = HashSet::new();
        for (index, attempt) in self.attempts.iter().enumerate() {
            attempt
                .validate()
                .map_err(|error| error.under(format!("attempts[{index}]")))?;
            if &attempt.task_ref != task_ref {
                return Err(ValidationError::new(
                    format!("attempts[{index}].task_ref"),
                    "must match snapshot task_ref",
                ));
            }
            if !attempt_ids.insert(attempt.attempt_id) || !ordinals.insert(attempt.ordinal) {
                return Err(ValidationError::new(
                    format!("attempts[{index}]"),
                    "attempt_id and ordinal must be unique",
                ));
            }
        }

        let mut previous_sequence = None;
        let mut terminal_seen = false;
        for (index, event) in self.events.iter().enumerate() {
            event
                .validate()
                .map_err(|error| error.under(format!("events[{index}]")))?;
            if &event.task_ref != task_ref {
                return Err(ValidationError::new(
                    format!("events[{index}].task_ref"),
                    "must match snapshot task_ref",
                ));
            }
            if terminal_seen {
                return Err(ValidationError::new(
                    format!("events[{index}]"),
                    "no event may follow a terminal task event",
                ));
            }
            if let Some(previous) = previous_sequence
                && event.sequence <= previous
            {
                return Err(ValidationError::new(
                    format!("events[{index}].sequence"),
                    "events must be in strictly increasing sequence order",
                ));
            }
            previous_sequence = Some(event.sequence);
            terminal_seen = event.terminal.is_some();
        }
        if previous_sequence.is_some_and(|sequence| sequence > self.snapshot.sequence) {
            return Err(ValidationError::new(
                "snapshot.sequence",
                "must not predate an uploaded event sequence",
            ));
        }

        let mut error_ids = HashSet::new();
        for (index, error) in self.errors.iter().enumerate() {
            error
                .validate()
                .map_err(|error| error.under(format!("errors[{index}]")))?;
            if &error.task_ref != task_ref || !error_ids.insert(error.error_id) {
                return Err(ValidationError::new(
                    format!("errors[{index}]"),
                    "task_ref must match and error_id must be unique",
                ));
            }
        }
        for (index, gap) in self.gaps.iter().enumerate() {
            gap.validate()
                .map_err(|error| error.under(format!("gaps[{index}]")))?;
            if gap.task_ref.as_ref().is_some_and(|value| value != task_ref) {
                return Err(ValidationError::new(
                    format!("gaps[{index}].task_ref"),
                    "must match snapshot task_ref",
                ));
            }
        }
        Ok(())
    }
}

impl Validate for Heartbeat {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_uuid_v7("heartbeat_id", &self.heartbeat_id)?;
        validate_uuid_v7("instance_id", &self.instance_id)?;
        validate_text("client_id", &self.client_id, MAX_ID_BYTES)?;
        if let Some(note) = &self.note {
            validate_text("note", note, MAX_ERROR_MESSAGE_BYTES)?;
        }
        Ok(())
    }
}

impl Validate for IngestBatch {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.version != PROTOCOL_VERSION {
            return Err(ValidationError::new(
                "version",
                format!("must equal {PROTOCOL_VERSION}"),
            ));
        }
        validate_uuid_v7("batch_id", &self.batch_id)?;
        validate_uuid_v7("client.instance_id", &self.client.instance_id)?;
        validate_text("client.client_id", &self.client.client_id, MAX_ID_BYTES)?;
        validate_text(
            "client.hostname",
            &self.client.hostname,
            MAX_SHORT_TEXT_BYTES,
        )?;
        validate_text(
            "client.platform",
            &self.client.platform,
            MAX_SHORT_TEXT_BYTES,
        )?;
        validate_text(
            "client.codex_version",
            &self.client.codex_version,
            MAX_SHORT_TEXT_BYTES,
        )?;
        if self.tasks.len() > MAX_BATCH_TASKS || self.heartbeats.len() > MAX_BATCH_HEARTBEATS {
            return Err(ValidationError::new(
                "tasks",
                "batch contains too many tasks or heartbeats",
            ));
        }
        let mut task_refs = HashSet::new();
        for (index, task) in self.tasks.iter().enumerate() {
            task.validate()
                .map_err(|error| error.under(format!("tasks[{index}]")))?;
            if !task_refs.insert(&task.snapshot.task_ref) {
                return Err(ValidationError::new(
                    format!("tasks[{index}].snapshot.task_ref"),
                    "must be unique within a batch",
                ));
            }
        }
        for (index, heartbeat) in self.heartbeats.iter().enumerate() {
            heartbeat
                .validate()
                .map_err(|error| error.under(format!("heartbeats[{index}]")))?;
            if heartbeat.client_id != self.client.client_id
                || heartbeat.instance_id != self.client.instance_id
            {
                return Err(ValidationError::new(
                    format!("heartbeats[{index}]"),
                    "client identity must match the batch envelope",
                ));
            }
        }
        Ok(())
    }
}

impl Validate for ContentRequest {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_uuid_v7("request_id", &self.request_id)?;
        validate_text("client_id", &self.client_id, MAX_ID_BYTES)?;
        validate_text("task_ref", &self.task_ref, MAX_ID_BYTES)?;
        validate_text("session_id", &self.session_id, MAX_ID_BYTES)?;
        validate_text("thread_id", &self.thread_id, MAX_ID_BYTES)?;
        if self.parts.is_empty() {
            return Err(ValidationError::new("parts", "must not be empty"));
        }
        if self
            .expires_at_ms
            .is_some_and(|expires| expires <= self.created_at_ms)
        {
            return Err(ValidationError::new(
                "expires_at_ms",
                "must be later than created_at_ms",
            ));
        }
        Ok(())
    }
}

impl Validate for ClientCommand {
    fn validate(&self) -> Result<(), ValidationError> {
        match self {
            Self::RequestContent(command) => {
                validate_uuid_v7("command_id", &command.command_id)?;
                command.request.validate()
            }
        }
    }
}

impl Validate for CommandPollResponse {
    fn validate(&self) -> Result<(), ValidationError> {
        for (index, command) in self.commands.iter().enumerate() {
            command
                .validate()
                .map_err(|error| error.under(format!("commands[{index}]")))?;
        }
        Ok(())
    }
}

impl Validate for ContentObjectManifest {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_uuid_v7("request_id", &self.request_id)?;
        validate_text("task_ref", &self.task_ref, MAX_ID_BYTES)?;
        validate_text("session_id", &self.session_id, MAX_ID_BYTES)?;
        validate_text("thread_id", &self.thread_id, MAX_ID_BYTES)?;
        validate_sha256("object_sha256", &self.object_sha256)?;
        validate_text("media_type", &self.media_type, MAX_SHORT_TEXT_BYTES)?;
        if self.chunk_count == 0 {
            return Err(ValidationError::new(
                "chunk_count",
                "must be greater than zero",
            ));
        }
        Ok(())
    }
}

impl Validate for ContentUploadChunk {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_uuid_v7("request_id", &self.request_id)?;
        validate_sha256("object_sha256", &self.object_sha256)?;
        validate_sha256("payload_sha256", &self.payload_sha256)?;
        if self.chunk_count == 0 || self.chunk_index >= self.chunk_count {
            return Err(ValidationError::new(
                "chunk_index",
                "must be smaller than a non-zero chunk_count",
            ));
        }
        if self.is_last != (self.chunk_index + 1 == self.chunk_count) {
            return Err(ValidationError::new(
                "is_last",
                "must identify exactly the final chunk",
            ));
        }
        if self.payload_zstd.len() > MAX_CONTENT_CHUNK_BYTES {
            return Err(ValidationError::new(
                "payload_zstd",
                format!("must not exceed {MAX_CONTENT_CHUNK_BYTES} bytes"),
            ));
        }
        if sha256_hex(&self.payload_zstd) != self.payload_sha256.to_ascii_lowercase() {
            return Err(ValidationError::new(
                "payload_sha256",
                "must match payload_zstd",
            ));
        }
        Ok(())
    }
}
