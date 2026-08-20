use crate::{
    IntegrityState, TaskEvent, TaskEventKind, TaskPhase, TaskSnapshot, TerminalOutcome, Validate,
    ValidationError,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReduceOutcome {
    pub snapshot: TaskSnapshot,
    pub changed: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum ReduceError {
    #[error(transparent)]
    InvalidEvent(#[from] ValidationError),
    #[error("event task_ref {event_task_ref} did not match reducer task_ref {reducer_task_ref}")]
    TaskRefMismatch {
        event_task_ref: String,
        reducer_task_ref: String,
    },
    #[error(
        "event sequence {event_sequence} was not greater than current sequence {current_sequence}"
    )]
    NonMonotonicSequence {
        event_sequence: u64,
        current_sequence: u64,
    },
    #[error("event sequence {event_sequence} skipped expected sequence {expected_sequence}")]
    SequenceGap {
        event_sequence: u64,
        expected_sequence: u64,
    },
    #[error("event timestamp {event_timestamp} predates snapshot timestamp {snapshot_timestamp}")]
    TimestampRegression {
        event_timestamp: i64,
        snapshot_timestamp: i64,
    },
    #[error("task is already terminal with {existing:?}; incoming outcome was {incoming:?}")]
    AlreadyTerminal {
        existing: TerminalOutcome,
        incoming: Option<TerminalOutcome>,
    },
    #[error("phase transition from {from:?} to {to:?} is invalid")]
    InvalidPhaseTransition { from: TaskPhase, to: TaskPhase },
}

#[derive(Debug, Clone)]
pub struct TaskReducer {
    snapshot: TaskSnapshot,
}

impl TaskReducer {
    #[must_use]
    pub fn new(snapshot: TaskSnapshot) -> Self {
        Self { snapshot }
    }

    #[must_use]
    pub fn snapshot(&self) -> &TaskSnapshot {
        &self.snapshot
    }

    /// Applies one validated, consecutive event to the task projection.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid evidence, task mismatch, sequence or time
    /// regressions, invalid phase changes, or updates after a terminal event.
    pub fn apply(&mut self, event: &TaskEvent) -> Result<ReduceOutcome, ReduceError> {
        event.validate()?;
        if event.task_ref != self.snapshot.task_ref {
            return Err(ReduceError::TaskRefMismatch {
                event_task_ref: event.task_ref.clone(),
                reducer_task_ref: self.snapshot.task_ref.clone(),
            });
        }
        if event.sequence <= self.snapshot.sequence {
            return Err(ReduceError::NonMonotonicSequence {
                event_sequence: event.sequence,
                current_sequence: self.snapshot.sequence,
            });
        }
        let expected_sequence = self.snapshot.sequence + 1;
        if event.sequence != expected_sequence {
            return Err(ReduceError::SequenceGap {
                event_sequence: event.sequence,
                expected_sequence,
            });
        }
        if event.occurred_at_ms < self.snapshot.updated_at_ms {
            return Err(ReduceError::TimestampRegression {
                event_timestamp: event.occurred_at_ms,
                snapshot_timestamp: self.snapshot.updated_at_ms,
            });
        }
        if let Some(existing) = self.snapshot.terminal {
            return Err(ReduceError::AlreadyTerminal {
                existing,
                incoming: event.terminal,
            });
        }
        if !valid_phase_transition(self.snapshot.phase, event.phase) {
            return Err(ReduceError::InvalidPhaseTransition {
                from: self.snapshot.phase,
                to: event.phase,
            });
        }

        self.snapshot.sequence = event.sequence;
        self.snapshot.updated_at_ms = event.occurred_at_ms;
        self.snapshot.phase = event.phase;
        self.snapshot.terminal = event.terminal;
        self.snapshot.model = event.model.clone().or_else(|| self.snapshot.model.clone());
        if let Some(response_id) = &event.response_id
            && !self
                .snapshot
                .response_ids
                .iter()
                .any(|item| item == response_id)
        {
            self.snapshot.response_ids.push(response_id.clone());
        }
        for tool_name in &event.tool_names {
            if !self
                .snapshot
                .tool_names
                .iter()
                .any(|item| item == tool_name)
            {
                self.snapshot.tool_names.push(tool_name.clone());
            }
        }
        self.snapshot.usage = event.usage.clone();
        if let Some(error) = &event.error {
            self.snapshot.last_error = Some(error.clone());
        }

        match event.kind {
            TaskEventKind::AttemptStarted => {
                self.snapshot.attempt_count = self.snapshot.attempt_count.saturating_add(1);
            }
            TaskEventKind::CaptureGap => {
                self.snapshot.integrity = IntegrityState::Degraded;
            }
            TaskEventKind::UnsupportedBuild => {
                self.snapshot.integrity = IntegrityState::UnsupportedBuild;
            }
            TaskEventKind::TerminalLost => {
                self.snapshot.integrity = IntegrityState::Lost;
                self.snapshot.completed_at_ms = Some(event.occurred_at_ms);
            }
            kind if kind.terminal_hint().is_some() => {
                self.snapshot.completed_at_ms = Some(event.occurred_at_ms);
            }
            _ => {}
        }

        Ok(ReduceOutcome {
            snapshot: self.snapshot.clone(),
            changed: true,
        })
    }
}

fn valid_phase_transition(from: TaskPhase, to: TaskPhase) -> bool {
    match from {
        TaskPhase::Running => matches!(
            to,
            TaskPhase::Running
                | TaskPhase::AwaitingTool
                | TaskPhase::Retrying
                | TaskPhase::Terminal
        ),
        TaskPhase::AwaitingTool => matches!(
            to,
            TaskPhase::AwaitingTool
                | TaskPhase::Running
                | TaskPhase::Retrying
                | TaskPhase::Terminal
        ),
        TaskPhase::Retrying => matches!(
            to,
            TaskPhase::Retrying
                | TaskPhase::Running
                | TaskPhase::AwaitingTool
                | TaskPhase::Terminal
        ),
        TaskPhase::Terminal => false,
    }
}

impl From<TaskSnapshot> for TaskReducer {
    fn from(snapshot: TaskSnapshot) -> Self {
        Self::new(snapshot)
    }
}

impl From<TaskReducer> for TaskSnapshot {
    fn from(value: TaskReducer) -> Self {
        value.snapshot
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        CodexTaskMetadata, ErrorRecord, ErrorSource, IntegrityState, TaskEvent, TaskEventKind,
        TaskIdentity, TaskPhase, TaskSnapshot, TerminalOutcome, UsageSummary,
    };

    use super::{ReduceError, TaskReducer};

    fn snapshot() -> TaskSnapshot {
        TaskSnapshot {
            task_ref: "s:t:r".to_owned(),
            identity: TaskIdentity {
                provider: "openai".to_owned(),
                session_id: "s".to_owned(),
                thread_id: "t".to_owned(),
                turn_id: "r".to_owned(),
            },
            codex: CodexTaskMetadata {
                request_kind: "turn".to_owned(),
                parent_turn_id: None,
                root_turn_id: None,
            },
            conversation_title: None,
            sequence: 0,
            phase: TaskPhase::Running,
            terminal: None,
            integrity: IntegrityState::Complete,
            model: None,
            attempt_count: 0,
            tool_names: Vec::new(),
            response_ids: Vec::new(),
            usage: UsageSummary::default(),
            started_at_ms: 1,
            updated_at_ms: 1,
            completed_at_ms: None,
            last_error: None,
        }
    }

    #[test]
    fn reducer_applies_terminal_event() {
        let mut reducer = TaskReducer::new(snapshot());
        let error = ErrorRecord {
            error_id: uuid::Uuid::now_v7(),
            task_ref: "s:t:r".to_owned(),
            attempt_id: None,
            occurred_at_ms: 10,
            source: ErrorSource::TurnComplete,
            wire_type: None,
            code: Some("failed".to_owned()),
            message: "boom".to_owned(),
            param: None,
            reason: None,
            http_status: None,
            exit_code: None,
            signal: None,
        };
        let event = TaskEvent {
            event_id: uuid::Uuid::now_v7(),
            task_ref: "s:t:r".to_owned(),
            sequence: 1,
            occurred_at_ms: 10,
            kind: TaskEventKind::TerminalFailed,
            phase: TaskPhase::Terminal,
            terminal: Some(TerminalOutcome::Failed),
            attempt_id: None,
            response_id: Some("resp_1".to_owned()),
            model: Some("gpt-5".to_owned()),
            tool_names: vec!["shell".to_owned()],
            usage: UsageSummary {
                input_tokens: 1,
                output_tokens: 2,
                reasoning_tokens: 3,
                total_tokens: 6,
            },
            error: Some(error.clone()),
            http_status: None,
            exit_code: None,
            signal: None,
            note: None,
        };
        let result = reducer.apply(&event).expect("reduce");
        assert_eq!(result.snapshot.terminal, Some(TerminalOutcome::Failed));
        assert_eq!(result.snapshot.last_error, Some(error));
        assert_eq!(result.snapshot.response_ids, vec!["resp_1".to_owned()]);
        assert_eq!(result.snapshot.tool_names, vec!["shell".to_owned()]);
        assert_eq!(result.snapshot.completed_at_ms, Some(10));
    }

    #[test]
    fn reducer_rejects_reordered_and_gapped_sequences() {
        let mut reducer = TaskReducer::new(snapshot());
        let first = TaskEvent {
            event_id: uuid::Uuid::now_v7(),
            task_ref: "s:t:r".to_owned(),
            sequence: 1,
            occurred_at_ms: 2,
            kind: TaskEventKind::TaskObserved,
            phase: TaskPhase::Running,
            terminal: None,
            attempt_id: None,
            response_id: None,
            model: None,
            tool_names: Vec::new(),
            usage: UsageSummary::default(),
            error: None,
            http_status: None,
            exit_code: None,
            signal: None,
            note: None,
        };
        reducer.apply(&first).expect("first event");

        let duplicate_sequence = TaskEvent {
            event_id: uuid::Uuid::now_v7(),
            ..first.clone()
        };
        assert!(matches!(
            reducer.apply(&duplicate_sequence),
            Err(ReduceError::NonMonotonicSequence { .. })
        ));

        let gapped = TaskEvent {
            event_id: uuid::Uuid::now_v7(),
            sequence: 3,
            occurred_at_ms: 3,
            ..first
        };
        assert!(matches!(
            reducer.apply(&gapped),
            Err(ReduceError::SequenceGap {
                expected_sequence: 2,
                event_sequence: 3
            })
        ));
    }

    #[test]
    fn failed_attempt_does_not_end_task() {
        let mut reducer = TaskReducer::new(snapshot());
        let error = ErrorRecord {
            error_id: uuid::Uuid::now_v7(),
            task_ref: "s:t:r".to_owned(),
            attempt_id: Some(uuid::Uuid::now_v7()),
            occurred_at_ms: 2,
            source: ErrorSource::ResponseFailed,
            wire_type: Some("response.failed".to_owned()),
            code: Some("rate_limit".to_owned()),
            message: "retry".to_owned(),
            param: None,
            reason: None,
            http_status: None,
            exit_code: None,
            signal: None,
        };
        let event = TaskEvent {
            event_id: uuid::Uuid::now_v7(),
            task_ref: "s:t:r".to_owned(),
            sequence: 1,
            occurred_at_ms: 2,
            kind: TaskEventKind::AttemptFailed,
            phase: TaskPhase::Retrying,
            terminal: None,
            attempt_id: error.attempt_id,
            response_id: Some("resp_1".to_owned()),
            model: None,
            tool_names: Vec::new(),
            usage: UsageSummary::default(),
            error: Some(error),
            http_status: None,
            exit_code: None,
            signal: None,
            note: None,
        };
        let result = reducer.apply(&event).expect("failed attempt");
        assert_eq!(result.snapshot.phase, TaskPhase::Retrying);
        assert_eq!(result.snapshot.terminal, None);
        assert_eq!(result.snapshot.completed_at_ms, None);
    }

    #[test]
    fn terminal_conflict_is_rejected() {
        let mut reducer = TaskReducer::new(snapshot());
        let completed = TaskEvent {
            event_id: uuid::Uuid::now_v7(),
            task_ref: "s:t:r".to_owned(),
            sequence: 1,
            occurred_at_ms: 2,
            kind: TaskEventKind::TerminalCompleted,
            phase: TaskPhase::Terminal,
            terminal: Some(TerminalOutcome::Completed),
            attempt_id: None,
            response_id: None,
            model: None,
            tool_names: Vec::new(),
            usage: UsageSummary::default(),
            error: None,
            http_status: None,
            exit_code: None,
            signal: None,
            note: None,
        };
        reducer.apply(&completed).expect("completed");
        let conflicting = TaskEvent {
            event_id: uuid::Uuid::now_v7(),
            sequence: 2,
            occurred_at_ms: 3,
            ..completed
        };
        assert!(matches!(
            reducer.apply(&conflicting),
            Err(ReduceError::AlreadyTerminal {
                existing: TerminalOutcome::Completed,
                incoming: Some(TerminalOutcome::Completed)
            })
        ));
    }
}
