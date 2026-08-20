use std::{
    collections::{BTreeSet, HashMap},
    str::FromStr,
    sync::Arc,
};

use anyhow::{Result, bail};
use codexwatch_protocol::{
    self as wire, AttemptRecord, CaptureGapRecord, ClientCommand, ClientInstance,
    CommandPollResponse, ContentObjectManifest, ContentPart, ContentRequestCommand,
    ContentUploadResult, ContentUploadStatus, ErrorRecord, ErrorSource, FlowDirection, Heartbeat,
    IngestAck, IngestBatch, IntegrityState, TaskEvent, TaskEventKind, TaskIdentity, TaskSnapshot,
    TaskUpload, TerminalOutcome, UsageSummary, encode_batch,
};
use serde::{Deserialize, Serialize};
use sqlx::{
    Row, SqlitePool,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions},
};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::{
    blob::{BlobStore, StoredBlob, StoredContentInput},
    config::ClientConfig,
    model::{
        AttemptStatus, AttemptSummary, CaptureGapSummary, Completeness, HeartbeatSummary,
        ProcessSummary, SessionSummary, StructuredError, SummaryRecord, TaskKey, TaskOutcome,
        TaskPhase, TaskSummary, TaskTransition, TokenUsage, TransitionCause,
    },
};

pub const OUTBOX_HARD_CAP_BYTES: i64 = 1024 * 1024 * 1024;
pub const OUTBOX_PRIORITY_RESERVE_BYTES: i64 = 64 * 1024 * 1024;
const ACK_RETENTION_DAYS: i64 = 400;

#[derive(Debug, Clone)]
pub struct ClientStore {
    pool: SqlitePool,
    blob_store: Arc<BlobStore>,
    client: ClientInstance,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PersistOutcome {
    pub enqueued_batches: usize,
    pub stored_contents: usize,
    pub duplicate_records: usize,
}

#[derive(Debug, Clone)]
pub struct PendingBatch {
    pub batch_id: Uuid,
    pub payload_sha256: String,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HealthSnapshot {
    pub outbox_batches: u64,
    pub outbox_bytes: u64,
    pub pending_commands: u64,
    pub active_tasks: u64,
    pub active_flows: u64,
    pub raw_objects: u64,
}

#[derive(Debug, Clone)]
pub struct TaskCursor {
    pub sequence: u64,
    pub conversation_title: Option<String>,
    pub attempt_count: u32,
    pub phase: TaskPhase,
    pub outcome: Option<TaskOutcome>,
    pub started_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub completeness: Completeness,
    pub model: Option<String>,
    pub tool_names: Vec<String>,
    pub response_ids: Vec<String>,
    pub usage: TokenUsage,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CommandStatus {
    Pending,
    Running,
    Failed,
    Completed,
}

#[derive(Debug, Clone)]
pub struct StoredCommand {
    pub command: ClientCommand,
    pub status: CommandStatus,
    pub attempt_count: u32,
}

#[derive(Debug, Clone)]
pub struct UploadWork {
    pub command_id: Uuid,
    pub request_id: Uuid,
    pub manifests: Vec<ContentObjectManifest>,
}

#[derive(Debug, Clone)]
pub enum UploadPreparation {
    Ready(UploadWork),
    Expired {
        command_id: Uuid,
        result: ContentUploadResult,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedError {
    error: StructuredError,
}

#[derive(Debug, Default)]
struct TaskAccumulator {
    attempts: Vec<AttemptRecord>,
    events: Vec<TaskEvent>,
    errors: Vec<ErrorRecord>,
    gaps: Vec<CaptureGapRecord>,
}

impl ClientStore {
    pub async fn open(config: &ClientConfig) -> Result<Self> {
        config.ensure_paths()?;
        let options = SqliteConnectOptions::from_str(&config.database_url())?
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await?;
        let hostname = std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string());
        let client = ClientInstance {
            client_id: config.client_id.clone(),
            instance_id: config.client_instance_id,
            hostname,
            platform: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
            codex_version: config.client_version.clone(),
            started_at_ms: now_ms(),
        };
        let store = Self {
            pool,
            blob_store: Arc::new(BlobStore::new(config.blob_dir.clone())),
            client,
        };
        store.migrate().await?;
        Ok(store)
    }

    pub fn blob_store(&self) -> &BlobStore {
        self.blob_store.as_ref()
    }

    pub async fn persist_ingress(
        &self,
        records: Vec<SummaryRecord>,
        contents: Vec<StoredContentInput>,
    ) -> Result<PersistOutcome> {
        let records: Vec<_> = records.into_iter().map(normalize_record).collect();
        let mut tx = self.pool.begin().await?;
        let mut accepted = Vec::new();
        let mut duplicate_records = 0usize;

        for record in &records {
            if self.apply_record_tx(&mut tx, record).await? {
                accepted.push(record.clone());
            } else {
                duplicate_records += 1;
            }
        }

        let mut stored_contents = 0usize;
        for content in contents {
            let stored = self.blob_store.store(&content)?;
            self.store_raw_object_tx(&mut tx, &stored).await?;
            stored_contents += 1;
        }

        let enqueued_batches = self.enqueue_records_tx(&mut tx, accepted).await?;
        tx.commit().await?;
        Ok(PersistOutcome {
            enqueued_batches,
            stored_contents,
            duplicate_records,
        })
    }

    pub async fn next_due_batch(&self, now: OffsetDateTime) -> Result<Option<PendingBatch>> {
        let row = sqlx::query(
            "SELECT batch_id, payload_sha256, body FROM outbox WHERE next_attempt_at <= ? ORDER BY created_at LIMIT 1",
        )
        .bind(ts(now))
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| {
            Ok(PendingBatch {
                batch_id: Uuid::parse_str(&row.try_get::<String, _>("batch_id")?)?,
                payload_sha256: row.try_get("payload_sha256")?,
                body: row.try_get("body")?,
            })
        })
        .transpose()
    }

    pub async fn mark_batch_acked(&self, ack: &IngestAck) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "INSERT OR REPLACE INTO acked_batches(batch_id, payload_sha256, acked_at) VALUES(?, ?, ?)",
        )
        .bind(ack.batch_id.to_string())
        .bind(&ack.payload_sha256)
        .bind(now_ms())
        .execute(&mut *tx)
        .await?;
        sqlx::query("DELETE FROM outbox WHERE batch_id = ? AND payload_sha256 = ?")
            .bind(ack.batch_id.to_string())
            .bind(&ack.payload_sha256)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn mark_batch_retry(&self, batch_id: Uuid, error: &str) -> Result<()> {
        let attempt_count: i64 =
            sqlx::query_scalar("SELECT attempt_count FROM outbox WHERE batch_id = ?")
                .bind(batch_id.to_string())
                .fetch_one(&self.pool)
                .await?;
        let next_attempt = OffsetDateTime::now_utc() + backoff_delay(attempt_count as u32);
        sqlx::query(
            "UPDATE outbox SET attempt_count = attempt_count + 1, next_attempt_at = ?, last_error = ? WHERE batch_id = ?",
        )
        .bind(ts(next_attempt))
        .bind(truncate_message(error))
        .bind(batch_id.to_string())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn save_commands(&self, response: &CommandPollResponse) -> Result<()> {
        for command in &response.commands {
            let (command_id, expires_at_ms) = command_meta(command)?;
            sqlx::query(
                "INSERT INTO commands(command_id, expires_at, status, payload_json, attempt_count, next_attempt_at) \
                 VALUES(?, ?, ?, ?, 0, ?) ON CONFLICT(command_id) DO NOTHING",
            )
            .bind(command_id.to_string())
            .bind(
                expires_at_ms.unwrap_or(
                    now_ms() + Duration::days(7).whole_milliseconds() as i64,
                ),
            )
            .bind(serde_json::to_string(&CommandStatus::Pending)?)
            .bind(serde_json::to_string(command)?)
            .bind(now_ms())
            .execute(&self.pool)
            .await?;
        }
        Ok(())
    }

    pub async fn next_due_command(&self, now: OffsetDateTime) -> Result<Option<StoredCommand>> {
        let row = sqlx::query(
            "SELECT payload_json, status, attempt_count FROM commands WHERE status IN (?, ?, ?) AND next_attempt_at <= ? ORDER BY rowid LIMIT 1",
        )
        .bind(serde_json::to_string(&CommandStatus::Pending)?)
        .bind(serde_json::to_string(&CommandStatus::Failed)?)
        .bind(serde_json::to_string(&CommandStatus::Running)?)
        .bind(ts(now))
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| {
            Ok(StoredCommand {
                command: serde_json::from_str(&row.try_get::<String, _>("payload_json")?)?,
                status: serde_json::from_str(&row.try_get::<String, _>("status")?)?,
                attempt_count: row.try_get::<i64, _>("attempt_count")? as u32,
            })
        })
        .transpose()
    }

    pub async fn prepare_upload(&self, command: &ClientCommand) -> Result<UploadPreparation> {
        let (command_id, request) = match command {
            ClientCommand::RequestContent(content) => (content.command_id, &content.request),
        };
        if request
            .expires_at_ms
            .is_some_and(|expires_at_ms| expires_at_ms <= now_ms())
        {
            return Ok(UploadPreparation::Expired {
                command_id,
                result: ContentUploadResult {
                    request_id: request.request_id,
                    status: ContentUploadStatus::ContentExpired,
                    note: Some("content request expired".into()),
                },
            });
        }

        let mut manifests = Vec::new();
        let mut tx = self.pool.begin().await?;
        for part in &request.parts {
            let row = sqlx::query(
                "SELECT object_sha256, media_type, uncompressed_bytes, compressed_bytes, chunk_count, created_at, expires_at \
                 FROM raw_objects WHERE task_ref = ? AND part = ? ORDER BY created_at DESC LIMIT 1",
            )
            .bind(&request.task_ref)
            .bind(content_part_name(*part))
            .fetch_optional(&mut *tx)
            .await?;
            let Some(row) = row else {
                return Ok(UploadPreparation::Expired {
                    command_id,
                    result: ContentUploadResult {
                        request_id: request.request_id,
                        status: ContentUploadStatus::ContentExpired,
                        note: Some(format!(
                            "missing local content for part {}",
                            content_part_name(*part)
                        )),
                    },
                });
            };
            let expires_at = row.try_get::<i64, _>("expires_at")?;
            if expires_at <= now_ms() {
                return Ok(UploadPreparation::Expired {
                    command_id,
                    result: ContentUploadResult {
                        request_id: request.request_id,
                        status: ContentUploadStatus::ContentExpired,
                        note: Some(format!(
                            "expired local content for part {}",
                            content_part_name(*part)
                        )),
                    },
                });
            }
            manifests.push(ContentObjectManifest {
                request_id: request.request_id,
                task_ref: request.task_ref.clone(),
                session_id: request.session_id.clone(),
                thread_id: request.thread_id.clone(),
                part: *part,
                object_sha256: row.try_get("object_sha256")?,
                media_type: row.try_get("media_type")?,
                uncompressed_bytes: row.try_get::<i64, _>("uncompressed_bytes")? as u64,
                compressed_bytes: row.try_get::<i64, _>("compressed_bytes")? as u64,
                chunk_count: row.try_get::<i64, _>("chunk_count")? as u32,
                created_at_ms: row.try_get("created_at")?,
            });
        }
        sqlx::query("UPDATE raw_objects SET pinned_by_command_id = ? WHERE task_ref = ?")
            .bind(command_id.to_string())
            .bind(&request.task_ref)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "UPDATE commands SET status = ?, attempt_count = attempt_count + 1, next_attempt_at = ? WHERE command_id = ?",
        )
        .bind(serde_json::to_string(&CommandStatus::Running)?)
        .bind(now_ms())
        .bind(command_id.to_string())
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(UploadPreparation::Ready(UploadWork {
            command_id,
            request_id: request.request_id,
            manifests,
        }))
    }

    pub async fn complete_command(
        &self,
        command_id: Uuid,
        result: &ContentUploadResult,
        keep_pinned: bool,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "UPDATE commands SET status = ?, result_json = ?, completed_at = ?, next_attempt_at = ? WHERE command_id = ?",
        )
        .bind(serde_json::to_string(&CommandStatus::Completed)?)
        .bind(serde_json::to_string(result)?)
        .bind(now_ms())
        .bind(now_ms())
        .bind(command_id.to_string())
        .execute(&mut *tx)
        .await?;
        if !keep_pinned {
            sqlx::query(
                "UPDATE raw_objects SET pinned_by_command_id = NULL WHERE pinned_by_command_id = ?",
            )
            .bind(command_id.to_string())
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn fail_command(
        &self,
        command_id: Uuid,
        error: &str,
        keep_pinned: bool,
    ) -> Result<()> {
        let attempt_count: i64 =
            sqlx::query_scalar("SELECT attempt_count FROM commands WHERE command_id = ?")
                .bind(command_id.to_string())
                .fetch_one(&self.pool)
                .await?;
        let next_attempt = OffsetDateTime::now_utc() + backoff_delay(attempt_count as u32);
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "UPDATE commands SET status = ?, next_attempt_at = ?, error_json = ? WHERE command_id = ?",
        )
        .bind(serde_json::to_string(&CommandStatus::Failed)?)
        .bind(ts(next_attempt))
        .bind(truncate_message(error))
        .bind(command_id.to_string())
        .execute(&mut *tx)
        .await?;
        if !keep_pinned {
            sqlx::query(
                "UPDATE raw_objects SET pinned_by_command_id = NULL WHERE pinned_by_command_id = ?",
            )
            .bind(command_id.to_string())
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn cleanup(&self, now: OffsetDateTime) -> Result<()> {
        let rows = sqlx::query(
            "SELECT object_sha256 FROM raw_objects WHERE expires_at <= ? AND pinned_by_command_id IS NULL",
        )
        .bind(ts(now))
        .fetch_all(&self.pool)
        .await?;
        for row in rows {
            let sha: String = row.try_get("object_sha256")?;
            self.blob_store.remove(&sha)?;
        }
        sqlx::query(
            "DELETE FROM raw_objects WHERE expires_at <= ? AND pinned_by_command_id IS NULL",
        )
        .bind(ts(now))
        .execute(&self.pool)
        .await?;
        sqlx::query("DELETE FROM acked_batches WHERE acked_at <= ?")
            .bind(ts(now - Duration::days(ACK_RETENTION_DAYS)))
            .execute(&self.pool)
            .await?;
        sqlx::query("DELETE FROM commands WHERE status = ? AND completed_at <= ?")
            .bind(serde_json::to_string(&CommandStatus::Completed)?)
            .bind(ts(now - Duration::days(30)))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn health_snapshot(&self) -> Result<HealthSnapshot> {
        Ok(HealthSnapshot {
            outbox_batches: count_rows(&self.pool, "SELECT COUNT(*) FROM outbox").await?,
            outbox_bytes: count_rows(
                &self.pool,
                "SELECT COALESCE(SUM(LENGTH(body)), 0) FROM outbox",
            )
            .await?,
            pending_commands: count_rows(
                &self.pool,
                "SELECT COUNT(*) FROM commands WHERE status != '\"completed\"'",
            )
            .await?,
            active_tasks: count_rows(&self.pool, "SELECT COUNT(*) FROM active_tasks").await?,
            active_flows: count_rows(
                &self.pool,
                "SELECT COUNT(*) FROM flows WHERE closed_at IS NULL",
            )
            .await?,
            raw_objects: count_rows(&self.pool, "SELECT COUNT(*) FROM raw_objects").await?,
        })
    }

    pub async fn load_chunks(
        &self,
        manifest: &ContentObjectManifest,
    ) -> Result<Vec<wire::ContentUploadChunk>> {
        self.blob_store
            .load_chunks(&manifest.object_sha256, manifest.request_id)
    }

    pub async fn load_task_cursor(&self, task: &TaskKey) -> Result<Option<TaskCursor>> {
        let row = sqlx::query(
            "SELECT sequence, conversation_title, attempt_count, phase, outcome, started_at, updated_at, completeness, model, tool_names_json, response_ids_json, usage_json FROM active_tasks WHERE task_ref = ?",
        )
        .bind(task.task_ref())
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| {
            Ok(TaskCursor {
                sequence: row.try_get::<i64, _>("sequence")? as u64,
                conversation_title: row.try_get("conversation_title")?,
                attempt_count: row.try_get::<i64, _>("attempt_count")? as u32,
                phase: serde_json::from_str(&row.try_get::<String, _>("phase")?)?,
                outcome: row
                    .try_get::<Option<String>, _>("outcome")?
                    .map(|raw| serde_json::from_str(&raw))
                    .transpose()?,
                started_at: from_ms(row.try_get("started_at")?),
                updated_at: from_ms(row.try_get("updated_at")?),
                completeness: serde_json::from_str(&row.try_get::<String, _>("completeness")?)?,
                model: row.try_get("model")?,
                tool_names: serde_json::from_str(&row.try_get::<String, _>("tool_names_json")?)?,
                response_ids: serde_json::from_str(
                    &row.try_get::<String, _>("response_ids_json")?,
                )?,
                usage: serde_json::from_str(&row.try_get::<String, _>("usage_json")?)?,
            })
        })
        .transpose()
    }

    pub async fn sync_conversation_title(&self, session_id: &str, title: &str) -> Result<usize> {
        let rows = sqlx::query(
            "SELECT client_id, provider, session_id, thread_id, turn_id, started_at
             FROM active_tasks
             WHERE session_id = ? AND (conversation_title IS NULL OR conversation_title != ?)",
        )
        .bind(session_id)
        .bind(title)
        .fetch_all(&self.pool)
        .await?;
        if rows.is_empty() {
            return Ok(0);
        }
        sqlx::query(
            "UPDATE active_tasks SET conversation_title = ?
             WHERE session_id = ? AND (conversation_title IS NULL OR conversation_title != ?)",
        )
        .bind(title)
        .bind(session_id)
        .bind(title)
        .execute(&self.pool)
        .await?;
        let records = rows
            .into_iter()
            .map(|row| {
                SummaryRecord::Session(SessionSummary {
                    task: TaskKey {
                        client_id: row.get("client_id"),
                        provider: crate::model::ProviderId::new(row.get::<String, _>("provider")),
                        session_id: row.get("session_id"),
                        thread_id: row.get("thread_id"),
                        turn_id: row.get("turn_id"),
                    },
                    parent_turn_id: None,
                    root_turn_id: None,
                    first_seen_at: from_ms(row.get("started_at")),
                })
            })
            .collect();
        Ok(self
            .persist_ingress(records, Vec::new())
            .await?
            .enqueued_batches)
    }

    pub async fn has_attempt_response(&self, task: &TaskKey, response_id: &str) -> Result<bool> {
        let exists: i64 = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM attempts WHERE task_ref = ? AND response_id = ?)",
        )
        .bind(task.task_ref())
        .bind(response_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(exists != 0)
    }

    pub async fn note_flow_open(
        &self,
        flow_id: Uuid,
        process_instance_id: Option<Uuid>,
        local_addr: &str,
        remote_addr: &str,
        transport: &str,
        created_at: OffsetDateTime,
    ) -> Result<()> {
        sqlx::query(
            "INSERT OR IGNORE INTO flows(flow_id, client_instance_id, process_instance_id, local_addr, remote_addr, transport, created_at, closed_at) VALUES(?, ?, ?, ?, ?, ?, ?, NULL)",
        )
        .bind(flow_id.to_string())
        .bind(self.client.instance_id.to_string())
        .bind(process_instance_id.map(|value| value.to_string()))
        .bind(local_addr)
        .bind(remote_addr)
        .bind(transport)
        .bind(ts(created_at))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn note_flow_closed(&self, flow_id: Uuid, closed_at: OffsetDateTime) -> Result<()> {
        sqlx::query("UPDATE flows SET closed_at = ? WHERE flow_id = ?")
            .bind(ts(closed_at))
            .bind(flow_id.to_string())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn migrate(&self) -> Result<()> {
        let statements = [
            "CREATE TABLE IF NOT EXISTS processes(
                process_instance_id TEXT PRIMARY KEY,
                client_instance_id TEXT NOT NULL,
                pid INTEGER NOT NULL,
                executable_sha256 TEXT NOT NULL,
                codex_version TEXT,
                started_at INTEGER NOT NULL,
                exited_at INTEGER,
                exit_code INTEGER,
                signal INTEGER
            )",
            "CREATE TABLE IF NOT EXISTS flows(
                flow_id TEXT PRIMARY KEY,
                client_instance_id TEXT NOT NULL,
                process_instance_id TEXT,
                local_addr TEXT,
                remote_addr TEXT,
                transport TEXT,
                created_at INTEGER NOT NULL,
                closed_at INTEGER
            )",
            "CREATE TABLE IF NOT EXISTS active_tasks(
                task_ref TEXT PRIMARY KEY,
                client_id TEXT NOT NULL,
                provider TEXT NOT NULL,
                session_id TEXT NOT NULL,
                thread_id TEXT NOT NULL,
                turn_id TEXT NOT NULL,
                conversation_title TEXT,
                phase TEXT NOT NULL,
                outcome TEXT,
                sequence INTEGER NOT NULL,
                last_event_id TEXT NOT NULL,
                started_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                terminal_at INTEGER,
                attempt_count INTEGER NOT NULL,
                model TEXT,
                tool_names_json TEXT NOT NULL,
                response_ids_json TEXT NOT NULL,
                usage_json TEXT NOT NULL,
                completeness TEXT NOT NULL,
                last_error_json TEXT,
                parent_turn_id TEXT,
                root_turn_id TEXT,
                first_seen_at INTEGER
            )",
            "CREATE TABLE IF NOT EXISTS attempts(
                attempt_id TEXT PRIMARY KEY,
                task_ref TEXT NOT NULL,
                ordinal INTEGER NOT NULL,
                status TEXT NOT NULL,
                started_at INTEGER NOT NULL,
                finished_at INTEGER,
                response_id TEXT,
                model TEXT,
                tool_names_json TEXT NOT NULL,
                usage_json TEXT NOT NULL,
                completeness TEXT NOT NULL,
                error_json TEXT
            )",
            "CREATE TABLE IF NOT EXISTS capture_gaps(
                gap_id TEXT PRIMARY KEY,
                client_instance_id TEXT NOT NULL,
                task_ref TEXT,
                observed_at INTEGER NOT NULL,
                reason TEXT NOT NULL,
                lost_bytes INTEGER,
                flow_id TEXT
            )",
            "CREATE TABLE IF NOT EXISTS raw_objects(
                object_sha256 TEXT PRIMARY KEY,
                task_ref TEXT NOT NULL,
                part TEXT NOT NULL,
                media_type TEXT NOT NULL,
                uncompressed_bytes INTEGER NOT NULL,
                compressed_bytes INTEGER NOT NULL,
                chunk_count INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                pinned_by_command_id TEXT,
                sanitized_headers_json TEXT NOT NULL
            )",
            "CREATE TABLE IF NOT EXISTS outbox(
                batch_id TEXT PRIMARY KEY,
                payload_sha256 TEXT NOT NULL,
                body BLOB NOT NULL,
                record_count INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                next_attempt_at INTEGER NOT NULL,
                attempt_count INTEGER NOT NULL,
                last_error TEXT,
                is_priority INTEGER NOT NULL
            )",
            "CREATE TABLE IF NOT EXISTS acked_batches(
                batch_id TEXT NOT NULL,
                payload_sha256 TEXT NOT NULL,
                acked_at INTEGER NOT NULL,
                PRIMARY KEY(batch_id, payload_sha256)
            )",
            "CREATE TABLE IF NOT EXISTS commands(
                command_id TEXT PRIMARY KEY,
                expires_at INTEGER NOT NULL,
                status TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                result_json TEXT,
                error_json TEXT,
                attempt_count INTEGER NOT NULL,
                next_attempt_at INTEGER NOT NULL,
                completed_at INTEGER
            )",
        ];
        for statement in statements {
            sqlx::query(statement).execute(&self.pool).await?;
        }
        let has_title_column = sqlx::query("PRAGMA table_info(active_tasks)")
            .fetch_all(&self.pool)
            .await?
            .iter()
            .any(|row| row.get::<String, _>("name") == "conversation_title");
        if !has_title_column {
            sqlx::query("ALTER TABLE active_tasks ADD COLUMN conversation_title TEXT")
                .execute(&self.pool)
                .await?;
        }
        Ok(())
    }

    async fn apply_record_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        record: &SummaryRecord,
    ) -> Result<bool> {
        match record {
            SummaryRecord::Task(summary) => self.upsert_task_summary_tx(tx, summary).await,
            SummaryRecord::TaskTransition(transition) => {
                self.upsert_transition_tx(tx, transition).await?;
                Ok(true)
            }
            SummaryRecord::Attempt(attempt) => self.upsert_attempt_tx(tx, attempt).await,
            SummaryRecord::CaptureGap(gap) => self.upsert_gap_tx(tx, gap).await,
            SummaryRecord::Process(process) => self.upsert_process_tx(tx, process).await,
            SummaryRecord::Session(session) => self.merge_session_tx(tx, session).await,
            SummaryRecord::Heartbeat(_) => Ok(true),
            SummaryRecord::HttpExchange(_) => Ok(true),
        }
    }

    async fn store_raw_object_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        stored: &StoredBlob,
    ) -> Result<()> {
        sqlx::query(
            "INSERT OR REPLACE INTO raw_objects(
                object_sha256, task_ref, part, media_type, uncompressed_bytes, compressed_bytes,
                chunk_count, created_at, expires_at, pinned_by_command_id, sanitized_headers_json
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)",
        )
        .bind(&stored.object_sha256)
        .bind(stored.task.task_ref())
        .bind(content_part_name(stored.part))
        .bind(&stored.media_type)
        .bind(stored.uncompressed_bytes as i64)
        .bind(stored.compressed_bytes.len() as i64)
        .bind(stored.chunk_count as i64)
        .bind(ts(stored.created_at))
        .bind(ts(stored.expires_at))
        .bind(serde_json::to_string(&stored.sanitized_headers)?)
        .execute(&mut **tx)
        .await?;
        Ok(())
    }

    async fn enqueue_records_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        records: Vec<SummaryRecord>,
    ) -> Result<usize> {
        if records.is_empty() {
            return Ok(0);
        }
        let priority = records.iter().any(is_priority_record);
        let batches = split_records(records);
        let mut inserted = 0usize;
        for batch_records in batches {
            let wire_batch = self.build_wire_batch_tx(tx, &batch_records).await?;
            if wire_batch.tasks.is_empty() && wire_batch.heartbeats.is_empty() {
                continue;
            }
            let encoded = encode_batch(&wire_batch)?;
            self.ensure_outbox_capacity_tx(tx, encoded.bytes.len() as i64, priority)
                .await?;
            sqlx::query(
                "INSERT INTO outbox(batch_id, payload_sha256, body, record_count, created_at, next_attempt_at, attempt_count, last_error, is_priority) VALUES(?, ?, ?, ?, ?, ?, 0, NULL, ?)",
            )
            .bind(encoded.batch_id.to_string())
            .bind(encoded.payload_sha256)
            .bind(encoded.bytes)
            .bind((wire_batch.tasks.len() + wire_batch.heartbeats.len()) as i64)
            .bind(now_ms())
            .bind(now_ms())
            .bind(i64::from(priority))
            .execute(&mut **tx)
            .await?;
            inserted += 1;
        }
        Ok(inserted)
    }

    async fn build_wire_batch_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        records: &[SummaryRecord],
    ) -> Result<IngestBatch> {
        let mut task_refs = BTreeSet::new();
        let mut tasks: HashMap<String, TaskAccumulator> = HashMap::new();
        let mut heartbeats = Vec::new();

        for record in records {
            match record {
                SummaryRecord::Session(session) => {
                    task_refs.insert(session.task.task_ref());
                }
                SummaryRecord::Task(summary) => {
                    task_refs.insert(summary.task.task_ref());
                }
                SummaryRecord::TaskTransition(transition) => {
                    let task_ref = transition.task.task_ref();
                    task_refs.insert(task_ref.clone());
                    let event = map_transition_event(transition);
                    if let Some(error) = &event.error {
                        tasks
                            .entry(task_ref.clone())
                            .or_default()
                            .errors
                            .push(error.clone());
                    }
                    tasks.entry(task_ref).or_default().events.push(event);
                }
                SummaryRecord::Attempt(attempt) => {
                    let task_ref = attempt.task.task_ref();
                    task_refs.insert(task_ref.clone());
                    let record = self.build_attempt_record_tx(tx, attempt).await?;
                    if let Some(error) = &record.error {
                        tasks
                            .entry(task_ref.clone())
                            .or_default()
                            .errors
                            .push(error.clone());
                    }
                    tasks.entry(task_ref).or_default().attempts.push(record);
                }
                SummaryRecord::CaptureGap(gap) => {
                    if let Some(task) = &gap.task {
                        let task_ref = task.task_ref();
                        task_refs.insert(task_ref.clone());
                        tasks
                            .entry(task_ref)
                            .or_default()
                            .gaps
                            .push(map_gap_record(gap));
                    }
                }
                SummaryRecord::Heartbeat(heartbeat) => {
                    heartbeats.push(self.build_heartbeat(heartbeat).await?);
                }
                SummaryRecord::HttpExchange(_) | SummaryRecord::Process(_) => {}
            }
        }

        let mut uploads = Vec::new();
        for task_ref in task_refs {
            if let Some(snapshot) = self.load_snapshot_tx(tx, &task_ref).await? {
                let acc = tasks.remove(&task_ref).unwrap_or_default();
                uploads.push(TaskUpload {
                    snapshot,
                    attempts: acc.attempts,
                    events: acc.events,
                    errors: dedupe_errors(acc.errors),
                    gaps: acc.gaps,
                });
            }
        }

        Ok(IngestBatch {
            version: wire::PROTOCOL_VERSION,
            batch_id: Uuid::now_v7(),
            generated_at_ms: now_ms(),
            client: self.client.clone(),
            tasks: uploads,
            heartbeats,
        })
    }

    async fn load_snapshot_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        task_ref: &str,
    ) -> Result<Option<TaskSnapshot>> {
        let row = sqlx::query(
            "SELECT client_id, provider, session_id, thread_id, turn_id, conversation_title, phase, outcome, sequence, started_at, updated_at, terminal_at, attempt_count, model, tool_names_json, response_ids_json, usage_json, completeness, last_error_json, parent_turn_id, root_turn_id FROM active_tasks WHERE task_ref = ?",
        )
        .bind(task_ref)
        .fetch_optional(&mut **tx)
        .await?;
        row.map(|row| {
            let completeness: Completeness =
                serde_json::from_str(&row.try_get::<String, _>("completeness")?)?;
            let usage: TokenUsage = serde_json::from_str(&row.try_get::<String, _>("usage_json")?)?;
            let error = row
                .try_get::<Option<String>, _>("last_error_json")?
                .map(|raw| serde_json::from_str::<PersistedError>(&raw).map(|value| value.error))
                .transpose()?;
            let outcome: Option<TaskOutcome> = row
                .try_get::<Option<String>, _>("outcome")?
                .map(|raw| serde_json::from_str(&raw))
                .transpose()?;
            let updated_at_ms: i64 = row.try_get("updated_at")?;
            Ok(TaskSnapshot {
                task_ref: task_ref.to_string(),
                identity: TaskIdentity {
                    provider: row.try_get("provider")?,
                    session_id: row.try_get("session_id")?,
                    thread_id: row.try_get("thread_id")?,
                    turn_id: row.try_get("turn_id")?,
                },
                codex: wire::CodexTaskMetadata {
                    request_kind: "turn".into(),
                    parent_turn_id: row.try_get("parent_turn_id")?,
                    root_turn_id: row.try_get("root_turn_id")?,
                },
                conversation_title: row.try_get("conversation_title")?,
                sequence: row.try_get::<i64, _>("sequence")? as u64,
                phase: map_phase(serde_json::from_str::<TaskPhase>(
                    &row.try_get::<String, _>("phase")?,
                )?),
                terminal: outcome.map(map_outcome),
                integrity: map_integrity(completeness),
                model: row.try_get("model")?,
                attempt_count: row.try_get::<i64, _>("attempt_count")? as u32,
                tool_names: serde_json::from_str(&row.try_get::<String, _>("tool_names_json")?)?,
                response_ids: serde_json::from_str(
                    &row.try_get::<String, _>("response_ids_json")?,
                )?,
                usage: map_usage(&usage),
                started_at_ms: row.try_get("started_at")?,
                updated_at_ms,
                completed_at_ms: row.try_get("terminal_at")?,
                last_error: error
                    .map(|error| map_error_record(task_ref, None, updated_at_ms, &error, None)),
            })
        })
        .transpose()
    }

    async fn build_attempt_record_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        attempt: &AttemptSummary,
    ) -> Result<AttemptRecord> {
        let request_object_sha256 = sqlx::query_scalar::<_, String>(
            "SELECT object_sha256 FROM raw_objects WHERE task_ref = ? AND part = ? ORDER BY created_at DESC LIMIT 1",
        )
        .bind(attempt.task.task_ref())
        .bind(content_part_name(ContentPart::Request))
        .fetch_optional(&mut **tx)
        .await?;
        let response_object_sha256 = sqlx::query_scalar::<_, String>(
            "SELECT object_sha256 FROM raw_objects WHERE task_ref = ? AND part = ? ORDER BY created_at DESC LIMIT 1",
        )
        .bind(attempt.task.task_ref())
        .bind(content_part_name(ContentPart::Response))
        .fetch_optional(&mut **tx)
        .await?;
        Ok(AttemptRecord {
            attempt_id: attempt.attempt_id,
            task_ref: attempt.task.task_ref(),
            ordinal: attempt.ordinal,
            response_id: attempt.response_id.clone(),
            transport: "responses".into(),
            status: map_attempt_status(attempt.status),
            http_status: extract_http_status(attempt.error.as_ref()),
            model: attempt.model.clone(),
            tool_names: attempt.tool_names.clone(),
            usage: map_usage(&attempt.usage),
            error: attempt.error.as_ref().map(|error| {
                map_error_record(
                    &attempt.task.task_ref(),
                    Some(attempt.attempt_id),
                    ts(attempt.finished_at.unwrap_or(attempt.started_at)),
                    error,
                    None,
                )
            }),
            request_object_sha256,
            response_object_sha256,
            started_at_ms: ts(attempt.started_at),
            ended_at_ms: attempt.finished_at.map(ts),
            awaiting_tool: false,
        })
    }

    async fn build_heartbeat(&self, heartbeat: &HeartbeatSummary) -> Result<Heartbeat> {
        Ok(Heartbeat {
            heartbeat_id: Uuid::now_v7(),
            client_id: self.client.client_id.clone(),
            instance_id: heartbeat.client_instance_id,
            observed_at_ms: ts(heartbeat.observed_at),
            queue_depth: 0,
            active_task_count: 0,
            capture_health: if !heartbeat.health.profile_supported {
                IntegrityState::UnsupportedBuild
            } else if heartbeat.health.ring_buffer_drops > 0
                || matches!(
                    heartbeat.health.last_error,
                    Some(StructuredError::CaptureLost(_))
                )
            {
                IntegrityState::Degraded
            } else {
                IntegrityState::Complete
            },
            note: Some(heartbeat.client_version.clone()),
        })
    }

    async fn ensure_outbox_capacity_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        next_bytes: i64,
        priority: bool,
    ) -> Result<()> {
        let total_bytes: i64 =
            sqlx::query_scalar("SELECT COALESCE(SUM(LENGTH(body)), 0) FROM outbox")
                .fetch_one(&mut **tx)
                .await?;
        let priority_bytes: i64 = sqlx::query_scalar(
            "SELECT COALESCE(SUM(LENGTH(body)), 0) FROM outbox WHERE is_priority = 1",
        )
        .fetch_one(&mut **tx)
        .await?;
        if total_bytes + next_bytes > OUTBOX_HARD_CAP_BYTES {
            bail!("outbox hard cap reached");
        }
        if !priority {
            let routine_bytes = total_bytes - priority_bytes;
            let routine_cap = OUTBOX_HARD_CAP_BYTES - OUTBOX_PRIORITY_RESERVE_BYTES;
            if routine_bytes + next_bytes > routine_cap {
                bail!("routine outbox budget exhausted");
            }
        }
        Ok(())
    }

    async fn upsert_task_summary_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        summary: &TaskSummary,
    ) -> Result<bool> {
        let task_ref = summary.task.task_ref();
        let existing =
            sqlx::query("SELECT sequence, last_event_id FROM active_tasks WHERE task_ref = ?")
                .bind(&task_ref)
                .fetch_optional(&mut **tx)
                .await?;
        if let Some(row) = existing {
            let sequence: i64 = row.try_get("sequence")?;
            let last_event_id: String = row.try_get("last_event_id")?;
            if sequence as u64 > summary.sequence
                || (sequence as u64 == summary.sequence
                    && last_event_id == summary.last_event_id.to_string())
            {
                return Ok(false);
            }
        }
        sqlx::query(
            "INSERT INTO active_tasks(task_ref, client_id, provider, session_id, thread_id, turn_id, conversation_title, phase, outcome, sequence, last_event_id, started_at, updated_at, terminal_at, attempt_count, model, tool_names_json, response_ids_json, usage_json, completeness, last_error_json, parent_turn_id, root_turn_id, first_seen_at)
             VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?)
             ON CONFLICT(task_ref) DO UPDATE SET conversation_title=COALESCE(excluded.conversation_title, active_tasks.conversation_title), phase=excluded.phase, outcome=excluded.outcome, sequence=excluded.sequence, last_event_id=excluded.last_event_id, started_at=excluded.started_at, updated_at=excluded.updated_at, terminal_at=excluded.terminal_at, attempt_count=excluded.attempt_count, model=excluded.model, tool_names_json=excluded.tool_names_json, response_ids_json=excluded.response_ids_json, usage_json=excluded.usage_json, completeness=excluded.completeness, last_error_json=excluded.last_error_json",
        )
        .bind(&task_ref)
        .bind(&summary.task.client_id)
        .bind(&summary.task.provider.0)
        .bind(&summary.task.session_id)
        .bind(&summary.task.thread_id)
        .bind(&summary.task.turn_id)
        .bind(&summary.conversation_title)
        .bind(serde_json::to_string(&summary.phase)?)
        .bind(json_opt(&summary.outcome)?)
        .bind(summary.sequence as i64)
        .bind(summary.last_event_id.to_string())
        .bind(ts(summary.started_at))
        .bind(ts(summary.updated_at))
        .bind(summary.terminal_at.map(ts))
        .bind(summary.attempt_count as i64)
        .bind(&summary.model)
        .bind(serde_json::to_string(&summary.tool_names)?)
        .bind(serde_json::to_string(&summary.response_ids)?)
        .bind(serde_json::to_string(&summary.usage)?)
        .bind(serde_json::to_string(&summary.completeness)?)
        .bind(json_opt_error(summary.last_error.as_ref())?)
        .bind(ts(summary.started_at))
        .execute(&mut **tx)
        .await?;
        Ok(true)
    }

    async fn upsert_transition_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        transition: &TaskTransition,
    ) -> Result<bool> {
        let task_ref = transition.task.task_ref();
        let existing = sqlx::query("SELECT sequence, last_event_id, started_at, attempt_count, tool_names_json, response_ids_json, usage_json FROM active_tasks WHERE task_ref = ?")
            .bind(&task_ref)
            .fetch_optional(&mut **tx)
            .await?;
        let (started_at, attempt_count, tool_names_json, response_ids_json, usage_json) =
            if let Some(row) = existing {
                let sequence: i64 = row.try_get("sequence")?;
                let event_id: String = row.try_get("last_event_id")?;
                if sequence as u64 > transition.sequence
                    || (sequence as u64 == transition.sequence
                        && event_id == transition.event_id.to_string())
                {
                    return Ok(false);
                }
                (
                    row.try_get::<i64, _>("started_at")?,
                    row.try_get::<i64, _>("attempt_count")?,
                    row.try_get::<String, _>("tool_names_json")?,
                    row.try_get::<String, _>("response_ids_json")?,
                    row.try_get::<String, _>("usage_json")?,
                )
            } else {
                (
                    ts(transition.observed_at),
                    0,
                    "[]".into(),
                    "[]".into(),
                    "{}".into(),
                )
            };
        sqlx::query(
            "INSERT INTO active_tasks(task_ref, client_id, provider, session_id, thread_id, turn_id, phase, outcome, sequence, last_event_id, started_at, updated_at, terminal_at, attempt_count, model, tool_names_json, response_ids_json, usage_json, completeness, last_error_json, parent_turn_id, root_turn_id, first_seen_at)
             VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, NULL, NULL, ?)
             ON CONFLICT(task_ref) DO UPDATE SET phase=excluded.phase, outcome=excluded.outcome, sequence=excluded.sequence, last_event_id=excluded.last_event_id, updated_at=excluded.updated_at, terminal_at=excluded.terminal_at, completeness=excluded.completeness, last_error_json=excluded.last_error_json",
        )
        .bind(&task_ref)
        .bind(&transition.task.client_id)
        .bind(&transition.task.provider.0)
        .bind(&transition.task.session_id)
        .bind(&transition.task.thread_id)
        .bind(&transition.task.turn_id)
        .bind(serde_json::to_string(&transition.phase)?)
        .bind(json_opt(&transition.outcome)?)
        .bind(transition.sequence as i64)
        .bind(transition.event_id.to_string())
        .bind(started_at)
        .bind(ts(transition.observed_at))
        .bind((transition.phase == TaskPhase::Terminal).then(|| ts(transition.observed_at)))
        .bind(attempt_count)
        .bind(tool_names_json)
        .bind(response_ids_json)
        .bind(usage_json)
        .bind(serde_json::to_string(&transition.completeness)?)
        .bind(json_opt_error(transition.error.as_ref())?)
        .bind(started_at)
        .execute(&mut **tx)
        .await?;
        Ok(true)
    }

    async fn upsert_attempt_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        attempt: &AttemptSummary,
    ) -> Result<bool> {
        let task_ref = attempt.task.task_ref();
        let exists: Option<String> =
            sqlx::query_scalar("SELECT attempt_id FROM attempts WHERE attempt_id = ?")
                .bind(attempt.attempt_id.to_string())
                .fetch_optional(&mut **tx)
                .await?;
        sqlx::query(
            "INSERT INTO attempts(attempt_id, task_ref, ordinal, status, started_at, finished_at, response_id, model, tool_names_json, usage_json, completeness, error_json)
             VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(attempt_id) DO UPDATE SET status=excluded.status, finished_at=excluded.finished_at, response_id=excluded.response_id, model=excluded.model, tool_names_json=excluded.tool_names_json, usage_json=excluded.usage_json, completeness=excluded.completeness, error_json=excluded.error_json",
        )
        .bind(attempt.attempt_id.to_string())
        .bind(&task_ref)
        .bind(attempt.ordinal as i64)
        .bind(serde_json::to_string(&attempt.status)?)
        .bind(ts(attempt.started_at))
        .bind(attempt.finished_at.map(ts))
        .bind(&attempt.response_id)
        .bind(&attempt.model)
        .bind(serde_json::to_string(&attempt.tool_names)?)
        .bind(serde_json::to_string(&attempt.usage)?)
        .bind(serde_json::to_string(&attempt.completeness)?)
        .bind(json_opt_error(attempt.error.as_ref())?)
        .execute(&mut **tx)
        .await?;

        if exists.is_none() {
            let row = sqlx::query(
                "SELECT attempt_count, tool_names_json, response_ids_json FROM active_tasks WHERE task_ref = ?",
            )
            .bind(&task_ref)
            .fetch_optional(&mut **tx)
            .await?;
            if let Some(row) = row {
                let attempt_count: i64 = row.try_get("attempt_count")?;
                let tool_names: Vec<String> =
                    serde_json::from_str(&row.try_get::<String, _>("tool_names_json")?)?;
                let response_ids: Vec<String> =
                    serde_json::from_str(&row.try_get::<String, _>("response_ids_json")?)?;
                sqlx::query(
                    "UPDATE active_tasks SET attempt_count = ?, model = COALESCE(?, model), tool_names_json = ?, response_ids_json = ?, usage_json = ?, completeness = ?, last_error_json = COALESCE(?, last_error_json) WHERE task_ref = ?",
                )
                .bind(attempt_count.max(attempt.ordinal as i64))
                .bind(&attempt.model)
                .bind(serde_json::to_string(&merge_unique(tool_names, attempt.tool_names.clone()))?)
                .bind(serde_json::to_string(&merge_unique(response_ids, attempt.response_id.clone().into_iter().collect()))?)
                .bind(serde_json::to_string(&attempt.usage)?)
                .bind(serde_json::to_string(&attempt.completeness)?)
                .bind(json_opt_error(attempt.error.as_ref())?)
                .bind(&task_ref)
                .execute(&mut **tx)
                .await?;
            }
        }
        Ok(true)
    }

    async fn upsert_gap_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        gap: &CaptureGapSummary,
    ) -> Result<bool> {
        let exists: Option<String> =
            sqlx::query_scalar("SELECT gap_id FROM capture_gaps WHERE gap_id = ?")
                .bind(gap.gap_id.to_string())
                .fetch_optional(&mut **tx)
                .await?;
        if exists.is_some() {
            return Ok(false);
        }
        sqlx::query(
            "INSERT INTO capture_gaps(gap_id, client_instance_id, task_ref, observed_at, reason, lost_bytes, flow_id) VALUES(?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(gap.gap_id.to_string())
        .bind(gap.client_instance_id.to_string())
        .bind(gap.task.as_ref().map(TaskKey::task_ref))
        .bind(ts(gap.observed_at))
        .bind(&gap.reason)
        .bind(gap.lost_bytes.map(|value| value as i64))
        .bind(gap.flow_id.map(|value| value.to_string()))
        .execute(&mut **tx)
        .await?;
        Ok(true)
    }

    async fn upsert_process_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        process: &ProcessSummary,
    ) -> Result<bool> {
        let exists: Option<String> = sqlx::query_scalar(
            "SELECT process_instance_id FROM processes WHERE process_instance_id = ?",
        )
        .bind(process.process_instance_id.to_string())
        .fetch_optional(&mut **tx)
        .await?;
        sqlx::query(
            "INSERT INTO processes(process_instance_id, client_instance_id, pid, executable_sha256, codex_version, started_at, exited_at, exit_code, signal)
             VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(process_instance_id) DO UPDATE SET exited_at=excluded.exited_at, exit_code=excluded.exit_code, signal=excluded.signal",
        )
        .bind(process.process_instance_id.to_string())
        .bind(process.client_instance_id.to_string())
        .bind(process.pid as i64)
        .bind(&process.executable_sha256)
        .bind(&process.codex_version)
        .bind(ts(process.started_at))
        .bind(process.exited_at.map(ts))
        .bind(process.exit_code)
        .bind(process.signal)
        .execute(&mut **tx)
        .await?;
        Ok(exists.is_none())
    }

    async fn merge_session_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        session: &SessionSummary,
    ) -> Result<bool> {
        let result = sqlx::query(
            "UPDATE active_tasks SET parent_turn_id = COALESCE(?, parent_turn_id), root_turn_id = COALESCE(?, root_turn_id), first_seen_at = COALESCE(first_seen_at, ?) WHERE task_ref = ?",
        )
        .bind(&session.parent_turn_id)
        .bind(&session.root_turn_id)
        .bind(ts(session.first_seen_at))
        .bind(session.task.task_ref())
        .execute(&mut **tx)
        .await?;
        Ok(result.rows_affected() > 0)
    }
}

fn split_records(records: Vec<SummaryRecord>) -> Vec<Vec<SummaryRecord>> {
    let mut chunks = Vec::new();
    let mut current = Vec::new();
    for record in records {
        current.push(record);
        if current.len() >= 128 {
            chunks.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        chunks.push(current);
    }
    chunks
}

fn normalize_record(mut record: SummaryRecord) -> SummaryRecord {
    normalize_record_error(&mut record);
    record
}

fn normalize_record_error(record: &mut SummaryRecord) {
    match record {
        SummaryRecord::Task(summary) => normalize_error_opt(&mut summary.last_error),
        SummaryRecord::TaskTransition(transition) => normalize_error_opt(&mut transition.error),
        SummaryRecord::Attempt(attempt) => normalize_error_opt(&mut attempt.error),
        SummaryRecord::Heartbeat(heartbeat) => {
            normalize_error_opt(&mut heartbeat.health.last_error)
        }
        SummaryRecord::Session(_)
        | SummaryRecord::HttpExchange(_)
        | SummaryRecord::CaptureGap(_)
        | SummaryRecord::Process(_) => {}
    }
}

fn normalize_error_opt(error: &mut Option<StructuredError>) {
    if let Some(error) = error {
        match error {
            StructuredError::Provider(inner) => inner.message = truncate_message(&inner.message),
            StructuredError::Http(inner) => {
                if let Some(provider) = &mut inner.provider_error {
                    provider.message = truncate_message(&provider.message);
                }
            }
            StructuredError::Incomplete(inner) => inner.reason = truncate_message(&inner.reason),
            StructuredError::CodexTerminal(inner) => {
                inner.message = truncate_message(&inner.message)
            }
            StructuredError::TurnAborted(inner) => inner.reason = truncate_message(&inner.reason),
            StructuredError::CaptureLost(inner) => inner.reason = truncate_message(&inner.reason),
            StructuredError::ProcessTerminated(_) | StructuredError::UnsupportedCodexBuild(_) => {}
        }
    }
}

fn truncate_message(message: &str) -> String {
    const MAX: usize = 32 * 1024;
    if message.len() <= MAX {
        return message.to_string();
    }
    let suffix = format!(
        " [truncated orig_len={} sha256={}]",
        message.len(),
        wire::sha256_hex(message.as_bytes())
    );
    let keep = MAX.saturating_sub(suffix.len());
    let mut end = keep;
    while !message.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}{}", &message[..end], suffix)
}

fn json_opt<T: Serialize>(value: &Option<T>) -> Result<Option<String>> {
    value
        .as_ref()
        .map(serde_json::to_string)
        .transpose()
        .map_err(Into::into)
}

fn json_opt_error(error: Option<&StructuredError>) -> Result<Option<String>> {
    error
        .map(|error| {
            serde_json::to_string(&PersistedError {
                error: error.clone(),
            })
        })
        .transpose()
        .map_err(Into::into)
}

async fn count_rows(pool: &SqlitePool, sql: &str) -> Result<u64> {
    let value: i64 = sqlx::query_scalar(sql).fetch_one(pool).await?;
    Ok(value as u64)
}

fn map_phase(value: TaskPhase) -> wire::TaskPhase {
    match value {
        TaskPhase::Running => wire::TaskPhase::Running,
        TaskPhase::AwaitingTool => wire::TaskPhase::AwaitingTool,
        TaskPhase::Retrying => wire::TaskPhase::Retrying,
        TaskPhase::Terminal => wire::TaskPhase::Terminal,
    }
}

fn map_outcome(value: TaskOutcome) -> TerminalOutcome {
    match value {
        TaskOutcome::Completed => TerminalOutcome::Completed,
        TaskOutcome::Failed => TerminalOutcome::Failed,
        TaskOutcome::Aborted => TerminalOutcome::Aborted,
        TaskOutcome::Terminated => TerminalOutcome::Terminated,
        TaskOutcome::Lost => TerminalOutcome::Lost,
    }
}

fn map_integrity(value: Completeness) -> IntegrityState {
    match value {
        Completeness::Complete => IntegrityState::Complete,
        Completeness::Degraded | Completeness::Unknown => IntegrityState::Degraded,
    }
}

fn map_usage(usage: &TokenUsage) -> UsageSummary {
    UsageSummary {
        input_tokens: usage.input_tokens.unwrap_or(0),
        output_tokens: usage.output_tokens.unwrap_or(0),
        reasoning_tokens: usage.reasoning_tokens.unwrap_or(0),
        total_tokens: usage.total_tokens.unwrap_or(
            usage.input_tokens.unwrap_or(0)
                + usage.output_tokens.unwrap_or(0)
                + usage.reasoning_tokens.unwrap_or(0),
        ),
    }
}

fn map_attempt_status(status: AttemptStatus) -> wire::AttemptStatus {
    match status {
        AttemptStatus::Running => wire::AttemptStatus::Running,
        AttemptStatus::Completed => wire::AttemptStatus::Completed,
        AttemptStatus::Failed => wire::AttemptStatus::Failed,
        AttemptStatus::Incomplete => wire::AttemptStatus::Incomplete,
        AttemptStatus::Cancelled => wire::AttemptStatus::Cancelled,
        AttemptStatus::TransportLost => wire::AttemptStatus::TransportLost,
    }
}

fn map_transition_event(transition: &TaskTransition) -> TaskEvent {
    let kind = match (transition.cause, transition.phase, transition.outcome) {
        (TransitionCause::AttemptStarted, _, _) => TaskEventKind::AttemptStarted,
        (TransitionCause::ResponseEndTurn, TaskPhase::Terminal, Some(TaskOutcome::Completed)) => {
            TaskEventKind::TerminalCompleted
        }
        (TransitionCause::ResponseEndTurn, _, _) => TaskEventKind::AttemptCompleted,
        (TransitionCause::ToolCallObserved, _, _) => TaskEventKind::AwaitingTool,
        (TransitionCause::RetryScheduled, _, _) => TaskEventKind::Retrying,
        (TransitionCause::CaptureLost, TaskPhase::Terminal, Some(TaskOutcome::Lost)) => {
            TaskEventKind::TerminalLost
        }
        (TransitionCause::CaptureLost, _, _) => TaskEventKind::CaptureGap,
        (TransitionCause::ProcessExited, _, Some(TaskOutcome::Lost)) => TaskEventKind::TerminalLost,
        (TransitionCause::ProcessExited, _, _) => TaskEventKind::ProcessExit,
        (TransitionCause::CodexTurnAborted, _, _) => TaskEventKind::TerminalAborted,
        (TransitionCause::CodexTurnComplete, _, Some(TaskOutcome::Completed)) => {
            TaskEventKind::TerminalCompleted
        }
        (TransitionCause::CodexTurnComplete, _, Some(TaskOutcome::Failed)) => {
            TaskEventKind::TerminalFailed
        }
        (TransitionCause::CodexTurnComplete, _, Some(TaskOutcome::Aborted)) => {
            TaskEventKind::TerminalAborted
        }
        (TransitionCause::CodexTurnComplete, _, Some(TaskOutcome::Terminated)) => {
            TaskEventKind::TerminalTerminated
        }
        (TransitionCause::CodexTurnComplete, _, Some(TaskOutcome::Lost)) => {
            TaskEventKind::TerminalLost
        }
        (TransitionCause::CodexTurnComplete, _, None) => TaskEventKind::AttemptCompleted,
        (TransitionCause::AttemptCompleted, TaskPhase::AwaitingTool, _) => {
            TaskEventKind::AwaitingTool
        }
        (TransitionCause::AttemptCompleted, TaskPhase::Retrying, _) => {
            classify_attempt_failure(transition.error.as_ref())
        }
        (TransitionCause::AttemptCompleted, _, _) => TaskEventKind::AttemptCompleted,
        (TransitionCause::CaptureStarted | TransitionCause::ClientRecovered, _, _) => {
            TaskEventKind::TaskObserved
        }
    };
    TaskEvent {
        event_id: transition.event_id,
        task_ref: transition.task.task_ref(),
        sequence: transition.sequence,
        occurred_at_ms: ts(transition.observed_at),
        kind,
        phase: map_phase(transition.phase),
        terminal: transition.outcome.map(map_outcome),
        attempt_id: None,
        response_id: None,
        model: None,
        tool_names: Vec::new(),
        usage: UsageSummary::default(),
        error: transition.error.as_ref().map(|error| {
            map_error_record(
                &transition.task.task_ref(),
                None,
                ts(transition.observed_at),
                error,
                Some(kind),
            )
        }),
        http_status: extract_http_status(transition.error.as_ref()),
        exit_code: extract_process_exit(transition.error.as_ref()).0,
        signal: extract_process_exit(transition.error.as_ref()).1,
        note: None,
    }
}

fn classify_attempt_failure(error: Option<&StructuredError>) -> TaskEventKind {
    match error {
        Some(StructuredError::Incomplete(_)) => TaskEventKind::AttemptIncomplete,
        Some(StructuredError::CaptureLost(_)) => TaskEventKind::AttemptLost,
        Some(StructuredError::Provider(provider)) if provider.wire_type == "response.cancelled" => {
            TaskEventKind::AttemptCancelled
        }
        Some(StructuredError::Provider(_)) | Some(StructuredError::Http(_)) => {
            TaskEventKind::AttemptFailed
        }
        _ => TaskEventKind::Retrying,
    }
}

fn map_gap_record(gap: &CaptureGapSummary) -> CaptureGapRecord {
    CaptureGapRecord {
        gap_id: gap.gap_id,
        task_ref: gap.task.as_ref().map(TaskKey::task_ref),
        flow_id: gap
            .flow_id
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unknown".to_string()),
        direction: FlowDirection::ServerToClient,
        occurred_at_ms: ts(gap.observed_at),
        start_seq: gap.lost_bytes.unwrap_or(0),
        end_seq: gap.lost_bytes.unwrap_or(0),
        reason: gap.reason.clone(),
    }
}

fn map_error_record(
    task_ref: &str,
    attempt_id: Option<Uuid>,
    occurred_at_ms: i64,
    error: &StructuredError,
    event_kind: Option<TaskEventKind>,
) -> ErrorRecord {
    match error {
        StructuredError::Provider(inner) => ErrorRecord {
            error_id: Uuid::now_v7(),
            task_ref: task_ref.to_string(),
            attempt_id,
            occurred_at_ms,
            source: if inner.wire_type == "response.cancelled" {
                ErrorSource::ResponseCancelled
            } else {
                ErrorSource::ResponseFailed
            },
            wire_type: Some(inner.wire_type.clone()),
            code: inner.code.clone(),
            message: inner.message.clone(),
            param: inner.param.clone(),
            reason: None,
            http_status: None,
            exit_code: None,
            signal: None,
        },
        StructuredError::Http(inner) => ErrorRecord {
            error_id: Uuid::now_v7(),
            task_ref: task_ref.to_string(),
            attempt_id,
            occurred_at_ms,
            source: ErrorSource::HttpStatus,
            wire_type: inner
                .provider_error
                .as_ref()
                .map(|value| value.wire_type.clone()),
            code: inner
                .provider_error
                .as_ref()
                .and_then(|value| value.code.clone()),
            message: inner.provider_error.as_ref().map_or_else(
                || format!("http {}", inner.status),
                |value| value.message.clone(),
            ),
            param: inner
                .provider_error
                .as_ref()
                .and_then(|value| value.param.clone()),
            reason: None,
            http_status: Some(inner.status),
            exit_code: None,
            signal: None,
        },
        StructuredError::Incomplete(inner) => ErrorRecord {
            error_id: Uuid::now_v7(),
            task_ref: task_ref.to_string(),
            attempt_id,
            occurred_at_ms,
            source: ErrorSource::ResponseIncomplete,
            wire_type: None,
            code: None,
            message: inner.reason.clone(),
            param: None,
            reason: Some(inner.reason.clone()),
            http_status: None,
            exit_code: None,
            signal: None,
        },
        StructuredError::CodexTerminal(inner) => ErrorRecord {
            error_id: Uuid::now_v7(),
            task_ref: task_ref.to_string(),
            attempt_id,
            occurred_at_ms,
            source: ErrorSource::TurnComplete,
            wire_type: None,
            code: inner.code.clone(),
            message: inner.message.clone(),
            param: None,
            reason: None,
            http_status: None,
            exit_code: None,
            signal: None,
        },
        StructuredError::TurnAborted(inner) => ErrorRecord {
            error_id: Uuid::now_v7(),
            task_ref: task_ref.to_string(),
            attempt_id,
            occurred_at_ms,
            source: ErrorSource::TurnAborted,
            wire_type: None,
            code: None,
            message: inner.reason.clone(),
            param: None,
            reason: Some(inner.reason.clone()),
            http_status: None,
            exit_code: None,
            signal: None,
        },
        StructuredError::ProcessTerminated(inner) => ErrorRecord {
            error_id: Uuid::now_v7(),
            task_ref: task_ref.to_string(),
            attempt_id,
            occurred_at_ms,
            source: ErrorSource::ProcessExit,
            wire_type: None,
            code: None,
            message: "process exited".into(),
            param: None,
            reason: event_kind.map(|kind| format!("{kind:?}")),
            http_status: None,
            exit_code: inner.exit_code,
            signal: inner.signal,
        },
        StructuredError::CaptureLost(inner) => ErrorRecord {
            error_id: Uuid::now_v7(),
            task_ref: task_ref.to_string(),
            attempt_id,
            occurred_at_ms,
            source: ErrorSource::CaptureGap,
            wire_type: None,
            code: None,
            message: inner.reason.clone(),
            param: None,
            reason: Some(inner.reason.clone()),
            http_status: None,
            exit_code: None,
            signal: None,
        },
        StructuredError::UnsupportedCodexBuild(inner) => ErrorRecord {
            error_id: Uuid::now_v7(),
            task_ref: task_ref.to_string(),
            attempt_id,
            occurred_at_ms,
            source: ErrorSource::UnsupportedCodexBuild,
            wire_type: None,
            code: Some(inner.executable_sha256.clone()),
            message: format!("unsupported build {}", inner.architecture),
            param: inner.codex_version.clone(),
            reason: None,
            http_status: None,
            exit_code: None,
            signal: None,
        },
    }
}

fn extract_http_status(error: Option<&StructuredError>) -> Option<u16> {
    match error {
        Some(StructuredError::Http(inner)) => Some(inner.status),
        _ => None,
    }
}

fn extract_process_exit(error: Option<&StructuredError>) -> (Option<i32>, Option<i32>) {
    match error {
        Some(StructuredError::ProcessTerminated(inner)) => (inner.exit_code, inner.signal),
        _ => (None, None),
    }
}

fn dedupe_errors(errors: Vec<ErrorRecord>) -> Vec<ErrorRecord> {
    let mut seen = BTreeSet::new();
    errors
        .into_iter()
        .filter(|error| seen.insert(error.error_id))
        .collect()
}

fn merge_unique(mut current: Vec<String>, appended: Vec<String>) -> Vec<String> {
    for value in appended {
        if !value.is_empty() && !current.iter().any(|item| item == &value) {
            current.push(value);
        }
    }
    current
}

fn is_priority_record(record: &SummaryRecord) -> bool {
    match record {
        SummaryRecord::CaptureGap(_) | SummaryRecord::Heartbeat(_) => true,
        SummaryRecord::Task(summary) => summary.outcome.is_some() || summary.last_error.is_some(),
        SummaryRecord::TaskTransition(transition) => {
            transition.phase == TaskPhase::Terminal || transition.error.is_some()
        }
        SummaryRecord::Attempt(attempt) => !matches!(attempt.status, AttemptStatus::Running),
        SummaryRecord::Process(process) => {
            process.signal.is_some() || process.exit_code.is_some_and(|code| code != 0)
        }
        SummaryRecord::Session(_) | SummaryRecord::HttpExchange(_) => false,
    }
}

fn content_part_name(part: ContentPart) -> &'static str {
    match part {
        ContentPart::Request => "request",
        ContentPart::Response => "response",
        ContentPart::ToolInput => "tool_input",
        ContentPart::ToolOutput => "tool_output",
        ContentPart::ModelText => "model_text",
    }
}

fn command_meta(command: &ClientCommand) -> Result<(Uuid, Option<i64>)> {
    Ok(match command {
        ClientCommand::RequestContent(ContentRequestCommand {
            command_id,
            request,
        }) => (*command_id, request.expires_at_ms),
    })
}

fn ts(value: OffsetDateTime) -> i64 {
    value.unix_timestamp() * 1000
}

fn from_ms(value: i64) -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(value) * 1_000_000)
        .expect("valid timestamp")
}

fn now_ms() -> i64 {
    ts(OffsetDateTime::now_utc())
}

fn backoff_delay(attempt_count: u32) -> Duration {
    let seconds = (2_u64.saturating_pow(attempt_count.min(10)) * 5).min(600);
    Duration::seconds(seconds as i64)
}
