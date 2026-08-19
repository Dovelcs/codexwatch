#![allow(
    clippy::cast_possible_truncation,
    clippy::default_trait_access,
    clippy::too_many_lines
)]

use std::{collections::BTreeMap, sync::Arc};

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
};
use codexwatch_client::{
    ClientConfig, ClientIngress, ClientService, StoredContentInput,
    model::{
        AttemptStatus, AttemptSummary, CaptureHealth, Completeness, HeartbeatSummary, ProviderId,
        SummaryRecord, TaskKey, TaskOutcome, TaskPhase, TaskSummary, TaskTransition,
        TransitionCause,
    },
};
use codexwatch_protocol::{
    self as wire, ClientCommand, CommandPollResponse, ContentPart, ContentRequest,
    ContentRequestCommand, ContentUploadResult, ContentUploadStatus, decode_batch_with_payload,
};
use serde::Deserialize;
use sqlx::SqlitePool;
use tempfile::TempDir;
use time::{Duration, OffsetDateTime};
use tokio::{net::TcpListener, sync::Mutex};
use uuid::Uuid;

#[derive(Debug, Default)]
struct ServerState {
    fail_ingest: bool,
    batches: Vec<wire::IngestBatch>,
    manifests: Vec<Vec<wire::ContentObjectManifest>>,
    chunks: usize,
    commands: Vec<ClientCommand>,
    results: Vec<ContentUploadResult>,
    paths: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct WaitQuery {
    wait: Option<u32>,
}

#[derive(Clone)]
struct SharedState(Arc<Mutex<ServerState>>);

async fn spawn_server(state: Arc<Mutex<ServerState>>) -> String {
    async fn ingest(
        State(state): State<SharedState>,
        headers: HeaderMap,
        body: bytes::Bytes,
    ) -> impl IntoResponse {
        let mut state = state.0.lock().await;
        state.paths.push("/api/v1/ingest".into());
        if state.fail_ingest {
            return StatusCode::BAD_GATEWAY.into_response();
        }
        let decoded = decode_batch_with_payload(&body).expect("decode batch");
        let ack = wire::IngestAck {
            batch_id: decoded.batch.batch_id,
            payload_sha256: headers
                .get("x-payload-sha256")
                .expect("sha header")
                .to_str()
                .expect("sha string")
                .to_string(),
            accepted_tasks: decoded.batch.tasks.len() as u32,
            accepted_heartbeats: decoded.batch.heartbeats.len() as u32,
            duplicate: false,
        };
        state.batches.push(decoded.batch);
        (StatusCode::OK, Json(ack)).into_response()
    }

    async fn next_commands(
        State(state): State<SharedState>,
        Query(query): Query<WaitQuery>,
    ) -> impl IntoResponse {
        let _ = query.wait;
        let mut state = state.0.lock().await;
        state.paths.push("/api/v1/client/commands/next".into());
        if state.commands.is_empty() {
            return StatusCode::NO_CONTENT.into_response();
        }
        let commands = std::mem::take(&mut state.commands);
        (
            StatusCode::OK,
            Json(CommandPollResponse {
                server_time_ms: OffsetDateTime::now_utc().unix_timestamp() * 1000,
                commands,
            }),
        )
            .into_response()
    }

    async fn upload_manifests(
        State(state): State<SharedState>,
        Path(_command_id): Path<String>,
        Json(manifests): Json<Vec<wire::ContentObjectManifest>>,
    ) -> impl IntoResponse {
        let mut state = state.0.lock().await;
        state
            .paths
            .push("/api/v1/client/commands/{command_id}/content/manifests".into());
        state.manifests.push(manifests);
        StatusCode::OK
    }

    async fn upload_chunk(
        State(state): State<SharedState>,
        Path(_command_id): Path<String>,
        Json(_chunk): Json<wire::ContentUploadChunk>,
    ) -> impl IntoResponse {
        let mut state = state.0.lock().await;
        state
            .paths
            .push("/api/v1/client/commands/{command_id}/content/chunks".into());
        state.chunks += 1;
        StatusCode::OK
    }

    async fn upload_result(
        State(state): State<SharedState>,
        Path(_command_id): Path<String>,
        Json(result): Json<ContentUploadResult>,
    ) -> impl IntoResponse {
        let mut state = state.0.lock().await;
        state
            .paths
            .push("/api/v1/client/commands/{command_id}/result".into());
        state.results.push(result);
        StatusCode::OK
    }

    let router = Router::new()
        .route("/api/v1/ingest", post(ingest))
        .route("/api/v1/client/commands/next", get(next_commands))
        .route(
            "/api/v1/client/commands/{command_id}/content/manifests",
            post(upload_manifests),
        )
        .route(
            "/api/v1/client/commands/{command_id}/content/chunks",
            post(upload_chunk),
        )
        .route(
            "/api/v1/client/commands/{command_id}/result",
            post(upload_result),
        )
        .with_state(SharedState(state));

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        axum::serve(listener, router).await.expect("serve");
    });
    format!("http://{addr}")
}

fn config(dir: &TempDir, server_url: String) -> ClientConfig {
    ClientConfig {
        client_id: "client-test".into(),
        client_instance_id: Uuid::now_v7(),
        data_dir: dir.path().join("data"),
        database_path: dir.path().join("data/client.db"),
        blob_dir: dir.path().join("data/blobs"),
        server_url,
        api_token: "token".into(),
        poll_wait_seconds: 0,
        cleanup_interval_seconds: 1,
        flush_interval_millis: 1_000,
        heartbeat_interval_seconds: 30,
        process_scan_interval_seconds: 30,
        capture_poll_interval_millis: 10,
        capture_interface_index: None,
        capture_codex_pid: None,
        capture_process_name: "codex".into(),
        capture_remote_ports: Vec::new(),
        ebpf_object_path: None,
        codex_binary_path: None,
        client_version: "0.1.0-test".into(),
    }
}

fn task_key() -> TaskKey {
    TaskKey {
        client_id: "client-test".into(),
        provider: ProviderId::new("openai"),
        session_id: "session-1".into(),
        thread_id: "thread-1".into(),
        turn_id: "turn-1".into(),
    }
}

fn task_summary(task: TaskKey, sequence: u64) -> TaskSummary {
    TaskSummary {
        task,
        phase: TaskPhase::Running,
        outcome: None,
        sequence,
        last_event_id: Uuid::now_v7(),
        started_at: OffsetDateTime::now_utc(),
        updated_at: OffsetDateTime::now_utc(),
        terminal_at: None,
        attempt_count: 1,
        model: Some("gpt-5".into()),
        tool_names: vec!["shell".into()],
        response_ids: vec!["resp_1".into()],
        usage: Default::default(),
        completeness: Completeness::Complete,
        last_error: None,
    }
}

#[tokio::test]
async fn retries_outbox_and_acks_after_recovery() {
    let state = Arc::new(Mutex::new(ServerState {
        fail_ingest: true,
        ..ServerState::default()
    }));
    let server_url = spawn_server(state.clone()).await;
    let dir = TempDir::new().expect("tmp");
    let cfg = config(&dir, server_url);
    let service = ClientService::open(cfg.clone()).await.expect("service");
    service
        .ingest(ClientIngress {
            records: vec![SummaryRecord::Task(task_summary(task_key(), 1))],
            contents: vec![],
        })
        .await
        .expect("ingest");
    service.flush_outbox_once().await.expect("retry");
    assert_eq!(
        service
            .store()
            .health_snapshot()
            .await
            .expect("health")
            .outbox_batches,
        1
    );

    state.lock().await.fail_ingest = false;
    let pool = SqlitePool::connect(&cfg.database_url())
        .await
        .expect("pool");
    sqlx::query("UPDATE outbox SET next_attempt_at = 0")
        .execute(&pool)
        .await
        .expect("reset retry");
    service.flush_outbox_once().await.expect("ack");
    assert_eq!(
        service
            .store()
            .health_snapshot()
            .await
            .expect("health")
            .outbox_batches,
        0
    );
    assert_eq!(state.lock().await.batches.len(), 1);
}

#[tokio::test]
async fn uploads_content_only_on_request() {
    let state = Arc::new(Mutex::new(ServerState::default()));
    let server_url = spawn_server(state.clone()).await;
    let dir = TempDir::new().expect("tmp");
    let service = ClientService::open(config(&dir, server_url))
        .await
        .expect("service");
    let task = task_key();
    let raw_body = b"unique raw prompt body".to_vec();
    service
        .ingest(ClientIngress {
            records: vec![
                SummaryRecord::Task(task_summary(task.clone(), 1)),
                SummaryRecord::Attempt(AttemptSummary {
                    attempt_id: Uuid::now_v7(),
                    task: task.clone(),
                    ordinal: 1,
                    status: AttemptStatus::Completed,
                    started_at: OffsetDateTime::now_utc(),
                    finished_at: Some(OffsetDateTime::now_utc()),
                    response_id: Some("resp_1".into()),
                    model: Some("gpt-5".into()),
                    tool_names: vec![],
                    usage: Default::default(),
                    completeness: Completeness::Complete,
                    error: None,
                }),
            ],
            contents: vec![StoredContentInput {
                task: task.clone(),
                part: ContentPart::Request,
                media_type: "application/json".into(),
                body: raw_body.clone(),
                headers: BTreeMap::from([("authorization".into(), "secret".into())]),
                created_at: OffsetDateTime::now_utc(),
            }],
        })
        .await
        .expect("persist");

    let pending = service
        .store()
        .next_due_batch(OffsetDateTime::now_utc())
        .await
        .expect("pending")
        .expect("batch");
    let decoded = decode_batch_with_payload(&pending.body).expect("decode");
    let batch_json = serde_json::to_string(&decoded.batch).expect("json");
    assert!(!batch_json.contains("unique raw prompt body"));
    assert_eq!(state.lock().await.manifests.len(), 0);

    let request_id = Uuid::now_v7();
    state
        .lock()
        .await
        .commands
        .push(ClientCommand::RequestContent(ContentRequestCommand {
            command_id: Uuid::now_v7(),
            request: ContentRequest {
                request_id,
                client_id: "client-test".into(),
                task_ref: task.task_ref(),
                session_id: task.session_id.clone(),
                thread_id: task.thread_id.clone(),
                created_at_ms: OffsetDateTime::now_utc().unix_timestamp() * 1000,
                expires_at_ms: Some(
                    (OffsetDateTime::now_utc() + Duration::minutes(5)).unix_timestamp() * 1000,
                ),
                parts: vec![ContentPart::Request],
            },
        }));
    service.poll_command_once().await.expect("poll");
    service.execute_due_command_once().await.expect("upload");

    let state = state.lock().await;
    assert_eq!(state.manifests.len(), 1);
    assert_eq!(state.results.len(), 1);
    assert_eq!(state.results[0].request_id, request_id);
    assert_eq!(state.results[0].status, ContentUploadStatus::Stored);
    assert!(state.chunks >= 1);
    assert!(
        state
            .paths
            .iter()
            .any(|path| path == "/api/v1/client/commands/{command_id}/content/manifests")
    );
}

#[tokio::test]
async fn cleans_expired_content_and_keeps_pinned_until_completion() {
    let state = Arc::new(Mutex::new(ServerState::default()));
    let server_url = spawn_server(state.clone()).await;
    let dir = TempDir::new().expect("tmp");
    let cfg = config(&dir, server_url);
    let service = ClientService::open(cfg.clone()).await.expect("service");
    let task = task_key();

    service
        .ingest(ClientIngress {
            records: vec![SummaryRecord::Task(task_summary(task.clone(), 1))],
            contents: vec![StoredContentInput {
                task: task.clone(),
                part: ContentPart::Response,
                media_type: "application/json".into(),
                body: b"old".to_vec(),
                headers: BTreeMap::new(),
                created_at: OffsetDateTime::now_utc() - Duration::hours(73),
            }],
        })
        .await
        .expect("persist");
    service.cleanup_once().await.expect("cleanup");
    assert_eq!(
        service
            .store()
            .health_snapshot()
            .await
            .expect("health")
            .raw_objects,
        0
    );

    service
        .ingest(ClientIngress {
            records: vec![SummaryRecord::Task(task_summary(task.clone(), 2))],
            contents: vec![StoredContentInput {
                task: task.clone(),
                part: ContentPart::Response,
                media_type: "application/json".into(),
                body: b"fresh".to_vec(),
                headers: BTreeMap::new(),
                created_at: OffsetDateTime::now_utc(),
            }],
        })
        .await
        .expect("persist fresh");

    let command_id = Uuid::now_v7();
    service
        .store()
        .save_commands(&CommandPollResponse {
            server_time_ms: 0,
            commands: vec![ClientCommand::RequestContent(ContentRequestCommand {
                command_id,
                request: ContentRequest {
                    request_id: Uuid::now_v7(),
                    client_id: "client-test".into(),
                    task_ref: task.task_ref(),
                    session_id: task.session_id.clone(),
                    thread_id: task.thread_id.clone(),
                    created_at_ms: OffsetDateTime::now_utc().unix_timestamp() * 1000,
                    expires_at_ms: Some(
                        (OffsetDateTime::now_utc() + Duration::minutes(5)).unix_timestamp() * 1000,
                    ),
                    parts: vec![ContentPart::Response],
                },
            })],
        })
        .await
        .expect("save command");

    let preparation = service
        .store()
        .prepare_upload(&ClientCommand::RequestContent(ContentRequestCommand {
            command_id,
            request: ContentRequest {
                request_id: Uuid::now_v7(),
                client_id: "client-test".into(),
                task_ref: task.task_ref(),
                session_id: task.session_id.clone(),
                thread_id: task.thread_id.clone(),
                created_at_ms: OffsetDateTime::now_utc().unix_timestamp() * 1000,
                expires_at_ms: Some(
                    (OffsetDateTime::now_utc() + Duration::minutes(5)).unix_timestamp() * 1000,
                ),
                parts: vec![ContentPart::Response],
            },
        }))
        .await
        .expect("prepare");
    assert!(matches!(
        preparation,
        codexwatch_client::store::UploadPreparation::Ready(_)
    ));

    let pool = SqlitePool::connect(&cfg.database_url())
        .await
        .expect("pool");
    sqlx::query("UPDATE raw_objects SET expires_at = ?")
        .bind((OffsetDateTime::now_utc() - Duration::minutes(1)).unix_timestamp() * 1000)
        .execute(&pool)
        .await
        .expect("expire");
    service.cleanup_once().await.expect("cleanup pinned");
    assert_eq!(
        service
            .store()
            .health_snapshot()
            .await
            .expect("health")
            .raw_objects,
        1
    );
}

#[tokio::test]
async fn marks_expired_content_requests() {
    let state = Arc::new(Mutex::new(ServerState::default()));
    let server_url = spawn_server(state.clone()).await;
    let dir = TempDir::new().expect("tmp");
    let service = ClientService::open(config(&dir, server_url))
        .await
        .expect("service");
    let task = task_key();
    state
        .lock()
        .await
        .commands
        .push(ClientCommand::RequestContent(ContentRequestCommand {
            command_id: Uuid::now_v7(),
            request: ContentRequest {
                request_id: Uuid::now_v7(),
                client_id: "client-test".into(),
                task_ref: task.task_ref(),
                session_id: task.session_id.clone(),
                thread_id: task.thread_id.clone(),
                created_at_ms: OffsetDateTime::now_utc().unix_timestamp() * 1000,
                expires_at_ms: Some(
                    (OffsetDateTime::now_utc() - Duration::minutes(1)).unix_timestamp() * 1000,
                ),
                parts: vec![ContentPart::Request],
            },
        }));
    service.poll_command_once().await.expect("poll");
    service.execute_due_command_once().await.expect("execute");
    let state = state.lock().await;
    assert_eq!(state.results.len(), 1);
    assert_eq!(state.results[0].status, ContentUploadStatus::ContentExpired);
}

#[tokio::test]
async fn survives_reopen_with_pending_terminal_batch() {
    let state = Arc::new(Mutex::new(ServerState::default()));
    let server_url = spawn_server(state.clone()).await;
    let dir = TempDir::new().expect("tmp");
    let cfg = config(&dir, server_url);
    let service = ClientService::open(cfg.clone()).await.expect("service");
    let task = task_key();
    service
        .ingest(ClientIngress {
            records: vec![
                SummaryRecord::Task(task_summary(task.clone(), 1)),
                SummaryRecord::TaskTransition(TaskTransition {
                    event_id: Uuid::now_v7(),
                    task,
                    sequence: 2,
                    observed_at: OffsetDateTime::now_utc(),
                    phase: TaskPhase::Terminal,
                    outcome: Some(TaskOutcome::Completed),
                    cause: TransitionCause::CodexTurnComplete,
                    completeness: Completeness::Complete,
                    error: None,
                }),
                SummaryRecord::Heartbeat(HeartbeatSummary {
                    client_instance_id: cfg.client_instance_id,
                    observed_at: OffsetDateTime::now_utc(),
                    client_version: cfg.client_version.clone(),
                    health: CaptureHealth {
                        af_packet_active: true,
                        uprobe_active: false,
                        profile_supported: true,
                        ring_buffer_drops: 0,
                        active_flows: 1,
                        outbox_bytes: 0,
                        last_error: None,
                    },
                }),
            ],
            contents: vec![],
        })
        .await
        .expect("persist");
    drop(service);
    let reopened = ClientService::open(cfg).await.expect("reopen");
    reopened.flush_outbox_once().await.expect("flush");
    assert_eq!(state.lock().await.batches.len(), 1);
}
