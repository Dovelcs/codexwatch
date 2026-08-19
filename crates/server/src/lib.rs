#![allow(
    clippy::cast_possible_wrap,
    clippy::cast_possible_truncation,
    clippy::duration_suboptimal_units,
    clippy::missing_errors_doc,
    clippy::needless_pass_by_value,
    clippy::too_many_arguments,
    clippy::too_many_lines
)]

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use anyhow::{Context, Result};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path as AxumPath, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
};
use clap::{Args, Parser, Subcommand, ValueEnum};
use codexwatch_protocol::{
    AttemptRecord, CaptureGapRecord, CaptureHealthResponse, ClientCommand, CommandPollResponse,
    ContentObjectManifest, ContentRequest, ContentRequestCommand, ContentUploadChunk,
    ContentUploadResult, ContentUploadStatus, ErrorListResponse, ErrorRecord, EventListResponse,
    Heartbeat, IngestAck, IngestBatch, IntegrityState, SessionDetail, TaskDetail, TaskEvent,
    TaskListQuery, TaskListResponse, TaskSnapshot, TaskUpload, Validate, decode_batch_with_payload,
    sha256_hex,
};
use sqlx::{
    Row, SqlitePool,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions},
};
use tokio::time::Instant;
use tracing::{info, warn};
use uuid::Uuid;

const CONTENT_CONVERSATION_LIMIT: i64 = 30;
const HEARTBEAT_RETENTION_MS: i64 = 30 * 24 * 60 * 60 * 1000;
const EPHEMERA_RETENTION_MS: i64 = 180 * 24 * 60 * 60 * 1000;
const RECEIPT_RETENTION_MS: i64 = 400 * 24 * 60 * 60 * 1000;

#[derive(Debug, Parser)]
#[command(name = "codexwatch-server")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Serve(ServeArgs),
    IssueToken(IssueTokenArgs),
    RevokeToken(RevokeTokenArgs),
    Tasks(ListArgs),
    Session(SessionArgs),
    Task(TaskArgs),
    Attempts(TaskArgs),
    Events(TaskArgs),
    Errors(TaskArgs),
    CaptureHealth(CaptureHealthArgs),
    RequestContent(RequestContentArgs),
    Cleanup(CleanupArgs),
}

#[derive(Debug, Args)]
pub struct ServeArgs {
    #[arg(long, default_value = "127.0.0.1:18080")]
    pub listen: SocketAddr,
    #[arg(long, default_value = "server.db")]
    pub db: PathBuf,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum TokenRoleArg {
    Client,
    Reader,
    Admin,
}

#[derive(Debug, Args)]
pub struct IssueTokenArgs {
    #[arg(long, default_value = "server.db")]
    pub db: PathBuf,
    #[arg(long)]
    pub client_id: String,
    #[arg(long)]
    pub token: String,
    #[arg(long)]
    pub role: Option<TokenRoleArg>,
    #[arg(long, default_value_t = false)]
    pub admin: bool,
}

#[derive(Debug, Args)]
pub struct RevokeTokenArgs {
    #[arg(long, default_value = "server.db")]
    pub db: PathBuf,
    #[arg(long)]
    pub token: String,
}

#[derive(Debug, Args)]
pub struct ListArgs {
    #[arg(long, default_value = "server.db")]
    pub db: PathBuf,
    #[arg(long)]
    pub client_id: Option<String>,
    #[arg(long)]
    pub provider: Option<String>,
    #[arg(long)]
    pub session_id: Option<String>,
    #[arg(long)]
    pub limit: Option<u32>,
}

#[derive(Debug, Args)]
pub struct TaskArgs {
    #[arg(long, default_value = "server.db")]
    pub db: PathBuf,
    #[arg(long)]
    pub task_ref: String,
}

#[derive(Debug, Args)]
pub struct CaptureHealthArgs {
    #[arg(long, default_value = "server.db")]
    pub db: PathBuf,
    #[arg(long)]
    pub client_id: String,
}

#[derive(Debug, Args)]
pub struct SessionArgs {
    #[arg(long, default_value = "server.db")]
    pub db: PathBuf,
    #[arg(long)]
    pub client_id: String,
    #[arg(long)]
    pub session_id: String,
    #[arg(long)]
    pub provider: Option<String>,
    #[arg(long)]
    pub thread_id: Option<String>,
}

#[derive(Debug, Args)]
pub struct RequestContentArgs {
    #[arg(long, default_value = "server.db")]
    pub db: PathBuf,
    #[arg(long)]
    pub task_ref: String,
    #[arg(long, required = true)]
    pub parts: Vec<String>,
    #[arg(long)]
    pub expires_at_ms: Option<i64>,
}

#[derive(Debug, Args)]
pub struct CleanupArgs {
    #[arg(long, default_value = "server.db")]
    pub db: PathBuf,
    #[arg(long)]
    pub now_ms: Option<i64>,
}

#[derive(Clone)]
struct AppState {
    pool: SqlitePool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TokenRole {
    Client,
    Reader,
    Admin,
}

impl From<TokenRoleArg> for TokenRole {
    fn from(value: TokenRoleArg) -> Self {
        match value {
            TokenRoleArg::Client => Self::Client,
            TokenRoleArg::Reader => Self::Reader,
            TokenRoleArg::Admin => Self::Admin,
        }
    }
}

impl TokenRole {
    fn as_str(self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::Reader => "reader",
            Self::Admin => "admin",
        }
    }

    fn from_db(value: &str) -> Option<Self> {
        match value {
            "client" => Some(Self::Client),
            "reader" => Some(Self::Reader),
            "admin" => Some(Self::Admin),
            _ => None,
        }
    }

    fn can_ingest(self) -> bool {
        matches!(self, Self::Client)
    }

    fn can_query(self) -> bool {
        matches!(self, Self::Reader | Self::Admin)
    }

    fn is_admin(self) -> bool {
        matches!(self, Self::Admin)
    }
}

#[derive(Debug, Clone)]
struct Principal {
    client_id: String,
    role: TokenRole,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct CreateContentRequestBody {
    parts: Vec<codexwatch_protocol::ContentPart>,
    expires_at_ms: Option<i64>,
}

#[derive(Debug, serde::Serialize)]
struct ConflictBody {
    error: &'static str,
    detail: String,
}

#[derive(Debug, serde::Serialize)]
struct SimpleOk {
    ok: bool,
}

#[derive(Debug, serde::Deserialize)]
struct SessionQuery {
    provider: Option<String>,
    thread_id: Option<String>,
}

#[derive(Debug, Clone)]
struct StoredContentRequest {
    request: ContentRequest,
}

#[derive(Debug, Clone)]
struct StoredConversation {
    session_id: String,
    thread_id: String,
}

pub async fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Serve(args) => serve(args).await,
        Command::IssueToken(args) => issue_token(args).await,
        Command::RevokeToken(args) => revoke_token(args).await,
        Command::Tasks(args) => list_tasks_cli(args).await,
        Command::Session(args) => session_cli(args).await,
        Command::Task(args) => task_cli(args).await,
        Command::Attempts(args) => attempts_cli(args).await,
        Command::Events(args) => events_cli(args).await,
        Command::Errors(args) => errors_cli(args).await,
        Command::CaptureHealth(args) => capture_health_cli(args).await,
        Command::RequestContent(args) => request_content_cli(args).await,
        Command::Cleanup(args) => cleanup_cli(args).await,
    }
}

async fn serve(args: ServeArgs) -> Result<()> {
    let pool = open_pool(&args.db).await?;
    migrate(&pool).await?;
    cleanup_retention(&pool, now_ms()).await?;
    spawn_retention_task(pool.clone());
    let app = build_router(AppState { pool });

    info!("listening on {}", args.listen);
    let listener = tokio::net::TcpListener::bind(args.listen).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/api/v1/ingest", post(ingest))
        .route("/api/v1/client/commands/next", get(next_command))
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
        .route("/api/v1/tasks", get(list_tasks))
        .route("/api/v1/tasks/{task_ref}", get(task_detail))
        .route("/api/v1/tasks/{task_ref}/attempts", get(task_attempts))
        .route("/api/v1/tasks/{task_ref}/events", get(task_events))
        .route("/api/v1/tasks/{task_ref}/errors", get(task_errors))
        .route(
            "/api/v1/sessions/{client_id}/{session_id}",
            get(session_detail),
        )
        .route(
            "/api/v1/tasks/{task_ref}/content-requests",
            post(create_content_request),
        )
        .route("/api/v1/capture-health/{client_id}", get(capture_health))
        .with_state(state)
}

async fn healthz(State(state): State<AppState>) -> Result<Json<SimpleOk>, StatusCode> {
    sqlx::query_scalar::<_, i64>("SELECT 1")
        .fetch_one(&state.pool)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    Ok(Json(SimpleOk { ok: true }))
}

async fn issue_token(args: IssueTokenArgs) -> Result<()> {
    let pool = open_pool(&args.db).await?;
    migrate(&pool).await?;
    let role = if args.admin {
        TokenRole::Admin
    } else {
        args.role.unwrap_or(TokenRoleArg::Client).into()
    };
    ensure_client_exists(&pool, &args.client_id, now_ms()).await?;
    upsert_token(&pool, &args.client_id, &args.token, role).await?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "client_id": args.client_id,
            "role": role.as_str(),
            "token_sha256": hash_token(&args.token),
        }))?
    );
    Ok(())
}

async fn revoke_token(args: RevokeTokenArgs) -> Result<()> {
    let pool = open_pool(&args.db).await?;
    migrate(&pool).await?;
    sqlx::query("UPDATE api_tokens SET revoked_at_ms=?2 WHERE token_hash=?1")
        .bind(hash_token(&args.token))
        .bind(now_ms())
        .execute(&pool)
        .await?;
    println!("{}", serde_json::to_string_pretty(&SimpleOk { ok: true })?);
    Ok(())
}

async fn list_tasks_cli(args: ListArgs) -> Result<()> {
    let pool = open_pool(&args.db).await?;
    migrate(&pool).await?;
    let response = list_tasks_inner(
        &pool,
        Principal {
            client_id: args.client_id.clone().unwrap_or_else(|| "cli".to_owned()),
            role: TokenRole::Admin,
        },
        TaskListQuery {
            client_id: args.client_id,
            provider: args.provider,
            session_id: args.session_id,
            phase: None,
            terminal: None,
            cursor: None,
            limit: args.limit.or(Some(100)),
        },
    )
    .await
    .map_err(|status| anyhow::anyhow!("list tasks failed: {status}"))?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

async fn session_cli(args: SessionArgs) -> Result<()> {
    let pool = open_pool(&args.db).await?;
    migrate(&pool).await?;
    let detail = session_detail_inner(
        &pool,
        Principal {
            client_id: args.client_id.clone(),
            role: TokenRole::Admin,
        },
        &args.client_id,
        &args.session_id,
        SessionQuery {
            provider: args.provider,
            thread_id: args.thread_id,
        },
    )
    .await
    .map_err(|status| anyhow::anyhow!("session detail failed: {status}"))?;
    println!("{}", serde_json::to_string_pretty(&detail)?);
    Ok(())
}

async fn task_cli(args: TaskArgs) -> Result<()> {
    let pool = open_pool(&args.db).await?;
    migrate(&pool).await?;
    let detail = task_detail_inner(
        &pool,
        Principal {
            client_id: "cli".to_owned(),
            role: TokenRole::Admin,
        },
        &args.task_ref,
    )
    .await
    .map_err(|status| anyhow::anyhow!("task detail failed: {status}"))?;
    println!("{}", serde_json::to_string_pretty(&detail)?);
    Ok(())
}

async fn attempts_cli(args: TaskArgs) -> Result<()> {
    let pool = open_pool(&args.db).await?;
    migrate(&pool).await?;
    let attempts = task_attempts_inner(
        &pool,
        Principal {
            client_id: "cli".to_owned(),
            role: TokenRole::Admin,
        },
        &args.task_ref,
    )
    .await
    .map_err(|status| anyhow::anyhow!("task attempts failed: {status}"))?;
    println!("{}", serde_json::to_string_pretty(&attempts)?);
    Ok(())
}

async fn events_cli(args: TaskArgs) -> Result<()> {
    let pool = open_pool(&args.db).await?;
    migrate(&pool).await?;
    let events = task_events_inner(
        &pool,
        Principal {
            client_id: "cli".to_owned(),
            role: TokenRole::Admin,
        },
        &args.task_ref,
    )
    .await
    .map_err(|status| anyhow::anyhow!("task events failed: {status}"))?;
    println!("{}", serde_json::to_string_pretty(&events)?);
    Ok(())
}

async fn errors_cli(args: TaskArgs) -> Result<()> {
    let pool = open_pool(&args.db).await?;
    migrate(&pool).await?;
    let errors = task_errors_inner(
        &pool,
        Principal {
            client_id: "cli".to_owned(),
            role: TokenRole::Admin,
        },
        &args.task_ref,
    )
    .await
    .map_err(|status| anyhow::anyhow!("task errors failed: {status}"))?;
    println!("{}", serde_json::to_string_pretty(&errors)?);
    Ok(())
}

async fn capture_health_cli(args: CaptureHealthArgs) -> Result<()> {
    let pool = open_pool(&args.db).await?;
    migrate(&pool).await?;
    let response = capture_health_inner(
        &pool,
        Principal {
            client_id: "cli".to_owned(),
            role: TokenRole::Admin,
        },
        &args.client_id,
    )
    .await
    .map_err(|status| anyhow::anyhow!("capture health failed: {status}"))?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

async fn request_content_cli(args: RequestContentArgs) -> Result<()> {
    let pool = open_pool(&args.db).await?;
    migrate(&pool).await?;
    let parts = args
        .parts
        .into_iter()
        .map(parse_content_part)
        .collect::<Result<Vec<_>>>()?;
    create_content_request_inner(
        &pool,
        Principal {
            client_id: "cli".to_owned(),
            role: TokenRole::Admin,
        },
        &args.task_ref,
        parts,
        args.expires_at_ms,
    )
    .await
    .map_err(|status| anyhow::anyhow!("request content failed: {status}"))?;
    println!("{}", serde_json::to_string_pretty(&SimpleOk { ok: true })?);
    Ok(())
}

async fn cleanup_cli(args: CleanupArgs) -> Result<()> {
    let pool = open_pool(&args.db).await?;
    migrate(&pool).await?;
    cleanup_retention(&pool, args.now_ms.unwrap_or_else(now_ms)).await?;
    println!("{}", serde_json::to_string_pretty(&SimpleOk { ok: true })?);
    Ok(())
}

async fn ingest(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, StatusCode> {
    let principal = authorize(&state.pool, &headers).await?;
    ensure_client_role(&principal)?;

    let decoded = match decode_batch_with_payload(&body) {
        Ok(decoded) => decoded,
        Err(codexwatch_protocol::CodecError::PayloadTooLarge) => {
            return Err(StatusCode::PAYLOAD_TOO_LARGE);
        }
        Err(_) => return Err(StatusCode::BAD_REQUEST),
    };
    if decoded.batch.client.client_id != principal.client_id {
        return Err(StatusCode::FORBIDDEN);
    }

    let mut tx = state.pool.begin().await.map_err(internal_error)?;
    let existing = sqlx::query(
        "SELECT payload_sha256 FROM ingest_receipts WHERE client_id=?1 AND batch_id=?2",
    )
    .bind(&principal.client_id)
    .bind(decoded.batch.batch_id.to_string())
    .fetch_optional(&mut *tx)
    .await
    .map_err(internal_error)?;
    if let Some(row) = existing {
        let payload_sha256: String = row.get("payload_sha256");
        if payload_sha256 != decoded.payload_sha256 {
            return Ok((
                StatusCode::CONFLICT,
                Json(ConflictBody {
                    error: "ingest_conflict",
                    detail: format!(
                        "batch_id {} reused with different payload",
                        decoded.batch.batch_id
                    ),
                }),
            )
                .into_response());
        }
        return Ok((
            StatusCode::OK,
            Json(IngestAck {
                batch_id: decoded.batch.batch_id,
                payload_sha256,
                accepted_tasks: 0,
                accepted_heartbeats: 0,
                duplicate: true,
            }),
        )
            .into_response());
    }

    persist_client(&mut tx, &decoded.batch)
        .await
        .map_err(internal_error)?;
    for task in &decoded.batch.tasks {
        persist_task_upload(&mut tx, &decoded.batch.client.client_id, task)
            .await
            .map_err(internal_error)?;
    }
    for heartbeat in &decoded.batch.heartbeats {
        persist_heartbeat(&mut tx, heartbeat)
            .await
            .map_err(internal_error)?;
    }
    sqlx::query(
        "INSERT INTO ingest_receipts(client_id, batch_id, payload_sha256, received_at_ms)
         VALUES(?1, ?2, ?3, ?4)",
    )
    .bind(&principal.client_id)
    .bind(decoded.batch.batch_id.to_string())
    .bind(&decoded.payload_sha256)
    .bind(now_ms())
    .execute(&mut *tx)
    .await
    .map_err(internal_error)?;
    tx.commit().await.map_err(internal_error)?;

    Ok((
        StatusCode::OK,
        Json(IngestAck {
            batch_id: decoded.batch.batch_id,
            payload_sha256: decoded.payload_sha256,
            accepted_tasks: decoded.batch.tasks.len() as u32,
            accepted_heartbeats: decoded.batch.heartbeats.len() as u32,
            duplicate: false,
        }),
    )
        .into_response())
}

async fn next_command(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<BTreeMap<String, String>>,
) -> Result<Json<CommandPollResponse>, StatusCode> {
    let principal = authorize(&state.pool, &headers).await?;
    ensure_client_role(&principal)?;

    let wait_seconds = params
        .get("wait")
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0)
        .min(30);
    let deadline = Instant::now() + Duration::from_secs(wait_seconds);

    loop {
        let mut tx = state.pool.begin().await.map_err(internal_error)?;
        let rows = sqlx::query(
            "SELECT command_id, payload_json FROM commands
             WHERE client_id=?1 AND status='pending'
             ORDER BY created_at_ms ASC
             LIMIT 16",
        )
        .bind(&principal.client_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(internal_error)?;
        if !rows.is_empty() {
            let mut commands = Vec::with_capacity(rows.len());
            for row in &rows {
                commands.push(
                    serde_json::from_str::<ClientCommand>(&row.get::<String, _>("payload_json"))
                        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
                );
            }
            for row in rows {
                sqlx::query(
                    "UPDATE commands SET status='dispatched', delivered_at_ms=?2 WHERE command_id=?1",
                )
                .bind(row.get::<String, _>("command_id"))
                .bind(now_ms())
                .execute(&mut *tx)
                .await
                .map_err(internal_error)?;
            }
            tx.commit().await.map_err(internal_error)?;
            return Ok(Json(CommandPollResponse {
                server_time_ms: now_ms(),
                commands,
            }));
        }
        tx.rollback().await.ok();

        if Instant::now() >= deadline {
            return Ok(Json(CommandPollResponse {
                server_time_ms: now_ms(),
                commands: Vec::new(),
            }));
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

async fn upload_chunk(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(command_id): AxumPath<Uuid>,
    Json(chunk): Json<ContentUploadChunk>,
) -> Result<Json<ContentUploadResult>, StatusCode> {
    let principal = authorize(&state.pool, &headers).await?;
    ensure_client_role(&principal)?;
    chunk.validate().map_err(|_| StatusCode::BAD_REQUEST)?;

    let mut tx = state.pool.begin().await.map_err(internal_error)?;
    let Some(stored_request) = load_command_request(&mut tx, command_id, &principal.client_id)
        .await
        .map_err(internal_error)?
    else {
        return Err(StatusCode::NOT_FOUND);
    };
    if stored_request.request.request_id != chunk.request_id {
        return Err(StatusCode::FORBIDDEN);
    }

    let now = now_ms();
    if stored_request
        .request
        .expires_at_ms
        .is_some_and(|expires| expires <= now)
    {
        complete_request_and_command(
            &mut tx,
            stored_request.request.request_id,
            "content_expired",
            "content_expired",
            now,
        )
        .await
        .map_err(internal_error)?;
        tx.commit().await.map_err(internal_error)?;
        return Ok(Json(ContentUploadResult {
            request_id: stored_request.request.request_id,
            status: ContentUploadStatus::ContentExpired,
            note: Some("content_expired".to_owned()),
        }));
    }

    let Some(manifest) = load_manifest(
        &mut tx,
        stored_request.request.request_id,
        &chunk.object_sha256,
    )
    .await
    .map_err(internal_error)?
    else {
        return Err(StatusCode::CONFLICT);
    };
    if manifest.chunk_count != chunk.chunk_count {
        return Err(StatusCode::CONFLICT);
    }

    let duplicate = upsert_chunk_row(&mut tx, &chunk, now).await?;
    let response = if is_object_complete(
        &mut tx,
        chunk.request_id,
        &chunk.object_sha256,
        chunk.chunk_count,
    )
    .await
    .map_err(internal_error)?
    {
        let assembled = assemble_object(
            &mut tx,
            chunk.request_id,
            &chunk.object_sha256,
            chunk.chunk_count,
        )
        .await?;
        let uncompressed =
            zstd::stream::decode_all(assembled.as_slice()).map_err(|_| StatusCode::BAD_REQUEST)?;
        if sha256_hex(&uncompressed) != chunk.object_sha256.to_ascii_lowercase() {
            return Err(StatusCode::BAD_REQUEST);
        }
        if assembled.len() as u64 != manifest.compressed_bytes
            || uncompressed.len() as u64 != manifest.uncompressed_bytes
        {
            return Err(StatusCode::BAD_REQUEST);
        }

        let _manifest = upsert_content_object(
            &mut tx,
            &stored_request.request,
            &manifest,
            &assembled,
            &uncompressed,
            now,
        )
        .await
        .map_err(internal_error)?;

        touch_conversation(
            &mut tx,
            &stored_request.request.client_id,
            &stored_request.request.session_id,
            &stored_request.request.thread_id,
            now,
        )
        .await
        .map_err(internal_error)?;

        if linked_object_count(&mut tx, stored_request.request.request_id)
            .await
            .map_err(internal_error)?
            >= stored_request.request.parts.len() as i64
        {
            complete_request_and_command(
                &mut tx,
                stored_request.request.request_id,
                "stored",
                "stored",
                now,
            )
            .await
            .map_err(internal_error)?;
        } else {
            sqlx::query("UPDATE content_requests SET status='partial_upload' WHERE request_id=?1")
                .bind(stored_request.request.request_id.to_string())
                .execute(&mut *tx)
                .await
                .map_err(internal_error)?;
        }

        ContentUploadResult {
            request_id: chunk.request_id,
            status: ContentUploadStatus::Stored,
            note: if duplicate {
                Some("duplicate_chunk_stored".to_owned())
            } else {
                None
            },
        }
    } else {
        ContentUploadResult {
            request_id: chunk.request_id,
            status: ContentUploadStatus::Stored,
            note: Some(if duplicate {
                "duplicate_chunk".to_owned()
            } else {
                "partial_upload".to_owned()
            }),
        }
    };

    tx.commit().await.map_err(internal_error)?;
    Ok(Json(response))
}

async fn upload_result(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(command_id): AxumPath<Uuid>,
    Json(result): Json<ContentUploadResult>,
) -> Result<Json<SimpleOk>, StatusCode> {
    let principal = authorize(&state.pool, &headers).await?;
    ensure_client_role(&principal)?;

    let mut tx = state.pool.begin().await.map_err(internal_error)?;
    let Some(stored_request) = load_command_request(&mut tx, command_id, &principal.client_id)
        .await
        .map_err(internal_error)?
    else {
        return Err(StatusCode::NOT_FOUND);
    };
    if stored_request.request.request_id != result.request_id {
        return Err(StatusCode::FORBIDDEN);
    }
    let (status, outcome) = match result.status {
        ContentUploadStatus::Stored => ("stored", "stored"),
        ContentUploadStatus::ContentExpired => ("content_expired", "content_expired"),
        ContentUploadStatus::Rejected => ("rejected", "rejected"),
    };
    complete_request_and_command(&mut tx, result.request_id, status, outcome, now_ms())
        .await
        .map_err(internal_error)?;
    tx.commit().await.map_err(internal_error)?;
    Ok(Json(SimpleOk { ok: true }))
}

async fn upload_manifests(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(command_id): AxumPath<Uuid>,
    Json(manifests): Json<Vec<ContentObjectManifest>>,
) -> Result<Json<SimpleOk>, StatusCode> {
    let principal = authorize(&state.pool, &headers).await?;
    ensure_client_role(&principal)?;

    let mut tx = state.pool.begin().await.map_err(internal_error)?;
    let Some(stored_request) = load_command_request(&mut tx, command_id, &principal.client_id)
        .await
        .map_err(internal_error)?
    else {
        return Err(StatusCode::NOT_FOUND);
    };
    if manifests.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let now = now_ms();
    if stored_request
        .request
        .expires_at_ms
        .is_some_and(|expires| expires <= now)
    {
        complete_request_and_command(
            &mut tx,
            stored_request.request.request_id,
            "content_expired",
            "content_expired",
            now,
        )
        .await
        .map_err(internal_error)?;
        tx.commit().await.map_err(internal_error)?;
        return Ok(Json(SimpleOk { ok: true }));
    }

    for manifest in &manifests {
        manifest.validate().map_err(|_| StatusCode::BAD_REQUEST)?;
        if manifest.request_id != stored_request.request.request_id
            || manifest.task_ref != stored_request.request.task_ref
            || manifest.session_id != stored_request.request.session_id
            || manifest.thread_id != stored_request.request.thread_id
            || !stored_request.request.parts.contains(&manifest.part)
        {
            return Err(StatusCode::FORBIDDEN);
        }
        persist_manifest_row(&mut tx, manifest, &stored_request.request.client_id, now)
            .await
            .map_err(map_manifest_error)?;
    }

    tx.commit().await.map_err(internal_error)?;
    Ok(Json(SimpleOk { ok: true }))
}

async fn create_content_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(task_ref): AxumPath<String>,
    Json(body): Json<CreateContentRequestBody>,
) -> Result<Json<SimpleOk>, StatusCode> {
    let principal = authorize(&state.pool, &headers).await?;
    create_content_request_inner(
        &state.pool,
        principal,
        &task_ref,
        body.parts,
        body.expires_at_ms,
    )
    .await?;
    Ok(Json(SimpleOk { ok: true }))
}

async fn list_tasks(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<TaskListQuery>,
) -> Result<Json<TaskListResponse>, StatusCode> {
    let principal = authorize(&state.pool, &headers).await?;
    let response = list_tasks_inner(&state.pool, principal, query).await?;
    Ok(Json(response))
}

async fn task_detail(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(task_ref): AxumPath<String>,
) -> Result<Json<TaskDetail>, StatusCode> {
    let principal = authorize(&state.pool, &headers).await?;
    let detail = task_detail_inner(&state.pool, principal, &task_ref).await?;
    Ok(Json(detail))
}

async fn task_attempts(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(task_ref): AxumPath<String>,
) -> Result<Json<Vec<AttemptRecord>>, StatusCode> {
    let principal = authorize(&state.pool, &headers).await?;
    let attempts = task_attempts_inner(&state.pool, principal, &task_ref).await?;
    Ok(Json(attempts))
}

async fn task_events(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(task_ref): AxumPath<String>,
) -> Result<Json<EventListResponse>, StatusCode> {
    let principal = authorize(&state.pool, &headers).await?;
    let response = task_events_inner(&state.pool, principal, &task_ref).await?;
    Ok(Json(response))
}

async fn task_errors(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(task_ref): AxumPath<String>,
) -> Result<Json<ErrorListResponse>, StatusCode> {
    let principal = authorize(&state.pool, &headers).await?;
    let response = task_errors_inner(&state.pool, principal, &task_ref).await?;
    Ok(Json(response))
}

async fn capture_health(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(client_id): AxumPath<String>,
) -> Result<Json<CaptureHealthResponse>, StatusCode> {
    let principal = authorize(&state.pool, &headers).await?;
    let response = capture_health_inner(&state.pool, principal, &client_id).await?;
    Ok(Json(response))
}

async fn session_detail(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath((client_id, session_id)): AxumPath<(String, String)>,
    Query(query): Query<SessionQuery>,
) -> Result<Json<SessionDetail>, StatusCode> {
    let principal = authorize(&state.pool, &headers).await?;
    let detail =
        session_detail_inner(&state.pool, principal, &client_id, &session_id, query).await?;
    Ok(Json(detail))
}

async fn list_tasks_inner(
    pool: &SqlitePool,
    principal: Principal,
    mut query: TaskListQuery,
) -> Result<TaskListResponse, StatusCode> {
    ensure_query_role(&principal)?;
    if !principal.role.is_admin() {
        if query
            .client_id
            .as_deref()
            .is_some_and(|client_id| client_id != principal.client_id)
        {
            return Err(StatusCode::FORBIDDEN);
        }
        query.client_id = Some(principal.client_id);
    }

    let rows = sqlx::query(
        "SELECT snapshot_json, updated_at_ms, task_ref FROM tasks
         WHERE (?1 IS NULL OR client_id=?1)
           AND (?2 IS NULL OR provider=?2)
           AND (?3 IS NULL OR session_id=?3)
           AND (?4 IS NULL OR phase=?4)
           AND (?5 IS NULL OR terminal=?5)
         ORDER BY updated_at_ms DESC, task_ref DESC
         LIMIT ?6",
    )
    .bind(query.client_id)
    .bind(query.provider)
    .bind(query.session_id)
    .bind(
        query
            .phase
            .map(|value| serde_json::to_string(&value))
            .transpose()
            .map_err(internal_error)?,
    )
    .bind(
        query
            .terminal
            .map(|value| serde_json::to_string(&value))
            .transpose()
            .map_err(internal_error)?,
    )
    .bind(i64::from(query.limit.unwrap_or(100).min(500)))
    .fetch_all(pool)
    .await
    .map_err(internal_error)?;

    let tasks = rows
        .iter()
        .map(|row| serde_json::from_str::<TaskSnapshot>(&row.get::<String, _>("snapshot_json")))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let next_cursor = if tasks.len() == query.limit.unwrap_or(100).min(500) as usize {
        rows.last().map(|row| {
            format!(
                "{}:{}",
                row.get::<i64, _>("updated_at_ms"),
                row.get::<String, _>("task_ref")
            )
        })
    } else {
        None
    };
    Ok(TaskListResponse { tasks, next_cursor })
}

async fn task_detail_inner(
    pool: &SqlitePool,
    principal: Principal,
    task_ref: &str,
) -> Result<TaskDetail, StatusCode> {
    ensure_query_role(&principal)?;
    ensure_task_visible(pool, &principal, task_ref).await?;
    let snapshot = fetch_snapshot(pool, task_ref)
        .await
        .map_err(internal_error)?;
    let attempts = fetch_payloads::<AttemptRecord>(pool, "attempts", task_ref)
        .await
        .map_err(internal_error)?;
    let events = fetch_payloads::<TaskEvent>(pool, "task_events", task_ref)
        .await
        .map_err(internal_error)?;
    let errors = fetch_payloads::<ErrorRecord>(pool, "errors", task_ref)
        .await
        .map_err(internal_error)?;
    let gaps = fetch_payloads::<CaptureGapRecord>(pool, "capture_gaps", task_ref)
        .await
        .map_err(internal_error)?;
    Ok(TaskDetail {
        snapshot,
        attempts,
        events,
        errors,
        gaps,
    })
}

async fn task_attempts_inner(
    pool: &SqlitePool,
    principal: Principal,
    task_ref: &str,
) -> Result<Vec<AttemptRecord>, StatusCode> {
    ensure_query_role(&principal)?;
    ensure_task_visible(pool, &principal, task_ref).await?;
    fetch_payloads::<AttemptRecord>(pool, "attempts", task_ref)
        .await
        .map_err(internal_error)
}

async fn task_events_inner(
    pool: &SqlitePool,
    principal: Principal,
    task_ref: &str,
) -> Result<EventListResponse, StatusCode> {
    ensure_query_role(&principal)?;
    ensure_task_visible(pool, &principal, task_ref).await?;
    let events = fetch_payloads::<TaskEvent>(pool, "task_events", task_ref)
        .await
        .map_err(internal_error)?;
    Ok(EventListResponse { events })
}

async fn task_errors_inner(
    pool: &SqlitePool,
    principal: Principal,
    task_ref: &str,
) -> Result<ErrorListResponse, StatusCode> {
    ensure_query_role(&principal)?;
    ensure_task_visible(pool, &principal, task_ref).await?;
    let errors = fetch_payloads::<ErrorRecord>(pool, "errors", task_ref)
        .await
        .map_err(internal_error)?;
    Ok(ErrorListResponse { errors })
}

async fn capture_health_inner(
    pool: &SqlitePool,
    principal: Principal,
    client_id: &str,
) -> Result<CaptureHealthResponse, StatusCode> {
    ensure_query_role(&principal)?;
    if !principal.role.is_admin() && principal.client_id != client_id {
        return Err(StatusCode::FORBIDDEN);
    }
    let row = sqlx::query(
        "SELECT instance_id, observed_at_ms, capture_health_json
         FROM heartbeats
         WHERE client_id=?1
         ORDER BY observed_at_ms DESC
         LIMIT 1",
    )
    .bind(client_id)
    .fetch_optional(pool)
    .await
    .map_err(internal_error)?;
    let Some(row) = row else {
        return Err(StatusCode::NOT_FOUND);
    };
    Ok(CaptureHealthResponse {
        client_id: client_id.to_owned(),
        instance_id: Uuid::parse_str(&row.get::<String, _>("instance_id"))
            .map_err(internal_error)?,
        observed_at_ms: row.get("observed_at_ms"),
        integrity: serde_json::from_str(&row.get::<String, _>("capture_health_json"))
            .unwrap_or(IntegrityState::Degraded),
    })
}

async fn session_detail_inner(
    pool: &SqlitePool,
    principal: Principal,
    client_id: &str,
    session_id: &str,
    query: SessionQuery,
) -> Result<SessionDetail, StatusCode> {
    ensure_query_role(&principal)?;
    if !principal.role.is_admin() && principal.client_id != client_id {
        return Err(StatusCode::FORBIDDEN);
    }

    let rows = sqlx::query(
        "SELECT provider, thread_id, snapshot_json
         FROM tasks
         WHERE client_id=?1
           AND session_id=?2
           AND (?3 IS NULL OR provider=?3)
           AND (?4 IS NULL OR thread_id=?4)
         ORDER BY updated_at_ms DESC, task_ref DESC",
    )
    .bind(client_id)
    .bind(session_id)
    .bind(query.provider.clone())
    .bind(query.thread_id.clone())
    .fetch_all(pool)
    .await
    .map_err(internal_error)?;
    if rows.is_empty() {
        return Err(StatusCode::NOT_FOUND);
    }

    let mut providers = BTreeSet::new();
    let mut threads = BTreeSet::new();
    for row in &rows {
        providers.insert(row.get::<String, _>("provider"));
        threads.insert(row.get::<String, _>("thread_id"));
    }
    if query.provider.is_none() && providers.len() > 1 {
        return Err(StatusCode::BAD_REQUEST);
    }
    if query.thread_id.is_none() && threads.len() > 1 {
        return Err(StatusCode::BAD_REQUEST);
    }

    let provider = query
        .provider
        .unwrap_or_else(|| providers.into_iter().next().expect("nonempty"));
    let thread_id = query
        .thread_id
        .unwrap_or_else(|| threads.into_iter().next().expect("nonempty"));

    let tasks = rows
        .into_iter()
        .map(|row| serde_json::from_str::<TaskSnapshot>(&row.get::<String, _>("snapshot_json")))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(SessionDetail {
        client_id: client_id.to_owned(),
        provider,
        session_id: session_id.to_owned(),
        thread_id,
        tasks,
    })
}

async fn create_content_request_inner(
    pool: &SqlitePool,
    principal: Principal,
    task_ref: &str,
    parts: Vec<codexwatch_protocol::ContentPart>,
    expires_at_ms: Option<i64>,
) -> Result<(), StatusCode> {
    ensure_admin_role(&principal)?;
    let row = sqlx::query("SELECT client_id, session_id, thread_id FROM tasks WHERE task_ref=?1")
        .bind(task_ref)
        .fetch_optional(pool)
        .await
        .map_err(internal_error)?;
    let Some(row) = row else {
        return Err(StatusCode::NOT_FOUND);
    };

    let request = ContentRequest {
        request_id: Uuid::now_v7(),
        client_id: row.get("client_id"),
        task_ref: task_ref.to_owned(),
        session_id: row.get("session_id"),
        thread_id: row.get("thread_id"),
        created_at_ms: now_ms(),
        expires_at_ms,
        parts,
    };
    request.validate().map_err(|_| StatusCode::BAD_REQUEST)?;

    let command = ClientCommand::RequestContent(ContentRequestCommand {
        command_id: Uuid::now_v7(),
        request: request.clone(),
    });

    let mut tx = pool.begin().await.map_err(internal_error)?;
    touch_conversation(
        &mut tx,
        &request.client_id,
        &request.session_id,
        &request.thread_id,
        request.created_at_ms,
    )
    .await
    .map_err(internal_error)?;
    evict_old_conversations(&mut tx, &request.client_id)
        .await
        .map_err(internal_error)?;
    sqlx::query(
        "INSERT INTO content_requests(
            request_id, client_id, task_ref, session_id, thread_id, parts_json,
            created_at_ms, expires_at_ms, completed_at_ms, status, outcome
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL, 'pending', NULL)",
    )
    .bind(request.request_id.to_string())
    .bind(&request.client_id)
    .bind(&request.task_ref)
    .bind(&request.session_id)
    .bind(&request.thread_id)
    .bind(serde_json::to_string(&request.parts).map_err(internal_error)?)
    .bind(request.created_at_ms)
    .bind(request.expires_at_ms)
    .execute(&mut *tx)
    .await
    .map_err(internal_error)?;
    sqlx::query(
        "INSERT INTO commands(
            command_id, request_id, client_id, status, created_at_ms,
            delivered_at_ms, completed_at_ms, payload_json
         ) VALUES(?1, ?2, ?3, 'pending', ?4, NULL, NULL, ?5)",
    )
    .bind(match &command {
        ClientCommand::RequestContent(inner) => inner.command_id.to_string(),
    })
    .bind(request.request_id.to_string())
    .bind(&request.client_id)
    .bind(request.created_at_ms)
    .bind(serde_json::to_string(&command).map_err(internal_error)?)
    .execute(&mut *tx)
    .await
    .map_err(internal_error)?;
    tx.commit().await.map_err(internal_error)?;
    Ok(())
}

async fn ensure_client_exists(
    executor: impl sqlx::Executor<'_, Database = sqlx::Sqlite>,
    client_id: &str,
    now: i64,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO clients(client_id, created_at_ms) VALUES(?1, ?2)
         ON CONFLICT(client_id) DO NOTHING",
    )
    .bind(client_id)
    .bind(now)
    .execute(executor)
    .await?;
    Ok(())
}

async fn upsert_token(
    pool: &SqlitePool,
    client_id: &str,
    token: &str,
    role: TokenRole,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO api_tokens(token_hash, client_id, role, created_at_ms, revoked_at_ms)
         VALUES(?1, ?2, ?3, ?4, NULL)
         ON CONFLICT(token_hash) DO UPDATE SET
           client_id=excluded.client_id,
           role=excluded.role,
           revoked_at_ms=NULL",
    )
    .bind(hash_token(token))
    .bind(client_id)
    .bind(role.as_str())
    .bind(now_ms())
    .execute(pool)
    .await?;
    Ok(())
}

async fn authorize(pool: &SqlitePool, headers: &HeaderMap) -> Result<Principal, StatusCode> {
    let Some(token) = headers
        .get(http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
    else {
        return Err(StatusCode::UNAUTHORIZED);
    };
    let row = sqlx::query(
        "SELECT client_id, role FROM api_tokens WHERE token_hash=?1 AND revoked_at_ms IS NULL",
    )
    .bind(hash_token(token))
    .fetch_optional(pool)
    .await
    .map_err(internal_error)?;
    let Some(row) = row else {
        return Err(StatusCode::UNAUTHORIZED);
    };
    let role = TokenRole::from_db(&row.get::<String, _>("role")).ok_or(StatusCode::FORBIDDEN)?;
    Ok(Principal {
        client_id: row.get("client_id"),
        role,
    })
}

fn ensure_client_role(principal: &Principal) -> Result<(), StatusCode> {
    if principal.role.can_ingest() {
        Ok(())
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}

fn ensure_query_role(principal: &Principal) -> Result<(), StatusCode> {
    if principal.role.can_query() {
        Ok(())
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}

fn ensure_admin_role(principal: &Principal) -> Result<(), StatusCode> {
    if principal.role.is_admin() {
        Ok(())
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}

async fn ensure_task_visible(
    pool: &SqlitePool,
    principal: &Principal,
    task_ref: &str,
) -> Result<(), StatusCode> {
    let row = sqlx::query("SELECT client_id FROM tasks WHERE task_ref=?1")
        .bind(task_ref)
        .fetch_optional(pool)
        .await
        .map_err(internal_error)?;
    let Some(row) = row else {
        return Err(StatusCode::NOT_FOUND);
    };
    if !principal.role.is_admin() && row.get::<String, _>("client_id") != principal.client_id {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(())
}

async fn persist_client(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    batch: &IngestBatch,
) -> Result<()> {
    ensure_client_exists(&mut **tx, &batch.client.client_id, batch.generated_at_ms).await?;
    sqlx::query(
        "INSERT INTO client_instances(
            instance_id, client_id, hostname, platform, codex_version, started_at_ms, last_seen_at_ms
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT(instance_id) DO UPDATE SET
           hostname=excluded.hostname,
           platform=excluded.platform,
           codex_version=excluded.codex_version,
           last_seen_at_ms=excluded.last_seen_at_ms",
    )
    .bind(batch.client.instance_id.to_string())
    .bind(&batch.client.client_id)
    .bind(&batch.client.hostname)
    .bind(&batch.client.platform)
    .bind(&batch.client.codex_version)
    .bind(batch.client.started_at_ms)
    .bind(batch.generated_at_ms)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn persist_task_upload(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    client_id: &str,
    upload: &TaskUpload,
) -> Result<()> {
    let snapshot = &upload.snapshot;
    let identity = &snapshot.identity;
    sqlx::query(
        "INSERT INTO sessions(
            client_id, provider, session_id, thread_id, first_seen_at_ms, last_seen_at_ms
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(client_id, provider, session_id, thread_id) DO UPDATE SET
           last_seen_at_ms=excluded.last_seen_at_ms",
    )
    .bind(client_id)
    .bind(&identity.provider)
    .bind(&identity.session_id)
    .bind(&identity.thread_id)
    .bind(snapshot.started_at_ms)
    .bind(snapshot.updated_at_ms)
    .execute(&mut **tx)
    .await?;

    sqlx::query(
        "INSERT INTO tasks(
            task_ref, client_id, provider, session_id, thread_id, turn_id,
            phase, terminal, updated_at_ms, snapshot_json
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
         ON CONFLICT(task_ref) DO UPDATE SET
            client_id=excluded.client_id,
            provider=excluded.provider,
            session_id=excluded.session_id,
            thread_id=excluded.thread_id,
            turn_id=excluded.turn_id,
            phase=excluded.phase,
            terminal=excluded.terminal,
            updated_at_ms=excluded.updated_at_ms,
            snapshot_json=excluded.snapshot_json",
    )
    .bind(&snapshot.task_ref)
    .bind(client_id)
    .bind(&identity.provider)
    .bind(&identity.session_id)
    .bind(&identity.thread_id)
    .bind(&identity.turn_id)
    .bind(serde_json::to_string(&snapshot.phase)?)
    .bind(
        snapshot
            .terminal
            .map(|value| serde_json::to_string(&value))
            .transpose()?,
    )
    .bind(snapshot.updated_at_ms)
    .bind(serde_json::to_string(snapshot)?)
    .execute(&mut **tx)
    .await?;

    sqlx::query(
        "INSERT INTO codex_tasks(task_ref, request_kind, parent_turn_id, root_turn_id)
         VALUES(?1, ?2, ?3, ?4)
         ON CONFLICT(task_ref) DO UPDATE SET
           request_kind=excluded.request_kind,
           parent_turn_id=excluded.parent_turn_id,
           root_turn_id=excluded.root_turn_id",
    )
    .bind(&snapshot.task_ref)
    .bind(&snapshot.codex.request_kind)
    .bind(&snapshot.codex.parent_turn_id)
    .bind(&snapshot.codex.root_turn_id)
    .execute(&mut **tx)
    .await?;

    replace_payloads(
        tx,
        "attempts",
        "attempt_id",
        "started_at_ms",
        &snapshot.task_ref,
        &upload.attempts,
        |attempt| attempt.attempt_id.to_string(),
        |attempt| attempt.started_at_ms,
    )
    .await?;
    replace_payloads(
        tx,
        "task_events",
        "event_id",
        "occurred_at_ms",
        &snapshot.task_ref,
        &upload.events,
        |event| event.event_id.to_string(),
        |event| event.occurred_at_ms,
    )
    .await?;
    replace_payloads(
        tx,
        "errors",
        "error_id",
        "occurred_at_ms",
        &snapshot.task_ref,
        &upload.errors,
        |error| error.error_id.to_string(),
        |error| error.occurred_at_ms,
    )
    .await?;
    replace_payloads(
        tx,
        "capture_gaps",
        "gap_id",
        "occurred_at_ms",
        &snapshot.task_ref,
        &upload.gaps,
        |gap| gap.gap_id.to_string(),
        |gap| gap.occurred_at_ms,
    )
    .await?;
    Ok(())
}

async fn replace_payloads<T, FId, FTs>(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    table: &str,
    id_column: &str,
    ts_column: &str,
    task_ref: &str,
    items: &[T],
    id_fn: FId,
    ts_fn: FTs,
) -> Result<()>
where
    T: serde::Serialize,
    FId: Fn(&T) -> String,
    FTs: Fn(&T) -> i64,
{
    let delete_sql = format!("DELETE FROM {table} WHERE task_ref=?1");
    sqlx::query(&delete_sql)
        .bind(task_ref)
        .execute(&mut **tx)
        .await?;

    let insert_sql = format!(
        "INSERT INTO {table}(task_ref, {id_column}, {ts_column}, payload_json) VALUES(?1, ?2, ?3, ?4)"
    );
    for item in items {
        sqlx::query(&insert_sql)
            .bind(task_ref)
            .bind(id_fn(item))
            .bind(ts_fn(item))
            .bind(serde_json::to_string(item)?)
            .execute(&mut **tx)
            .await?;
    }
    Ok(())
}

async fn persist_heartbeat(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    heartbeat: &Heartbeat,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO heartbeats(
            heartbeat_id, client_id, instance_id, observed_at_ms, queue_depth,
            active_task_count, capture_health_json, note
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
    )
    .bind(heartbeat.heartbeat_id.to_string())
    .bind(&heartbeat.client_id)
    .bind(heartbeat.instance_id.to_string())
    .bind(heartbeat.observed_at_ms)
    .bind(i64::from(heartbeat.queue_depth))
    .bind(i64::from(heartbeat.active_task_count))
    .bind(serde_json::to_string(&heartbeat.capture_health)?)
    .bind(&heartbeat.note)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn load_command_request(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    command_id: Uuid,
    client_id: &str,
) -> Result<Option<StoredContentRequest>> {
    let row = sqlx::query(
        "SELECT cr.request_id, cr.task_ref, cr.session_id, cr.thread_id, cr.created_at_ms, cr.expires_at_ms, cr.parts_json
         FROM commands c
         JOIN content_requests cr ON cr.request_id = c.request_id
         WHERE c.command_id=?1 AND c.client_id=?2",
    )
    .bind(command_id.to_string())
    .bind(client_id)
    .fetch_optional(&mut **tx)
    .await?;
    row.map(|row| {
        let parts_json: String = row.get("parts_json");
        let parts = serde_json::from_str(&parts_json)?;
        Ok(StoredContentRequest {
            request: ContentRequest {
                request_id: Uuid::parse_str(&row.get::<String, _>("request_id"))?,
                client_id: client_id.to_owned(),
                task_ref: row.get("task_ref"),
                session_id: row.get("session_id"),
                thread_id: row.get("thread_id"),
                created_at_ms: row.get("created_at_ms"),
                expires_at_ms: row.get("expires_at_ms"),
                parts,
            },
        })
    })
    .transpose()
}

async fn load_manifest(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    request_id: Uuid,
    object_sha256: &str,
) -> Result<Option<ContentObjectManifest>> {
    let row = sqlx::query(
        "SELECT manifest_json FROM content_manifests WHERE request_id=?1 AND object_sha256=?2",
    )
    .bind(request_id.to_string())
    .bind(object_sha256)
    .fetch_optional(&mut **tx)
    .await?;
    row.map(|row| serde_json::from_str(&row.get::<String, _>("manifest_json")).map_err(Into::into))
        .transpose()
}

async fn persist_manifest_row(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    manifest: &ContentObjectManifest,
    client_id: &str,
    now: i64,
) -> Result<(), StatusCode> {
    if let Some(row) = sqlx::query(
        "SELECT manifest_json FROM content_manifests WHERE request_id=?1 AND object_sha256=?2",
    )
    .bind(manifest.request_id.to_string())
    .bind(&manifest.object_sha256)
    .fetch_optional(&mut **tx)
    .await
    .map_err(internal_error)?
    {
        let existing: ContentObjectManifest =
            serde_json::from_str(&row.get::<String, _>("manifest_json"))
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        if existing != *manifest {
            return Err(StatusCode::CONFLICT);
        }
        return Ok(());
    }

    sqlx::query(
        "INSERT INTO content_manifests(
            request_id, object_sha256, client_id, manifest_json, created_at_ms
         ) VALUES(?1, ?2, ?3, ?4, ?5)",
    )
    .bind(manifest.request_id.to_string())
    .bind(&manifest.object_sha256)
    .bind(client_id)
    .bind(serde_json::to_string(manifest).map_err(internal_error)?)
    .bind(now)
    .execute(&mut **tx)
    .await
    .map_err(internal_error)?;
    Ok(())
}

async fn upsert_chunk_row(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    chunk: &ContentUploadChunk,
    now: i64,
) -> Result<bool, StatusCode> {
    if let Some(row) = sqlx::query(
        "SELECT chunk_count, payload_sha256, is_last
         FROM content_chunks
         WHERE request_id=?1 AND object_sha256=?2 AND chunk_index=?3",
    )
    .bind(chunk.request_id.to_string())
    .bind(&chunk.object_sha256)
    .bind(i64::from(chunk.chunk_index))
    .fetch_optional(&mut **tx)
    .await
    .map_err(internal_error)?
    {
        if row.get::<i64, _>("chunk_count") != i64::from(chunk.chunk_count)
            || row.get::<String, _>("payload_sha256") != chunk.payload_sha256
            || row.get::<i64, _>("is_last") != i64::from(chunk.is_last)
        {
            return Err(StatusCode::CONFLICT);
        }
        return Ok(true);
    }

    let mismatch = sqlx::query(
        "SELECT 1 FROM content_chunks
         WHERE request_id=?1 AND object_sha256=?2 AND chunk_count!=?3
         LIMIT 1",
    )
    .bind(chunk.request_id.to_string())
    .bind(&chunk.object_sha256)
    .bind(i64::from(chunk.chunk_count))
    .fetch_optional(&mut **tx)
    .await
    .map_err(internal_error)?;
    if mismatch.is_some() {
        return Err(StatusCode::CONFLICT);
    }

    sqlx::query(
        "INSERT INTO content_chunks(
            request_id, object_sha256, chunk_index, chunk_count,
            payload_sha256, payload_zstd, is_last, received_at_ms
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
    )
    .bind(chunk.request_id.to_string())
    .bind(&chunk.object_sha256)
    .bind(i64::from(chunk.chunk_index))
    .bind(i64::from(chunk.chunk_count))
    .bind(&chunk.payload_sha256)
    .bind(&chunk.payload_zstd)
    .bind(i64::from(chunk.is_last))
    .bind(now)
    .execute(&mut **tx)
    .await
    .map_err(internal_error)?;
    Ok(false)
}

async fn is_object_complete(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    request_id: Uuid,
    object_sha256: &str,
    chunk_count: u32,
) -> Result<bool> {
    let rows = sqlx::query(
        "SELECT chunk_index FROM content_chunks
         WHERE request_id=?1 AND object_sha256=?2
         ORDER BY chunk_index ASC",
    )
    .bind(request_id.to_string())
    .bind(object_sha256)
    .fetch_all(&mut **tx)
    .await?;
    if rows.len() != chunk_count as usize {
        return Ok(false);
    }
    for (expected, row) in rows.into_iter().enumerate() {
        if row.get::<i64, _>("chunk_index") != expected as i64 {
            return Ok(false);
        }
    }
    Ok(true)
}

async fn assemble_object(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    request_id: Uuid,
    object_sha256: &str,
    chunk_count: u32,
) -> Result<Vec<u8>, StatusCode> {
    let rows = sqlx::query(
        "SELECT payload_zstd FROM content_chunks
         WHERE request_id=?1 AND object_sha256=?2
         ORDER BY chunk_index ASC",
    )
    .bind(request_id.to_string())
    .bind(object_sha256)
    .fetch_all(&mut **tx)
    .await
    .map_err(internal_error)?;
    if rows.len() != chunk_count as usize {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut assembled = Vec::new();
    for row in rows {
        let payload: Vec<u8> = row.get("payload_zstd");
        assembled.extend_from_slice(&payload);
    }
    Ok(assembled)
}

async fn upsert_content_object(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    request: &ContentRequest,
    manifest: &ContentObjectManifest,
    assembled_zstd: &[u8],
    uncompressed: &[u8],
    now: i64,
) -> Result<ContentObjectManifest> {
    sqlx::query(
        "INSERT INTO content_objects(
            object_sha256, content_zstd, uncompressed_bytes, compressed_bytes, created_at_ms, last_accessed_at_ms
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(object_sha256) DO UPDATE SET
           content_zstd=excluded.content_zstd,
           uncompressed_bytes=excluded.uncompressed_bytes,
           compressed_bytes=excluded.compressed_bytes,
           last_accessed_at_ms=excluded.last_accessed_at_ms",
    )
    .bind(&manifest.object_sha256)
    .bind(assembled_zstd)
    .bind(uncompressed.len() as i64)
    .bind(assembled_zstd.len() as i64)
    .bind(now)
    .bind(now)
    .execute(&mut **tx)
    .await?;

    sqlx::query(
        "INSERT INTO content_links(
            request_id, object_sha256, client_id, session_id, thread_id,
            manifest_json, created_at_ms, last_accessed_at_ms
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
         ON CONFLICT(request_id, object_sha256) DO UPDATE SET
           manifest_json=excluded.manifest_json,
           last_accessed_at_ms=excluded.last_accessed_at_ms",
    )
    .bind(request.request_id.to_string())
    .bind(&manifest.object_sha256)
    .bind(&request.client_id)
    .bind(&request.session_id)
    .bind(&request.thread_id)
    .bind(serde_json::to_string(&manifest)?)
    .bind(now)
    .bind(now)
    .execute(&mut **tx)
    .await?;
    Ok(manifest.clone())
}

async fn linked_object_count(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    request_id: Uuid,
) -> Result<i64> {
    let row = sqlx::query("SELECT COUNT(*) AS count FROM content_links WHERE request_id=?1")
        .bind(request_id.to_string())
        .fetch_one(&mut **tx)
        .await?;
    Ok(row.get("count"))
}

async fn complete_request_and_command(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    request_id: Uuid,
    status: &str,
    outcome: &str,
    now: i64,
) -> Result<()> {
    sqlx::query(
        "UPDATE content_requests SET status=?2, outcome=?3, completed_at_ms=?4 WHERE request_id=?1",
    )
    .bind(request_id.to_string())
    .bind(status)
    .bind(outcome)
    .bind(now)
    .execute(&mut **tx)
    .await?;
    sqlx::query("UPDATE commands SET status='completed', completed_at_ms=?2 WHERE request_id=?1")
        .bind(request_id.to_string())
        .bind(now)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

async fn touch_conversation(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    client_id: &str,
    session_id: &str,
    thread_id: &str,
    now: i64,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO content_conversations(client_id, session_id, thread_id, last_requested_at_ms)
         VALUES(?1, ?2, ?3, ?4)
         ON CONFLICT(client_id, session_id, thread_id) DO UPDATE SET
           last_requested_at_ms=excluded.last_requested_at_ms",
    )
    .bind(client_id)
    .bind(session_id)
    .bind(thread_id)
    .bind(now)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn evict_old_conversations(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    client_id: &str,
) -> Result<()> {
    loop {
        let row =
            sqlx::query("SELECT COUNT(*) AS count FROM content_conversations WHERE client_id=?1")
                .bind(client_id)
                .fetch_one(&mut **tx)
                .await?;
        if row.get::<i64, _>("count") <= CONTENT_CONVERSATION_LIMIT {
            return Ok(());
        }
        let Some(victim) = select_oldest_conversation(tx, client_id).await? else {
            return Ok(());
        };
        evict_conversation(tx, client_id, &victim.session_id, &victim.thread_id).await?;
    }
}

async fn select_oldest_conversation(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    client_id: &str,
) -> Result<Option<StoredConversation>> {
    sqlx::query(
        "SELECT session_id, thread_id FROM content_conversations
         WHERE client_id=?1
         ORDER BY last_requested_at_ms ASC, session_id ASC, thread_id ASC
         LIMIT 1",
    )
    .bind(client_id)
    .fetch_optional(&mut **tx)
    .await?
    .map(|row| {
        Ok(StoredConversation {
            session_id: row.get("session_id"),
            thread_id: row.get("thread_id"),
        })
    })
    .transpose()
}

async fn evict_conversation(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    client_id: &str,
    session_id: &str,
    thread_id: &str,
) -> Result<()> {
    let request_rows = sqlx::query(
        "SELECT request_id FROM content_requests
         WHERE client_id=?1 AND session_id=?2 AND thread_id=?3",
    )
    .bind(client_id)
    .bind(session_id)
    .bind(thread_id)
    .fetch_all(&mut **tx)
    .await?;
    let request_ids = request_rows
        .into_iter()
        .map(|row| row.get::<String, _>("request_id"))
        .collect::<Vec<_>>();

    let mut object_sha256s = BTreeSet::new();
    for request_id in &request_ids {
        let rows = sqlx::query("SELECT object_sha256 FROM content_links WHERE request_id=?1")
            .bind(request_id)
            .fetch_all(&mut **tx)
            .await?;
        for row in rows {
            object_sha256s.insert(row.get::<String, _>("object_sha256"));
        }
        sqlx::query("DELETE FROM content_manifests WHERE request_id=?1")
            .bind(request_id)
            .execute(&mut **tx)
            .await?;
        sqlx::query("DELETE FROM content_chunks WHERE request_id=?1")
            .bind(request_id)
            .execute(&mut **tx)
            .await?;
        sqlx::query("DELETE FROM content_links WHERE request_id=?1")
            .bind(request_id)
            .execute(&mut **tx)
            .await?;
    }

    for object_sha256 in object_sha256s {
        let linked = sqlx::query("SELECT 1 FROM content_links WHERE object_sha256=?1 LIMIT 1")
            .bind(&object_sha256)
            .fetch_optional(&mut **tx)
            .await?;
        if linked.is_none() {
            sqlx::query("DELETE FROM content_objects WHERE object_sha256=?1")
                .bind(&object_sha256)
                .execute(&mut **tx)
                .await?;
        }
    }

    sqlx::query(
        "DELETE FROM content_conversations WHERE client_id=?1 AND session_id=?2 AND thread_id=?3",
    )
    .bind(client_id)
    .bind(session_id)
    .bind(thread_id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn fetch_snapshot(pool: &SqlitePool, task_ref: &str) -> Result<TaskSnapshot> {
    let row = sqlx::query("SELECT snapshot_json FROM tasks WHERE task_ref=?1")
        .bind(task_ref)
        .fetch_one(pool)
        .await?;
    Ok(serde_json::from_str(
        &row.get::<String, _>("snapshot_json"),
    )?)
}

async fn fetch_payloads<T>(pool: &SqlitePool, table: &str, task_ref: &str) -> Result<Vec<T>>
where
    T: for<'de> serde::Deserialize<'de>,
{
    let sql = format!("SELECT payload_json FROM {table} WHERE task_ref=?1 ORDER BY rowid ASC");
    let rows = sqlx::query(&sql).bind(task_ref).fetch_all(pool).await?;
    rows.into_iter()
        .map(|row| {
            serde_json::from_str::<T>(&row.get::<String, _>("payload_json")).map_err(Into::into)
        })
        .collect()
}

async fn open_pool(path: &Path) -> Result<SqlitePool> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await.ok();
    }
    let url = format!("sqlite://{}", path.display());
    let options = SqliteConnectOptions::from_str(&url)?
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .foreign_keys(true);
    SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .with_context(|| format!("connect sqlite {url}"))
}

async fn migrate(pool: &SqlitePool) -> Result<()> {
    for statement in [
        "CREATE TABLE IF NOT EXISTS clients(client_id TEXT PRIMARY KEY, created_at_ms INTEGER NOT NULL)",
        "CREATE TABLE IF NOT EXISTS api_tokens(token_hash TEXT PRIMARY KEY, client_id TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'client', created_at_ms INTEGER NOT NULL, revoked_at_ms INTEGER)",
        "CREATE TABLE IF NOT EXISTS client_instances(instance_id TEXT PRIMARY KEY, client_id TEXT NOT NULL, hostname TEXT NOT NULL, platform TEXT NOT NULL, codex_version TEXT NOT NULL, started_at_ms INTEGER NOT NULL, last_seen_at_ms INTEGER NOT NULL)",
        "CREATE TABLE IF NOT EXISTS sessions(client_id TEXT NOT NULL, provider TEXT NOT NULL, session_id TEXT NOT NULL, thread_id TEXT NOT NULL, first_seen_at_ms INTEGER NOT NULL, last_seen_at_ms INTEGER NOT NULL, PRIMARY KEY(client_id, provider, session_id, thread_id))",
        "CREATE TABLE IF NOT EXISTS tasks(task_ref TEXT PRIMARY KEY, client_id TEXT NOT NULL, provider TEXT NOT NULL, session_id TEXT NOT NULL, thread_id TEXT NOT NULL, turn_id TEXT NOT NULL, phase TEXT NOT NULL, terminal TEXT, updated_at_ms INTEGER NOT NULL, snapshot_json TEXT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS codex_tasks(task_ref TEXT PRIMARY KEY, request_kind TEXT NOT NULL, parent_turn_id TEXT, root_turn_id TEXT)",
        "CREATE TABLE IF NOT EXISTS attempts(task_ref TEXT NOT NULL, attempt_id TEXT PRIMARY KEY, started_at_ms INTEGER NOT NULL, ended_at_ms INTEGER, payload_json TEXT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS task_events(task_ref TEXT NOT NULL, event_id TEXT PRIMARY KEY, occurred_at_ms INTEGER NOT NULL, payload_json TEXT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS errors(task_ref TEXT NOT NULL, error_id TEXT PRIMARY KEY, occurred_at_ms INTEGER NOT NULL, payload_json TEXT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS capture_gaps(task_ref TEXT NOT NULL, gap_id TEXT PRIMARY KEY, occurred_at_ms INTEGER NOT NULL, payload_json TEXT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS http_exchanges(task_ref TEXT NOT NULL, exchange_id TEXT PRIMARY KEY, observed_at_ms INTEGER NOT NULL, payload_json TEXT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS heartbeats(heartbeat_id TEXT PRIMARY KEY, client_id TEXT NOT NULL, instance_id TEXT NOT NULL, observed_at_ms INTEGER NOT NULL, queue_depth INTEGER NOT NULL, active_task_count INTEGER NOT NULL, capture_health_json TEXT NOT NULL, note TEXT)",
        "CREATE TABLE IF NOT EXISTS ingest_receipts(client_id TEXT NOT NULL, batch_id TEXT NOT NULL, payload_sha256 TEXT NOT NULL, received_at_ms INTEGER NOT NULL, PRIMARY KEY(client_id, batch_id))",
        "CREATE TABLE IF NOT EXISTS commands(command_id TEXT PRIMARY KEY, request_id TEXT, client_id TEXT NOT NULL, status TEXT NOT NULL, created_at_ms INTEGER NOT NULL, delivered_at_ms INTEGER, completed_at_ms INTEGER, payload_json TEXT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS content_requests(request_id TEXT PRIMARY KEY, client_id TEXT NOT NULL, task_ref TEXT NOT NULL, session_id TEXT NOT NULL, thread_id TEXT NOT NULL, parts_json TEXT NOT NULL, created_at_ms INTEGER NOT NULL, expires_at_ms INTEGER, completed_at_ms INTEGER, status TEXT NOT NULL, outcome TEXT)",
        "CREATE TABLE IF NOT EXISTS content_manifests(request_id TEXT NOT NULL, object_sha256 TEXT NOT NULL, client_id TEXT NOT NULL, manifest_json TEXT NOT NULL, created_at_ms INTEGER NOT NULL, PRIMARY KEY(request_id, object_sha256))",
        "CREATE TABLE IF NOT EXISTS content_chunks(request_id TEXT NOT NULL, object_sha256 TEXT NOT NULL, chunk_index INTEGER NOT NULL, chunk_count INTEGER NOT NULL, payload_sha256 TEXT NOT NULL, payload_zstd BLOB NOT NULL, is_last INTEGER NOT NULL, received_at_ms INTEGER NOT NULL, PRIMARY KEY(request_id, object_sha256, chunk_index))",
        "CREATE TABLE IF NOT EXISTS content_objects(object_sha256 TEXT PRIMARY KEY, content_zstd BLOB NOT NULL, uncompressed_bytes INTEGER NOT NULL, compressed_bytes INTEGER NOT NULL, created_at_ms INTEGER NOT NULL, last_accessed_at_ms INTEGER NOT NULL)",
        "CREATE TABLE IF NOT EXISTS content_links(request_id TEXT NOT NULL, object_sha256 TEXT NOT NULL, client_id TEXT NOT NULL, session_id TEXT NOT NULL, thread_id TEXT NOT NULL, manifest_json TEXT NOT NULL, created_at_ms INTEGER NOT NULL, last_accessed_at_ms INTEGER NOT NULL, PRIMARY KEY(request_id, object_sha256))",
        "CREATE TABLE IF NOT EXISTS content_conversations(client_id TEXT NOT NULL, session_id TEXT NOT NULL, thread_id TEXT NOT NULL, last_requested_at_ms INTEGER NOT NULL, PRIMARY KEY(client_id, session_id, thread_id))",
    ] {
        sqlx::query(statement).execute(pool).await?;
    }
    for statement in [
        "CREATE INDEX IF NOT EXISTS idx_tasks_client_updated ON tasks(client_id, updated_at_ms DESC, task_ref DESC)",
        "CREATE INDEX IF NOT EXISTS idx_heartbeats_client_time ON heartbeats(client_id, observed_at_ms DESC)",
        "CREATE INDEX IF NOT EXISTS idx_content_conversations_client_time ON content_conversations(client_id, last_requested_at_ms ASC, session_id ASC, thread_id ASC)",
        "CREATE INDEX IF NOT EXISTS idx_content_links_object ON content_links(object_sha256)",
    ] {
        sqlx::query(statement).execute(pool).await?;
    }
    Ok(())
}

async fn cleanup_retention(pool: &SqlitePool, now: i64) -> Result<()> {
    sqlx::query("DELETE FROM heartbeats WHERE observed_at_ms < ?1")
        .bind(now - HEARTBEAT_RETENTION_MS)
        .execute(pool)
        .await?;
    sqlx::query("DELETE FROM ingest_receipts WHERE received_at_ms < ?1")
        .bind(now - RECEIPT_RETENTION_MS)
        .execute(pool)
        .await?;
    sqlx::query("DELETE FROM task_events WHERE occurred_at_ms < ?1")
        .bind(now - EPHEMERA_RETENTION_MS)
        .execute(pool)
        .await?;
    sqlx::query("DELETE FROM errors WHERE occurred_at_ms < ?1")
        .bind(now - EPHEMERA_RETENTION_MS)
        .execute(pool)
        .await?;
    sqlx::query("DELETE FROM capture_gaps WHERE occurred_at_ms < ?1")
        .bind(now - EPHEMERA_RETENTION_MS)
        .execute(pool)
        .await?;
    sqlx::query("DELETE FROM http_exchanges WHERE observed_at_ms < ?1")
        .bind(now - EPHEMERA_RETENTION_MS)
        .execute(pool)
        .await?;
    Ok(())
}

fn spawn_retention_task(pool: SqlitePool) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(6 * 60 * 60));
        loop {
            interval.tick().await;
            if let Err(error) = cleanup_retention(&pool, now_ms()).await {
                warn!("retention cleanup failed: {error}");
            }
        }
    });
}

fn parse_content_part(value: String) -> Result<codexwatch_protocol::ContentPart> {
    match value.as_str() {
        "request" => Ok(codexwatch_protocol::ContentPart::Request),
        "response" => Ok(codexwatch_protocol::ContentPart::Response),
        "tool_input" => Ok(codexwatch_protocol::ContentPart::ToolInput),
        "tool_output" => Ok(codexwatch_protocol::ContentPart::ToolOutput),
        "model_text" => Ok(codexwatch_protocol::ContentPart::ModelText),
        _ => anyhow::bail!("unsupported content part {value}"),
    }
}

fn hash_token(token: &str) -> String {
    sha256_hex(token.as_bytes())
}

fn map_manifest_error(status: StatusCode) -> StatusCode {
    status
}

fn internal_error(error: impl std::fmt::Display) -> StatusCode {
    warn!("internal error: {error}");
    StatusCode::INTERNAL_SERVER_ERROR
}

fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use axum::{
        body::{Body, to_bytes},
        http::{Method, Request, StatusCode, header},
    };
    use codexwatch_protocol::{
        ClientInstance, CodexTaskMetadata, ContentPart, IngestBatch, TaskIdentity, TaskPhase,
        TaskSnapshot, TaskUpload, UsageSummary, encode_batch,
    };
    use tempfile::TempDir;
    use tower::ServiceExt;

    use super::*;

    struct Harness {
        _dir: TempDir,
        pool: SqlitePool,
        app: Router,
    }

    impl Harness {
        async fn new() -> Self {
            let dir = TempDir::new().expect("tmp");
            let db = dir.path().join("server.db");
            let pool = open_pool(&db).await.expect("pool");
            migrate(&pool).await.expect("migrate");
            let app = build_router(AppState { pool: pool.clone() });
            Self {
                _dir: dir,
                pool,
                app,
            }
        }

        async fn issue_token(&self, client_id: &str, token: &str, role: TokenRole) {
            ensure_client_exists(&self.pool, client_id, 1)
                .await
                .expect("client");
            upsert_token(&self.pool, client_id, token, role)
                .await
                .expect("token");
        }

        async fn request(
            &self,
            method: Method,
            path: &str,
            token: &str,
            body: Body,
        ) -> http::Response<Body> {
            let builder = Request::builder()
                .method(method.clone())
                .uri(path)
                .header(header::AUTHORIZATION, format!("Bearer {token}"));
            let builder = if matches!(method, Method::POST | Method::PUT | Method::PATCH) {
                builder.header(header::CONTENT_TYPE, "application/json")
            } else {
                builder
            };
            self.app
                .clone()
                .oneshot(builder.body(body).expect("request"))
                .await
                .expect("response")
        }

        async fn json<T: serde::de::DeserializeOwned>(response: http::Response<Body>) -> T {
            let bytes = to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("body");
            serde_json::from_slice(&bytes).expect("json")
        }
    }

    fn sample_batch(
        client_id: &str,
        batch_id: Uuid,
        session: &str,
        thread: &str,
        turn: &str,
    ) -> IngestBatch {
        IngestBatch {
            version: codexwatch_protocol::PROTOCOL_VERSION,
            batch_id,
            generated_at_ms: 10,
            client: ClientInstance {
                client_id: client_id.to_owned(),
                instance_id: Uuid::now_v7(),
                hostname: "host".to_owned(),
                platform: "linux-x86_64".to_owned(),
                codex_version: "0.148.0".to_owned(),
                started_at_ms: 1,
            },
            tasks: vec![TaskUpload {
                snapshot: TaskSnapshot {
                    task_ref: format!("{session}:{thread}:{turn}"),
                    identity: TaskIdentity {
                        provider: "codex".to_owned(),
                        session_id: session.to_owned(),
                        thread_id: thread.to_owned(),
                        turn_id: turn.to_owned(),
                    },
                    codex: CodexTaskMetadata {
                        request_kind: "turn".to_owned(),
                        parent_turn_id: None,
                        root_turn_id: None,
                    },
                    sequence: 1,
                    phase: TaskPhase::Running,
                    terminal: None,
                    integrity: IntegrityState::Complete,
                    model: Some("gpt-5-codex".to_owned()),
                    attempt_count: 0,
                    tool_names: Vec::new(),
                    response_ids: Vec::new(),
                    usage: UsageSummary::default(),
                    started_at_ms: 5,
                    updated_at_ms: 10,
                    completed_at_ms: None,
                    last_error: None,
                },
                attempts: Vec::new(),
                events: Vec::new(),
                errors: Vec::new(),
                gaps: Vec::new(),
            }],
            heartbeats: Vec::new(),
        }
    }

    #[tokio::test]
    async fn healthz_is_unauthenticated_and_checks_sqlite() {
        let h = Harness::new().await;
        let response = h
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/healthz")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value = Harness::json(response).await;
        assert_eq!(body, serde_json::json!({ "ok": true }));
    }

    async fn ingest_batch(h: &Harness, token: &str, batch: &IngestBatch) -> http::Response<Body> {
        let encoded = encode_batch(batch).expect("encode");
        h.request(
            Method::POST,
            "/api/v1/ingest",
            token,
            Body::from(encoded.bytes),
        )
        .await
    }

    async fn seed_task(
        h: &Harness,
        client_id: &str,
        token: &str,
        session: &str,
        thread: &str,
        turn: &str,
    ) {
        let batch = sample_batch(client_id, Uuid::now_v7(), session, thread, turn);
        let response = ingest_batch(h, token, &batch).await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn ingest_idempotent_conflict_payload_too_large_and_spoof_are_enforced() {
        let h = Harness::new().await;
        h.issue_token("client-a", "tok-client-a", TokenRole::Client)
            .await;

        let batch_id = Uuid::now_v7();
        let batch = sample_batch("client-a", batch_id, "s1", "t1", "u1");
        let response = ingest_batch(&h, "tok-client-a", &batch).await;
        assert_eq!(response.status(), StatusCode::OK);
        let ack: IngestAck = Harness::json(response).await;
        assert!(!ack.duplicate);

        let duplicate = ingest_batch(&h, "tok-client-a", &batch).await;
        assert_eq!(duplicate.status(), StatusCode::OK);
        let ack: IngestAck = Harness::json(duplicate).await;
        assert!(ack.duplicate);

        let mut conflict = sample_batch("client-a", batch_id, "s1", "t1", "u1");
        conflict.tasks[0].snapshot.model = Some("other-model".to_owned());
        let response = ingest_batch(&h, "tok-client-a", &conflict).await;
        assert_eq!(response.status(), StatusCode::CONFLICT);

        let oversized = zstd::stream::encode_all(
            vec![0_u8; codexwatch_protocol::MAX_DECOMPRESSED_BATCH_BYTES + 1].as_slice(),
            1,
        )
        .expect("compress");
        let response = h
            .request(
                Method::POST,
                "/api/v1/ingest",
                "tok-client-a",
                Body::from(oversized),
            )
            .await;
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let spoof = sample_batch("client-b", Uuid::now_v7(), "s2", "t2", "u2");
        let response = ingest_batch(&h, "tok-client-a", &spoof).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let receipt_count: i64 = sqlx::query("SELECT COUNT(*) AS count FROM ingest_receipts")
            .fetch_one(&h.pool)
            .await
            .expect("count")
            .get("count");
        assert_eq!(receipt_count, 1);
    }

    #[tokio::test]
    async fn auth_separates_client_reader_admin_paths() {
        let h = Harness::new().await;
        h.issue_token("client-a", "tok-client-a", TokenRole::Client)
            .await;
        h.issue_token("client-a", "tok-reader-a", TokenRole::Reader)
            .await;
        h.issue_token("client-b", "tok-reader-b", TokenRole::Reader)
            .await;
        h.issue_token("admin", "tok-admin", TokenRole::Admin).await;
        seed_task(&h, "client-a", "tok-client-a", "s1", "t1", "u1").await;

        let response = h
            .request(Method::GET, "/api/v1/tasks", "tok-reader-a", Body::empty())
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        let tasks: TaskListResponse = Harness::json(response).await;
        assert_eq!(tasks.tasks.len(), 1);

        let response = h
            .request(Method::GET, "/api/v1/tasks", "tok-client-a", Body::empty())
            .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let response = h
            .request(
                Method::GET,
                "/api/v1/tasks/s1:t1:u1/attempts",
                "tok-reader-a",
                Body::empty(),
            )
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        let attempts: Vec<AttemptRecord> = Harness::json(response).await;
        assert!(attempts.is_empty());

        let response = h
            .request(
                Method::GET,
                "/api/v1/sessions/client-a/s1?provider=codex&thread_id=t1",
                "tok-reader-a",
                Body::empty(),
            )
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        let session: SessionDetail = Harness::json(response).await;
        assert_eq!(session.client_id, "client-a");
        assert_eq!(session.thread_id, "t1");
        assert_eq!(session.tasks.len(), 1);

        let response = h
            .request(
                Method::GET,
                "/api/v1/tasks/s1:t1:u1",
                "tok-reader-b",
                Body::empty(),
            )
            .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let response = h
            .request(
                Method::GET,
                "/api/v1/tasks/s1:t1:u1/attempts",
                "tok-client-a",
                Body::empty(),
            )
            .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let response = h
            .request(
                Method::GET,
                "/api/v1/sessions/client-a/s1?provider=codex&thread_id=t1",
                "tok-reader-b",
                Body::empty(),
            )
            .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let body = serde_json::to_vec(&CreateContentRequestBody {
            parts: vec![ContentPart::Response],
            expires_at_ms: Some(now_ms() + 60_000),
        })
        .expect("json");
        let response = h
            .request(
                Method::POST,
                "/api/v1/tasks/s1:t1:u1/content-requests",
                "tok-reader-a",
                Body::from(body.clone()),
            )
            .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let response = h
            .request(
                Method::POST,
                "/api/v1/tasks/s1:t1:u1/content-requests",
                "tok-admin",
                Body::from(body),
            )
            .await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn content_chunk_validation_and_assembly_work() {
        let h = Harness::new().await;
        h.issue_token("client-a", "tok-client-a", TokenRole::Client)
            .await;
        h.issue_token("admin", "tok-admin", TokenRole::Admin).await;
        seed_task(&h, "client-a", "tok-client-a", "s1", "t1", "u1").await;

        let create = serde_json::to_vec(&CreateContentRequestBody {
            parts: vec![ContentPart::Response],
            expires_at_ms: Some(now_ms() + 60_000),
        })
        .expect("json");
        let response = h
            .request(
                Method::POST,
                "/api/v1/tasks/s1:t1:u1/content-requests",
                "tok-admin",
                Body::from(create),
            )
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        let request_id = latest_request_id(&h.pool).await;
        let command_id = latest_command_id(&h.pool).await;

        let raw = b"hello server";
        let compressed = zstd::stream::encode_all(raw.as_slice(), 1).expect("compress");
        let split = compressed.len() / 2;
        let manifest = ContentObjectManifest {
            request_id,
            task_ref: "s1:t1:u1".to_owned(),
            session_id: "s1".to_owned(),
            thread_id: "t1".to_owned(),
            part: ContentPart::Response,
            object_sha256: sha256_hex(raw),
            media_type: "application/zstd".to_owned(),
            uncompressed_bytes: raw.len() as u64,
            compressed_bytes: compressed.len() as u64,
            chunk_count: 2,
            created_at_ms: now_ms(),
        };
        let response = h
            .request(
                Method::POST,
                &format!("/api/v1/client/commands/{command_id}/content/manifests"),
                "tok-client-a",
                Body::from(serde_json::to_vec(&vec![manifest.clone()]).expect("json")),
            )
            .await;
        assert_eq!(response.status(), StatusCode::OK);

        let chunk0 = ContentUploadChunk {
            request_id,
            chunk_index: 0,
            chunk_count: 2,
            object_sha256: sha256_hex(raw),
            payload_sha256: sha256_hex(&compressed[..split]),
            payload_zstd: compressed[..split].to_vec(),
            is_last: false,
        };
        let chunk1 = ContentUploadChunk {
            request_id,
            chunk_index: 1,
            chunk_count: 2,
            object_sha256: sha256_hex(raw),
            payload_sha256: sha256_hex(&compressed[split..]),
            payload_zstd: compressed[split..].to_vec(),
            is_last: true,
        };

        let response = h
            .request(
                Method::POST,
                &format!("/api/v1/client/commands/{command_id}/content/chunks"),
                "tok-client-a",
                Body::from(serde_json::to_vec(&chunk0).expect("json")),
            )
            .await;
        assert_eq!(response.status(), StatusCode::OK);

        let response = h
            .request(
                Method::POST,
                &format!("/api/v1/client/commands/{command_id}/content/chunks"),
                "tok-client-a",
                Body::from(serde_json::to_vec(&chunk1).expect("json")),
            )
            .await;
        assert_eq!(response.status(), StatusCode::OK);

        let response = h
            .request(
                Method::POST,
                &format!("/api/v1/client/commands/{command_id}/result"),
                "tok-client-a",
                Body::from(
                    serde_json::to_vec(&ContentUploadResult {
                        request_id,
                        status: ContentUploadStatus::Stored,
                        note: None,
                    })
                    .expect("json"),
                ),
            )
            .await;
        assert_eq!(response.status(), StatusCode::OK);

        let stored: Vec<u8> =
            sqlx::query("SELECT content_zstd FROM content_objects WHERE object_sha256=?1")
                .bind(sha256_hex(raw))
                .fetch_one(&h.pool)
                .await
                .expect("object")
                .get("content_zstd");
        let roundtrip = zstd::stream::decode_all(stored.as_slice()).expect("decode");
        assert_eq!(roundtrip, raw);

        let mut bad = chunk0.clone();
        bad.request_id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO content_requests(request_id, client_id, task_ref, session_id, thread_id, parts_json, created_at_ms, expires_at_ms, completed_at_ms, status, outcome)
             VALUES(?1, 'client-a', 's1:t1:u1', 's1', 't1', ?2, ?3, ?4, NULL, 'pending', NULL)",
        )
        .bind(bad.request_id.to_string())
        .bind(serde_json::to_string(&vec![ContentPart::Response]).expect("parts"))
        .bind(now_ms())
        .bind(now_ms() + 60_000)
        .execute(&h.pool)
        .await
        .expect("request");
        let bad_command_id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO commands(command_id, request_id, client_id, status, created_at_ms, delivered_at_ms, completed_at_ms, payload_json)
             VALUES(?1, ?2, 'client-a', 'pending', ?3, NULL, NULL, '{}')",
        )
        .bind(bad_command_id.to_string())
        .bind(bad.request_id.to_string())
        .bind(now_ms())
        .execute(&h.pool)
        .await
        .expect("command");
        let bad_manifest = ContentObjectManifest {
            request_id: bad.request_id,
            ..manifest
        };
        sqlx::query(
            "INSERT INTO content_manifests(request_id, object_sha256, client_id, manifest_json, created_at_ms)
             VALUES(?1, ?2, 'client-a', ?3, ?4)",
        )
        .bind(bad.request_id.to_string())
        .bind(&bad.object_sha256)
        .bind(serde_json::to_string(&bad_manifest).expect("manifest"))
        .bind(now_ms())
        .execute(&h.pool)
        .await
        .expect("manifest");
        bad.payload_sha256 = "0".repeat(64);
        let response = h
            .request(
                Method::POST,
                &format!("/api/v1/client/commands/{bad_command_id}/content/chunks"),
                "tok-client-a",
                Body::from(serde_json::to_vec(&bad).expect("json")),
            )
            .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn thirty_first_conversation_evicts_full_text_only() {
        let h = Harness::new().await;
        ensure_client_exists(&h.pool, "client-a", 1)
            .await
            .expect("client");

        for index in 0..31 {
            let session = format!("s{index:02}");
            let thread = format!("t{index:02}");
            let task_ref = format!("{session}:{thread}:u{index:02}");
            seed_task_row(&h.pool, "client-a", &task_ref, &session, &thread).await;
            create_content_request_inner(
                &h.pool,
                Principal {
                    client_id: "admin".to_owned(),
                    role: TokenRole::Admin,
                },
                &task_ref,
                vec![ContentPart::Response],
                Some(now_ms() + 60_000),
            )
            .await
            .expect("request");
            let request_id = latest_request_id(&h.pool).await;
            seed_full_text(
                &h.pool, request_id, "client-a", &task_ref, &session, &thread,
            )
            .await;
        }

        let requests: i64 = sqlx::query("SELECT COUNT(*) AS count FROM content_requests")
            .fetch_one(&h.pool)
            .await
            .expect("count")
            .get("count");
        let objects: i64 = sqlx::query("SELECT COUNT(*) AS count FROM content_objects")
            .fetch_one(&h.pool)
            .await
            .expect("count")
            .get("count");
        let conversations: i64 = sqlx::query("SELECT COUNT(*) AS count FROM content_conversations")
            .fetch_one(&h.pool)
            .await
            .expect("count")
            .get("count");
        assert_eq!(requests, 31);
        assert_eq!(objects, 30);
        assert_eq!(conversations, 30);

        let oldest_links: i64 = sqlx::query(
            "SELECT COUNT(*) AS count FROM content_links WHERE session_id='s00' AND thread_id='t00'",
        )
        .fetch_one(&h.pool)
        .await
        .expect("count")
        .get("count");
        let oldest_chunks: i64 = sqlx::query(
            "SELECT COUNT(*) AS count FROM content_chunks WHERE request_id IN (
                SELECT request_id FROM content_requests WHERE session_id='s00' AND thread_id='t00'
            )",
        )
        .fetch_one(&h.pool)
        .await
        .expect("count")
        .get("count");
        let oldest_metadata: i64 = sqlx::query(
            "SELECT COUNT(*) AS count FROM content_requests WHERE session_id='s00' AND thread_id='t00'",
        )
        .fetch_one(&h.pool)
        .await
        .expect("count")
        .get("count");
        assert_eq!(oldest_links, 0);
        assert_eq!(oldest_chunks, 0);
        assert_eq!(oldest_metadata, 1);
    }

    #[tokio::test]
    async fn cleanup_retention_removes_ephemera() {
        let h = Harness::new().await;
        let old_receipt = now_ms() - RECEIPT_RETENTION_MS - 1_000;
        sqlx::query(
            "INSERT INTO ingest_receipts(client_id, batch_id, payload_sha256, received_at_ms)
             VALUES('client-a', ?1, 'hash', ?2)",
        )
        .bind(Uuid::now_v7().to_string())
        .bind(old_receipt)
        .execute(&h.pool)
        .await
        .expect("receipt");
        sqlx::query(
            "INSERT INTO heartbeats(heartbeat_id, client_id, instance_id, observed_at_ms, queue_depth, active_task_count, capture_health_json, note)
             VALUES(?1, 'client-a', ?2, ?3, 0, 0, '\"complete\"', NULL)",
        )
        .bind(Uuid::now_v7().to_string())
        .bind(Uuid::now_v7().to_string())
        .bind(now_ms() - HEARTBEAT_RETENTION_MS - 1_000)
        .execute(&h.pool)
        .await
        .expect("heartbeat");
        sqlx::query(
            "INSERT INTO http_exchanges(task_ref, exchange_id, observed_at_ms, payload_json)
             VALUES('task', ?1, ?2, '{}')",
        )
        .bind(Uuid::now_v7().to_string())
        .bind(now_ms() - EPHEMERA_RETENTION_MS - 1_000)
        .execute(&h.pool)
        .await
        .expect("exchange");

        cleanup_retention(&h.pool, now_ms()).await.expect("cleanup");

        let receipts: i64 = sqlx::query("SELECT COUNT(*) AS count FROM ingest_receipts")
            .fetch_one(&h.pool)
            .await
            .expect("count")
            .get("count");
        let heartbeats: i64 = sqlx::query("SELECT COUNT(*) AS count FROM heartbeats")
            .fetch_one(&h.pool)
            .await
            .expect("count")
            .get("count");
        let exchanges: i64 = sqlx::query("SELECT COUNT(*) AS count FROM http_exchanges")
            .fetch_one(&h.pool)
            .await
            .expect("count")
            .get("count");
        assert_eq!(receipts, 0);
        assert_eq!(heartbeats, 0);
        assert_eq!(exchanges, 0);
    }

    async fn latest_request_id(pool: &SqlitePool) -> Uuid {
        let row = sqlx::query(
            "SELECT request_id FROM content_requests ORDER BY created_at_ms DESC, request_id DESC LIMIT 1",
        )
        .fetch_one(pool)
        .await
        .expect("request");
        Uuid::parse_str(&row.get::<String, _>("request_id")).expect("uuid")
    }

    async fn latest_command_id(pool: &SqlitePool) -> Uuid {
        let row = sqlx::query(
            "SELECT command_id FROM commands ORDER BY created_at_ms DESC, command_id DESC LIMIT 1",
        )
        .fetch_one(pool)
        .await
        .expect("command");
        Uuid::parse_str(&row.get::<String, _>("command_id")).expect("uuid")
    }

    async fn seed_task_row(
        pool: &SqlitePool,
        client_id: &str,
        task_ref: &str,
        session_id: &str,
        thread_id: &str,
    ) {
        sqlx::query(
            "INSERT INTO tasks(task_ref, client_id, provider, session_id, thread_id, turn_id, phase, terminal, updated_at_ms, snapshot_json)
             VALUES(?1, ?2, 'codex', ?3, ?4, 'turn', '\"running\"', NULL, 1, ?5)",
        )
        .bind(task_ref)
        .bind(client_id)
        .bind(session_id)
        .bind(thread_id)
        .bind(
            serde_json::to_string(&TaskSnapshot {
                task_ref: task_ref.to_owned(),
                identity: TaskIdentity {
                    provider: "codex".to_owned(),
                    session_id: session_id.to_owned(),
                    thread_id: thread_id.to_owned(),
                    turn_id: "turn".to_owned(),
                },
                codex: CodexTaskMetadata {
                    request_kind: "turn".to_owned(),
                    parent_turn_id: None,
                    root_turn_id: None,
                },
                sequence: 1,
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
            })
            .expect("snapshot"),
        )
        .execute(pool)
        .await
        .expect("task");
    }

    async fn seed_full_text(
        pool: &SqlitePool,
        request_id: Uuid,
        client_id: &str,
        task_ref: &str,
        session_id: &str,
        thread_id: &str,
    ) {
        let raw = format!("{task_ref}-body").into_bytes();
        let compressed = zstd::stream::encode_all(raw.as_slice(), 1).expect("compress");
        let object_sha256 = sha256_hex(&raw);
        let now = now_ms();
        sqlx::query(
            "INSERT INTO content_chunks(request_id, object_sha256, chunk_index, chunk_count, payload_sha256, payload_zstd, is_last, received_at_ms)
             VALUES(?1, ?2, 0, 1, ?3, ?4, 1, ?5)",
        )
        .bind(request_id.to_string())
        .bind(&object_sha256)
        .bind(sha256_hex(&compressed))
        .bind(&compressed)
        .bind(now)
        .execute(pool)
        .await
        .expect("chunk");
        sqlx::query(
            "INSERT INTO content_objects(object_sha256, content_zstd, uncompressed_bytes, compressed_bytes, created_at_ms, last_accessed_at_ms)
             VALUES(?1, ?2, ?3, ?4, ?5, ?5)",
        )
        .bind(&object_sha256)
        .bind(&compressed)
        .bind(raw.len() as i64)
        .bind(compressed.len() as i64)
        .bind(now)
        .execute(pool)
        .await
        .expect("object");
        let manifest = ContentObjectManifest {
            request_id,
            task_ref: task_ref.to_owned(),
            session_id: session_id.to_owned(),
            thread_id: thread_id.to_owned(),
            part: ContentPart::Response,
            object_sha256: object_sha256.clone(),
            media_type: "application/zstd".to_owned(),
            uncompressed_bytes: raw.len() as u64,
            compressed_bytes: compressed.len() as u64,
            chunk_count: 1,
            created_at_ms: now,
        };
        sqlx::query(
            "INSERT INTO content_links(request_id, object_sha256, client_id, session_id, thread_id, manifest_json, created_at_ms, last_accessed_at_ms)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)",
        )
        .bind(request_id.to_string())
        .bind(&object_sha256)
        .bind(client_id)
        .bind(session_id)
        .bind(thread_id)
        .bind(serde_json::to_string(&manifest).expect("manifest"))
        .bind(now)
        .execute(pool)
        .await
        .expect("link");
    }
}
