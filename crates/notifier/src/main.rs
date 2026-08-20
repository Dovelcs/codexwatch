use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use codexwatch_protocol::{
    CaptureHealthResponse, ErrorListResponse, EventListResponse, IntegrityState, SessionDetail,
    TaskDetail, TaskListResponse, TaskSnapshot, TerminalOutcome,
};
use reqwest::{Client, Method, StatusCode, Url};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::{process::Command, time::interval};

const CONFIG_PATH: &str = "/etc/codexwatch/notifier.toml";

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    server_url: String,
    api_token: String,
    admin_api_token: Option<String>,
    client_id: String,
    poll_interval_seconds: Option<u64>,
    notify_completed: Option<bool>,
    state_path: PathBuf,
    openclaw_binary: Option<PathBuf>,
    feishu_account: Option<String>,
    feishu_target: String,
}

impl Config {
    fn load() -> Result<Self> {
        let source =
            std::fs::read_to_string(CONFIG_PATH).with_context(|| format!("read {CONFIG_PATH}"))?;
        toml::from_str(&source).with_context(|| format!("parse {CONFIG_PATH}"))
    }

    fn poll_interval(&self) -> Duration {
        Duration::from_secs(self.poll_interval_seconds.unwrap_or(5).max(1))
    }

    fn notify_completed(&self) -> bool {
        self.notify_completed.unwrap_or(false)
    }

    fn openclaw_binary(&self) -> &Path {
        self.openclaw_binary
            .as_deref()
            .unwrap_or_else(|| Path::new("/usr/bin/openclaw"))
    }

    fn feishu_account(&self) -> &str {
        self.feishu_account.as_deref().unwrap_or("main")
    }
}

#[derive(Debug, Parser)]
#[command(name = "codexwatch-notifier")]
struct Cli {
    #[command(subcommand)]
    command: Option<CliCommand>,
}

#[derive(Debug, Subcommand)]
enum CliCommand {
    Daemon,
    Test,
    Tasks(ListArgs),
    Task(TaskArgs),
    Session(SessionArgs),
    Attempts(TaskArgs),
    Events(TaskArgs),
    Errors(TaskArgs),
    CaptureHealth,
    RequestContent(RequestContentArgs),
}

#[derive(Debug, Args)]
struct ListArgs {
    #[arg(long)]
    session_id: Option<String>,
    #[arg(long, default_value_t = 20)]
    limit: u32,
}

#[derive(Debug, Args)]
struct TaskArgs {
    task_ref: String,
}

#[derive(Debug, Args)]
struct SessionArgs {
    session_id: String,
    #[arg(long)]
    thread_id: Option<String>,
}

#[derive(Debug, Args)]
struct RequestContentArgs {
    task_ref: String,
    #[arg(long, value_delimiter = ',', default_value = "request,response")]
    parts: Vec<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct NotificationState {
    initialized: bool,
    completed_tasks: BTreeSet<String>,
    abnormal_tasks: BTreeSet<String>,
}

impl NotificationState {
    fn load(path: &Path) -> Result<Self> {
        match std::fs::read(path) {
            Ok(bytes) => {
                serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(error).with_context(|| format!("read {}", path.display())),
        }
    }

    fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let temporary = path.with_extension("tmp");
        std::fs::write(&temporary, serde_json::to_vec(self)?)?;
        std::fs::rename(&temporary, path)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NoticeKind {
    Completed,
    Abnormal,
}

struct ServerApi {
    client: Client,
    base_url: Url,
    token: String,
    admin_token: Option<String>,
    client_id: String,
}

impl ServerApi {
    fn new(config: &Config) -> Result<Self> {
        Ok(Self {
            client: Client::builder().timeout(Duration::from_secs(10)).build()?,
            base_url: Url::parse(&config.server_url)?,
            token: config.api_token.clone(),
            admin_token: config.admin_api_token.clone(),
            client_id: config.client_id.clone(),
        })
    }

    async fn tasks(&self, session_id: Option<&str>, limit: u32) -> Result<TaskListResponse> {
        let mut url = self.url(&["api", "v1", "tasks"])?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("client_id", &self.client_id);
            query.append_pair("limit", &limit.min(500).to_string());
            if let Some(session_id) = session_id {
                query.append_pair("session_id", session_id);
            }
        }
        self.get(url).await
    }

    async fn task<T: DeserializeOwned>(&self, task_ref: &str, suffix: Option<&str>) -> Result<T> {
        let mut parts = vec!["api", "v1", "tasks", task_ref];
        if let Some(suffix) = suffix {
            parts.push(suffix);
        }
        self.get(self.url(&parts)?).await
    }

    async fn session(&self, session_id: &str, thread_id: Option<&str>) -> Result<SessionDetail> {
        let mut url = self.url(&["api", "v1", "sessions", &self.client_id, session_id])?;
        if let Some(thread_id) = thread_id {
            url.query_pairs_mut()
                .append_pair("provider", "codex")
                .append_pair("thread_id", thread_id);
        }
        self.get(url).await
    }

    async fn capture_health(&self) -> Result<CaptureHealthResponse> {
        self.get(self.url(&["api", "v1", "capture-health", &self.client_id])?)
            .await
    }

    async fn request_content(&self, task_ref: &str, parts: &[String]) -> Result<()> {
        let token = self
            .admin_token
            .as_deref()
            .context("admin_api_token is required for request-content")?;
        let url = self.url(&["api", "v1", "tasks", task_ref, "content-requests"])?;
        let response = self
            .client
            .request(Method::POST, url)
            .bearer_auth(token)
            .json(&serde_json::json!({"parts": parts}))
            .send()
            .await?;
        if !response.status().is_success() {
            bail!("content request failed: {}", response.status());
        }
        Ok(())
    }

    async fn get<T: DeserializeOwned>(&self, url: Url) -> Result<T> {
        let response = self.client.get(url).bearer_auth(&self.token).send().await?;
        if response.status() != StatusCode::OK {
            bail!("server request failed: {}", response.status());
        }
        Ok(response.json().await?)
    }

    fn url(&self, parts: &[&str]) -> Result<Url> {
        let mut url = self.base_url.clone();
        url.set_query(None);
        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|()| anyhow::anyhow!("server_url cannot be a base URL"))?;
            segments.clear();
            for part in parts {
                segments.push(part);
            }
        }
        Ok(url)
    }
}

async fn send_feishu(config: &Config, message: &str) -> Result<()> {
    let output = Command::new(config.openclaw_binary())
        .args([
            "message",
            "send",
            "--channel",
            "feishu",
            "--account",
            config.feishu_account(),
            "--target",
            &config.feishu_target,
            "--message",
            message,
            "--json",
        ])
        .env("HOME", "/root")
        .stdin(Stdio::null())
        .output()
        .await?;
    if !output.status.success() {
        bail!(
            "OpenClaw Feishu send failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

fn notice_kind(task: &TaskSnapshot) -> Option<NoticeKind> {
    if task.last_error.is_some() || task.integrity != IntegrityState::Complete {
        return Some(NoticeKind::Abnormal);
    }
    match task.terminal {
        Some(TerminalOutcome::Completed) => Some(NoticeKind::Completed),
        Some(_) => Some(NoticeKind::Abnormal),
        None => None,
    }
}

fn notice_message(task: &TaskSnapshot, kind: NoticeKind) -> String {
    let title = task
        .conversation_title
        .as_deref()
        .unwrap_or(&task.identity.session_id);
    let observed_at = format_timestamp(task.updated_at_ms);
    match kind {
        NoticeKind::Completed => format!(
            "[CodexWatch 完成]\n对话：{title}\n任务：{}\n模型：{}\n时间：{observed_at}",
            task.identity.turn_id,
            task.model.as_deref().unwrap_or("未知")
        ),
        NoticeKind::Abnormal => {
            let result = task
                .terminal
                .map_or_else(|| enum_name(task.integrity), enum_name);
            let reason = task
                .last_error
                .as_ref()
                .map_or_else(|| result.clone(), |error| error.message.clone());
            format!(
                "[CodexWatch 异常]\n对话：{title}\n任务：{}\n状态：{result}\n原因：{reason}\n时间：{observed_at}",
                task.identity.turn_id
            )
        }
    }
}

fn enum_name(value: impl Serialize) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
        .unwrap_or_else(|| "unknown".to_owned())
}

fn format_timestamp(timestamp_ms: i64) -> String {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(timestamp_ms) * 1_000_000)
        .ok()
        .and_then(|value| value.format(&Rfc3339).ok())
        .unwrap_or_else(|| timestamp_ms.to_string())
}

async fn process_tasks(
    config: &Config,
    state: &mut NotificationState,
    tasks: &[TaskSnapshot],
    deliver: bool,
) -> Result<()> {
    for task in tasks.iter().rev() {
        let Some(kind) = notice_kind(task) else {
            continue;
        };
        if kind == NoticeKind::Abnormal && task.conversation_title.is_none() {
            continue;
        }
        let seen = match kind {
            NoticeKind::Completed => state.completed_tasks.contains(&task.task_ref),
            NoticeKind::Abnormal => state.abnormal_tasks.contains(&task.task_ref),
        };
        if seen {
            continue;
        }
        if deliver && (kind != NoticeKind::Completed || config.notify_completed()) {
            send_feishu(config, &notice_message(task, kind)).await?;
        }
        match kind {
            NoticeKind::Completed => state.completed_tasks.insert(task.task_ref.clone()),
            NoticeKind::Abnormal => state.abnormal_tasks.insert(task.task_ref.clone()),
        };
        state.save(&config.state_path)?;
    }
    Ok(())
}

async fn run_daemon(config: &Config, api: &ServerApi) -> Result<()> {
    let mut state = NotificationState::load(&config.state_path)?;
    let mut ticker = interval(config.poll_interval());
    loop {
        ticker.tick().await;
        let tasks = api.tasks(None, 500).await?;
        let deliver = state.initialized;
        process_tasks(config, &mut state, &tasks.tasks, deliver).await?;
        if !state.initialized {
            state.initialized = true;
            state.save(&config.state_path)?;
        }
    }
}

fn print_json(value: &impl Serialize) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let config = Config::load()?;
    let api = ServerApi::new(&config)?;
    match cli.command.unwrap_or(CliCommand::Daemon) {
        CliCommand::Daemon => run_daemon(&config, &api).await,
        CliCommand::Test => send_feishu(&config, "[CodexWatch 测试]\n通知链路工作正常。").await,
        CliCommand::Tasks(args) => {
            print_json(&api.tasks(args.session_id.as_deref(), args.limit).await?)
        }
        CliCommand::Task(args) => print_json(&api.task::<TaskDetail>(&args.task_ref, None).await?),
        CliCommand::Session(args) => print_json(
            &api.session(&args.session_id, args.thread_id.as_deref())
                .await?,
        ),
        CliCommand::Attempts(args) => print_json(
            &api.task::<serde_json::Value>(&args.task_ref, Some("attempts"))
                .await?,
        ),
        CliCommand::Events(args) => print_json(
            &api.task::<EventListResponse>(&args.task_ref, Some("events"))
                .await?,
        ),
        CliCommand::Errors(args) => print_json(
            &api.task::<ErrorListResponse>(&args.task_ref, Some("errors"))
                .await?,
        ),
        CliCommand::CaptureHealth => print_json(&api.capture_health().await?),
        CliCommand::RequestContent(args) => {
            api.request_content(&args.task_ref, &args.parts).await?;
            print_json(&serde_json::json!({"ok": true}))
        }
    }
}

#[cfg(test)]
mod tests {
    use codexwatch_protocol::{
        CodexTaskMetadata, ErrorRecord, ErrorSource, TaskIdentity, TaskPhase, UsageSummary,
    };
    use uuid::Uuid;

    use super::*;

    fn task() -> TaskSnapshot {
        TaskSnapshot {
            task_ref: "s:t:u".to_owned(),
            identity: TaskIdentity {
                provider: "codex".to_owned(),
                session_id: "s".to_owned(),
                thread_id: "t".to_owned(),
                turn_id: "u".to_owned(),
            },
            codex: CodexTaskMetadata {
                request_kind: "turn".to_owned(),
                parent_turn_id: None,
                root_turn_id: None,
            },
            conversation_title: Some("real title".to_owned()),
            sequence: 1,
            phase: TaskPhase::Running,
            terminal: None,
            integrity: IntegrityState::Complete,
            model: Some("gpt-5".to_owned()),
            attempt_count: 1,
            tool_names: Vec::new(),
            response_ids: Vec::new(),
            usage: UsageSummary::default(),
            started_at_ms: 1,
            updated_at_ms: 2,
            completed_at_ms: None,
            last_error: None,
        }
    }

    #[test]
    fn classifies_completion_and_abnormality() {
        let mut snapshot = task();
        assert_eq!(notice_kind(&snapshot), None);
        snapshot.terminal = Some(TerminalOutcome::Completed);
        assert_eq!(notice_kind(&snapshot), Some(NoticeKind::Completed));
        snapshot.last_error = Some(ErrorRecord {
            error_id: Uuid::now_v7(),
            task_ref: snapshot.task_ref.clone(),
            attempt_id: None,
            occurred_at_ms: 2,
            source: ErrorSource::HttpStatus,
            wire_type: None,
            code: Some("bad_gateway".to_owned()),
            message: "gateway failed".to_owned(),
            param: None,
            reason: None,
            http_status: Some(502),
            exit_code: None,
            signal: None,
        });
        assert_eq!(notice_kind(&snapshot), Some(NoticeKind::Abnormal));
        assert!(notice_message(&snapshot, NoticeKind::Abnormal).contains("real title"));
        assert!(notice_message(&snapshot, NoticeKind::Abnormal).contains("gateway failed"));
    }

    #[test]
    fn state_round_trip_is_atomic() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("state.json");
        let mut state = NotificationState {
            initialized: true,
            ..NotificationState::default()
        };
        state.completed_tasks.insert("task".to_owned());
        state.save(&path).expect("save");
        assert_eq!(
            NotificationState::load(&path)
                .expect("load")
                .completed_tasks,
            state.completed_tasks
        );
    }

    #[test]
    fn completion_notifications_default_off() {
        let config = Config {
            server_url: "http://127.0.0.1:18080".to_owned(),
            api_token: "reader".to_owned(),
            admin_api_token: None,
            client_id: "local".to_owned(),
            poll_interval_seconds: None,
            notify_completed: None,
            state_path: PathBuf::from("/tmp/state.json"),
            openclaw_binary: None,
            feishu_account: None,
            feishu_target: "ou_test".to_owned(),
        };
        assert!(!config.notify_completed());
    }
}
