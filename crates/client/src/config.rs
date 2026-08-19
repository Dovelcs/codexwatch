use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub client_id: String,
    pub client_instance_id: Uuid,
    pub data_dir: PathBuf,
    pub database_path: PathBuf,
    pub blob_dir: PathBuf,
    pub server_url: String,
    pub api_token: String,
    pub poll_wait_seconds: u32,
    pub cleanup_interval_seconds: u64,
    pub flush_interval_millis: u64,
    pub heartbeat_interval_seconds: u64,
    pub process_scan_interval_seconds: u64,
    pub capture_poll_interval_millis: u64,
    pub capture_interface_index: Option<i32>,
    pub capture_codex_pid: Option<u32>,
    pub capture_process_name: String,
    pub capture_remote_ports: Vec<u16>,
    pub ebpf_object_path: Option<PathBuf>,
    pub codex_binary_path: Option<PathBuf>,
    pub client_version: String,
}

impl ClientConfig {
    pub fn from_env() -> Result<Self> {
        let data_dir = std::env::var("CODEXWATCH_DATA_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("./var/client"));
        let database_path = std::env::var("CODEXWATCH_DB_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| data_dir.join("client.db"));
        let blob_dir = std::env::var("CODEXWATCH_BLOB_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| data_dir.join("blobs"));

        let client_id = std::env::var("CODEXWATCH_CLIENT_ID")
            .unwrap_or_else(|_| format!("client-{}", Uuid::now_v7()));
        let client_instance_id = std::env::var("CODEXWATCH_CLIENT_INSTANCE_ID")
            .ok()
            .and_then(|value| Uuid::parse_str(&value).ok())
            .unwrap_or_else(Uuid::now_v7);

        let server_url =
            std::env::var("CODEXWATCH_SERVER_URL").context("missing CODEXWATCH_SERVER_URL")?;
        let api_token =
            std::env::var("CODEXWATCH_API_TOKEN").context("missing CODEXWATCH_API_TOKEN")?;

        Ok(Self {
            client_id,
            client_instance_id,
            data_dir,
            database_path,
            blob_dir,
            server_url,
            api_token,
            poll_wait_seconds: std::env::var("CODEXWATCH_POLL_WAIT_SECONDS")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(30),
            cleanup_interval_seconds: std::env::var("CODEXWATCH_CLEANUP_INTERVAL_SECONDS")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(300),
            flush_interval_millis: std::env::var("CODEXWATCH_FLUSH_INTERVAL_MILLIS")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(2_000),
            heartbeat_interval_seconds: std::env::var("CODEXWATCH_HEARTBEAT_INTERVAL_SECONDS")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(60),
            process_scan_interval_seconds: std::env::var(
                "CODEXWATCH_PROCESS_SCAN_INTERVAL_SECONDS",
            )
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(1),
            capture_poll_interval_millis: std::env::var("CODEXWATCH_CAPTURE_POLL_INTERVAL_MILLIS")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(50),
            capture_interface_index: std::env::var("CODEXWATCH_CAPTURE_INTERFACE_INDEX")
                .ok()
                .and_then(|value| value.parse().ok()),
            capture_codex_pid: std::env::var("CODEXWATCH_CODEX_PID")
                .ok()
                .and_then(|value| value.parse().ok()),
            capture_process_name: std::env::var("CODEXWATCH_CODEX_PROCESS_NAME")
                .unwrap_or_else(|_| "codex".to_string()),
            capture_remote_ports: std::env::var("CODEXWATCH_CAPTURE_REMOTE_PORTS")
                .ok()
                .map(|value| {
                    value
                        .split(',')
                        .filter_map(|part| part.trim().parse().ok())
                        .collect()
                })
                .unwrap_or_default(),
            ebpf_object_path: std::env::var("CODEXWATCH_EBPF_OBJECT_PATH")
                .ok()
                .map(PathBuf::from),
            codex_binary_path: std::env::var("CODEXWATCH_CODEX_BINARY")
                .ok()
                .map(PathBuf::from),
            client_version: std::env::var("CODEXWATCH_CLIENT_VERSION")
                .unwrap_or_else(|_| env!("CARGO_PKG_VERSION").to_string()),
        })
    }

    pub fn ensure_paths(&self) -> Result<()> {
        std::fs::create_dir_all(&self.data_dir)?;
        std::fs::create_dir_all(&self.blob_dir)?;
        if let Some(parent) = self.database_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        Ok(())
    }

    #[must_use]
    pub fn database_url(&self) -> String {
        sqlite_url(&self.database_path)
    }

    #[must_use]
    pub fn capture_enabled(&self) -> bool {
        self.capture_interface_index.is_some()
    }

    pub fn validate_ebpf_config(&self) -> Result<()> {
        match (&self.ebpf_object_path, &self.codex_binary_path) {
            (Some(_), Some(_)) | (None, None) => Ok(()),
            (Some(_), None) => Err(anyhow::anyhow!(
                "CODEXWATCH_EBPF_OBJECT_PATH requires CODEXWATCH_CODEX_BINARY"
            )),
            (None, Some(_)) => Err(anyhow::anyhow!(
                "CODEXWATCH_CODEX_BINARY requires CODEXWATCH_EBPF_OBJECT_PATH"
            )),
        }
    }

    #[must_use]
    pub fn ebpf_enabled(&self) -> bool {
        self.ebpf_object_path.is_some() && self.codex_binary_path.is_some()
    }
}

#[must_use]
pub fn sqlite_url(path: &Path) -> String {
    format!("sqlite://{}", path.display())
}
