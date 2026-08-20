use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use nix::unistd::{Uid, User};
use serde::Deserialize;
use uuid::Uuid;

const USER_CONFIG_DIR: &str = "codexwatch";
const CLIENT_CONFIG_FILE: &str = "client.toml";

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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientFileConfig {
    client_id: String,
    client_instance_id: Option<Uuid>,
    server_url: String,
    api_token: String,
    data_dir: Option<PathBuf>,
    database_path: Option<PathBuf>,
    blob_dir: Option<PathBuf>,
    poll_wait_seconds: Option<u32>,
    cleanup_interval_seconds: Option<u64>,
    flush_interval_millis: Option<u64>,
    heartbeat_interval_seconds: Option<u64>,
    process_scan_interval_seconds: Option<u64>,
    capture_poll_interval_millis: Option<u64>,
    capture_interface: Option<String>,
    capture_interface_index: Option<i32>,
    capture_codex_pid: Option<u32>,
    capture_process_name: Option<String>,
    #[serde(default)]
    capture_remote_ports: Vec<u16>,
    ebpf_object_path: Option<PathBuf>,
    codex_binary_path: Option<PathBuf>,
    client_version: Option<String>,
}

impl ClientConfig {
    pub fn load() -> Result<Self> {
        let path = default_config_path()?;
        let source = std::fs::read_to_string(&path)
            .with_context(|| format!("read client config {}", path.display()))?;
        Self::from_toml(&source).with_context(|| format!("parse client config {}", path.display()))
    }

    fn from_toml(source: &str) -> Result<Self> {
        let file: ClientFileConfig = toml::from_str(source)?;
        let data_dir = file
            .data_dir
            .unwrap_or_else(|| PathBuf::from("./var/client"));
        let database_path = file
            .database_path
            .unwrap_or_else(|| data_dir.join("client.db"));
        let blob_dir = file.blob_dir.unwrap_or_else(|| data_dir.join("blobs"));
        let capture_interface_index = match (
            file.capture_interface.as_deref(),
            file.capture_interface_index,
        ) {
            (Some(_), Some(_)) => {
                bail!("configure only one of capture_interface or capture_interface_index")
            }
            (Some(name), None) => Some(resolve_interface_index(name)?),
            (None, index) => index,
        };

        Ok(Self {
            client_id: file.client_id,
            client_instance_id: file.client_instance_id.unwrap_or_else(Uuid::now_v7),
            data_dir,
            database_path,
            blob_dir,
            server_url: file.server_url,
            api_token: file.api_token,
            poll_wait_seconds: file.poll_wait_seconds.unwrap_or(30),
            cleanup_interval_seconds: file.cleanup_interval_seconds.unwrap_or(300),
            flush_interval_millis: file.flush_interval_millis.unwrap_or(2_000),
            heartbeat_interval_seconds: file.heartbeat_interval_seconds.unwrap_or(60),
            process_scan_interval_seconds: file.process_scan_interval_seconds.unwrap_or(1),
            capture_poll_interval_millis: file.capture_poll_interval_millis.unwrap_or(50),
            capture_interface_index,
            capture_codex_pid: file.capture_codex_pid,
            capture_process_name: file
                .capture_process_name
                .unwrap_or_else(|| "codex".to_owned()),
            capture_remote_ports: file.capture_remote_ports,
            ebpf_object_path: file.ebpf_object_path,
            codex_binary_path: file.codex_binary_path,
            client_version: file
                .client_version
                .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_owned()),
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
                "ebpf_object_path requires codex_binary_path"
            )),
            (None, Some(_)) => Err(anyhow::anyhow!(
                "codex_binary_path requires ebpf_object_path"
            )),
        }
    }

    #[must_use]
    pub fn ebpf_enabled(&self) -> bool {
        self.ebpf_object_path.is_some() && self.codex_binary_path.is_some()
    }
}

pub fn default_config_path() -> Result<PathBuf> {
    let sudo_home = sudo_user_home()?;
    Ok(resolve_config_path(
        Uid::effective().is_root(),
        sudo_home.as_deref(),
        std::env::var_os("XDG_CONFIG_HOME")
            .as_deref()
            .map(Path::new),
        std::env::var_os("HOME").as_deref().map(Path::new),
    ))
}

fn sudo_user_home() -> Result<Option<PathBuf>> {
    let Some(name) = std::env::var_os("SUDO_USER") else {
        return Ok(None);
    };
    let name = name.to_string_lossy();
    if name.is_empty() || name == "root" {
        return Ok(None);
    }
    let user = User::from_name(&name)
        .with_context(|| format!("lookup sudo user {name}"))?
        .with_context(|| format!("sudo user {name} does not exist"))?;
    Ok(Some(user.dir))
}

fn resolve_config_path(
    effective_root: bool,
    sudo_home: Option<&Path>,
    xdg_config_home: Option<&Path>,
    home: Option<&Path>,
) -> PathBuf {
    if let Some(home) = sudo_home {
        return home
            .join(".config")
            .join(USER_CONFIG_DIR)
            .join(CLIENT_CONFIG_FILE);
    }
    if effective_root {
        return PathBuf::from("/etc/codexwatch/client.toml");
    }
    if let Some(config_home) = usable_config_root(xdg_config_home) {
        return config_home.join(USER_CONFIG_DIR).join(CLIENT_CONFIG_FILE);
    }
    if let Some(home) = usable_config_root(home) {
        return home
            .join(".config")
            .join(USER_CONFIG_DIR)
            .join(CLIENT_CONFIG_FILE);
    }
    PathBuf::from("/etc/codexwatch/client.toml")
}

fn usable_config_root(path: Option<&Path>) -> Option<&Path> {
    path.filter(|path| !path.as_os_str().is_empty() && *path != Path::new("/"))
}

fn resolve_interface_index(name: &str) -> Result<i32> {
    if name.is_empty() || name.contains('/') || matches!(name, "." | "..") {
        bail!("invalid capture_interface {name:?}");
    }
    let path = Path::new("/sys/class/net").join(name).join("ifindex");
    let value = std::fs::read_to_string(&path)
        .with_context(|| format!("read interface index for {name}"))?;
    value
        .trim()
        .parse()
        .with_context(|| format!("parse interface index from {}", path.display()))
}

#[must_use]
pub fn sqlite_url(path: &Path) -> String {
    format!("sqlite://{}", path.display())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sudo_user_config_wins_over_root_fallback() {
        let path = resolve_config_path(
            true,
            Some(Path::new("/home/alice")),
            Some(Path::new("/tmp/xdg")),
            Some(Path::new("/root")),
        );
        assert_eq!(
            path,
            PathBuf::from("/home/alice/.config/codexwatch/client.toml")
        );
    }

    #[test]
    fn normal_user_honors_xdg_config_home() {
        let path = resolve_config_path(
            false,
            None,
            Some(Path::new("/tmp/xdg")),
            Some(Path::new("/home/alice")),
        );
        assert_eq!(path, PathBuf::from("/tmp/xdg/codexwatch/client.toml"));
    }

    #[test]
    fn root_service_uses_etc_config() {
        let path = resolve_config_path(true, None, None, Some(Path::new("/root")));
        assert_eq!(path, PathBuf::from("/etc/codexwatch/client.toml"));
    }

    #[test]
    fn unusable_user_home_falls_back_to_etc() {
        let path = resolve_config_path(false, None, Some(Path::new("")), Some(Path::new("/")));
        assert_eq!(path, PathBuf::from("/etc/codexwatch/client.toml"));
    }

    #[test]
    fn minimal_config_uses_runtime_defaults() {
        let config = ClientConfig::from_toml(
            r#"
                client_id = "local"
                server_url = "http://127.0.0.1:18080"
                api_token = "test-token"
                capture_remote_ports = [8080]
            "#,
        )
        .expect("config");

        assert_eq!(config.client_id, "local");
        assert_eq!(config.capture_remote_ports, vec![8080]);
        assert_eq!(config.process_scan_interval_seconds, 1);
        assert_eq!(config.data_dir, PathBuf::from("./var/client"));
    }
}
