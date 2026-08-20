use std::{collections::BTreeMap, path::PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use codexwatch_protocol::{ContentUploadResult, ContentUploadStatus};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tokio::{
    sync::mpsc,
    task::JoinSet,
    time::{Duration, interval},
};
use tracing::{info, warn};

use crate::{
    blob::StoredContentInput,
    capture_lane::{
        CaptureInput, LiveCaptureLane, LiveCaptureSource, NoopProcessDiscovery, PassiveTapSource,
        ProcessDiscovery, ProcfsProcessDiscovery, SharedProcessIndex,
    },
    config::ClientConfig,
    ebpf_lane::{EbpfFactory, SharedCaptureHealth, ebpf_factory_from_config, run_ebpf_loop},
    model::{HeartbeatSummary, SummaryRecord},
    store::{ClientStore, PersistOutcome, UploadPreparation},
    transport::ServerApi,
};

#[derive(Debug, Clone, Default)]
pub struct ClientIngress {
    pub records: Vec<SummaryRecord>,
    pub contents: Vec<StoredContentInput>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FixtureBundle {
    #[serde(default)]
    pub records: Vec<SummaryRecord>,
    #[serde(default)]
    pub contents: Vec<FixtureContent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixtureContent {
    pub task: crate::model::TaskKey,
    pub part: codexwatch_protocol::ContentPart,
    pub media_type: String,
    pub body_base64: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default = "OffsetDateTime::now_utc")]
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Clone)]
pub struct ClientService {
    store: ClientStore,
    api: ServerApi,
    config: ClientConfig,
}

impl ClientService {
    pub async fn open(config: ClientConfig) -> Result<Self> {
        let store = ClientStore::open(&config).await?;
        let api = ServerApi::new(&config)?;
        Ok(Self { store, api, config })
    }

    pub fn store(&self) -> &ClientStore {
        &self.store
    }

    pub async fn ingest(&self, ingress: ClientIngress) -> Result<PersistOutcome> {
        self.store
            .persist_ingress(ingress.records, ingress.contents)
            .await
    }

    pub async fn ingest_fixture(&self, fixture: FixtureBundle) -> Result<PersistOutcome> {
        let contents = fixture
            .contents
            .into_iter()
            .map(|content| {
                Ok(StoredContentInput {
                    task: content.task,
                    part: content.part,
                    media_type: content.media_type,
                    body: base64_decode(&content.body_base64)?,
                    headers: content.headers,
                    created_at: content.created_at,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        self.ingest(ClientIngress {
            records: fixture.records,
            contents,
        })
        .await
    }

    pub async fn flush_outbox_once(&self) -> Result<()> {
        let Some(batch) = self.store.next_due_batch(OffsetDateTime::now_utc()).await? else {
            return Ok(());
        };
        match self
            .api
            .post_ingest(&batch.payload_sha256, batch.body.clone())
            .await
        {
            Ok(Some(ack)) => self.store.mark_batch_acked(&ack).await,
            Ok(None) => Ok(()),
            Err(error) => {
                warn!("ingest retry scheduled: {error:#}");
                self.store
                    .mark_batch_retry(batch.batch_id, &error.to_string())
                    .await
            }
        }
    }

    pub async fn poll_command_once(&self) -> Result<()> {
        let response = self
            .api
            .poll_commands(self.config.poll_wait_seconds)
            .await?;
        self.store.save_commands(&response).await
    }

    pub async fn execute_due_command_once(&self) -> Result<()> {
        let Some(stored) = self
            .store
            .next_due_command(OffsetDateTime::now_utc())
            .await?
        else {
            return Ok(());
        };
        match self.store.prepare_upload(&stored.command).await? {
            UploadPreparation::Expired { command_id, result } => {
                self.api.post_upload_result(command_id, &result).await?;
                self.store
                    .complete_command(command_id, &result, false)
                    .await
            }
            UploadPreparation::Ready(work) => {
                if let Err(error) = self
                    .api
                    .post_manifests(work.command_id, &work.manifests)
                    .await
                {
                    self.store
                        .fail_command(work.command_id, &error.to_string(), true)
                        .await?;
                    return Ok(());
                }
                for manifest in &work.manifests {
                    for chunk in self.store.load_chunks(manifest).await? {
                        if let Err(error) = self.api.post_chunk(work.command_id, &chunk).await {
                            self.store
                                .fail_command(work.command_id, &error.to_string(), true)
                                .await?;
                            return Ok(());
                        }
                    }
                }
                let result = ContentUploadResult {
                    request_id: work.request_id,
                    status: ContentUploadStatus::Stored,
                    note: None,
                };
                self.api
                    .post_upload_result(work.command_id, &result)
                    .await?;
                self.store
                    .complete_command(work.command_id, &result, false)
                    .await
            }
        }
    }

    pub async fn cleanup_once(&self) -> Result<()> {
        self.store.cleanup(OffsetDateTime::now_utc()).await
    }

    pub async fn emit_heartbeat_once(&self, runtime_health: &SharedCaptureHealth) -> Result<()> {
        let snapshot = self.store.health_snapshot().await?;
        let health = runtime_health.snapshot(snapshot.active_flows as u32, snapshot.outbox_bytes);
        self.store
            .persist_ingress(
                vec![SummaryRecord::Heartbeat(HeartbeatSummary {
                    client_instance_id: self.config.client_instance_id,
                    observed_at: OffsetDateTime::now_utc(),
                    client_version: self.config.client_version.clone(),
                    health,
                })],
                Vec::new(),
            )
            .await?;
        Ok(())
    }

    pub async fn health_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(
            &self.store.health_snapshot().await?,
        )?)
    }

    pub async fn run_once(&self) -> Result<()> {
        self.flush_outbox_once().await?;
        self.poll_command_once().await?;
        self.execute_due_command_once().await?;
        self.cleanup_once().await?;
        Ok(())
    }

    pub async fn run_daemon(&self) -> Result<()> {
        self.config.validate_ebpf_config()?;
        let shared_index = SharedProcessIndex::default();
        let runtime_health = SharedCaptureHealth::default();
        let capture = if let Some(interface_index) = self.config.capture_interface_index {
            runtime_health.set_af_packet_active(true);
            Some(Box::new(PassiveTapSource::open(
                interface_index,
                shared_index.clone(),
                self.config.capture_remote_ports.iter().copied(),
            )?) as Box<dyn LiveCaptureSource>)
        } else {
            None
        };
        let discovery = if self.config.capture_enabled() || self.config.capture_codex_pid.is_some()
        {
            Box::new(ProcfsProcessDiscovery::new(
                self.config.clone(),
                shared_index.clone(),
            )) as Box<dyn ProcessDiscovery>
        } else {
            Box::new(NoopProcessDiscovery) as Box<dyn ProcessDiscovery>
        };
        let ebpf_factory = ebpf_factory_from_config(&self.config)?;
        self.run_daemon_with_components(
            capture,
            discovery,
            ebpf_factory,
            runtime_health,
            shared_index,
        )
        .await
    }

    pub async fn run_daemon_with_sources(
        &self,
        capture: Option<Box<dyn LiveCaptureSource>>,
        discovery: Box<dyn ProcessDiscovery>,
    ) -> Result<()> {
        self.run_daemon_with_components(
            capture,
            discovery,
            None,
            SharedCaptureHealth::default(),
            SharedProcessIndex::default(),
        )
        .await
    }

    pub async fn run_daemon_with_components(
        &self,
        capture: Option<Box<dyn LiveCaptureSource>>,
        discovery: Box<dyn ProcessDiscovery>,
        ebpf_factory: Option<Box<dyn EbpfFactory>>,
        runtime_health: SharedCaptureHealth,
        shared_index: SharedProcessIndex,
    ) -> Result<()> {
        let (tx, rx) = mpsc::channel::<CaptureInput>(512);
        let mut tasks = JoinSet::new();

        let lane_store = self.store.clone();
        let lane_config = self.config.clone();
        tasks.spawn(async move {
            run_capture_ingest_loop(LiveCaptureLane::new(lane_config, lane_store), rx).await
        });

        if let Some(capture) = capture {
            let poll = Duration::from_millis(self.config.capture_poll_interval_millis);
            let capture_tx = tx.clone();
            tasks.spawn(async move { run_capture_source_loop(capture, capture_tx, poll).await });
        }

        let discovery_interval = Duration::from_secs(self.config.process_scan_interval_seconds);
        let discovery_tx = tx.clone();
        tasks.spawn(async move {
            run_process_source_loop(discovery, discovery_tx, discovery_interval).await
        });

        if let Some(ebpf_factory) = ebpf_factory {
            let ebpf_tx = tx.clone();
            let ebpf_health = runtime_health.clone();
            let ebpf_index = shared_index.clone();
            tasks.spawn(async move {
                run_ebpf_loop(
                    ebpf_factory,
                    ebpf_health,
                    ebpf_index,
                    ebpf_tx,
                    Duration::from_secs(1),
                )
                .await
            });
        }

        let flush_service = self.clone();
        tasks.spawn(async move {
            let mut ticker = interval(Duration::from_millis(
                flush_service.config.flush_interval_millis,
            ));
            let mut backoff_seconds = 1_u64;
            loop {
                ticker.tick().await;
                match flush_service.flush_outbox_once().await {
                    Ok(()) => backoff_seconds = 1,
                    Err(error) => {
                        warn!("flush loop error: {error:#}");
                        tokio::time::sleep(Duration::from_secs(backoff_seconds)).await;
                        backoff_seconds = (backoff_seconds * 2).min(30);
                    }
                }
            }
            #[allow(unreachable_code)]
            Ok::<(), anyhow::Error>(())
        });

        let command_service = self.clone();
        tasks.spawn(async move {
            let mut backoff_seconds = 1_u64;
            loop {
                match command_service.poll_command_once().await {
                    Ok(()) => {
                        backoff_seconds = 1;
                        if let Err(error) = command_service.execute_due_command_once().await {
                            warn!("command execute error: {error:#}");
                        }
                    }
                    Err(error) => {
                        warn!("command poll error: {error:#}");
                        tokio::time::sleep(Duration::from_secs(backoff_seconds)).await;
                        backoff_seconds = (backoff_seconds * 2).min(30);
                    }
                }
            }
            #[allow(unreachable_code)]
            Ok::<(), anyhow::Error>(())
        });

        let cleanup_service = self.clone();
        tasks.spawn(async move {
            let mut ticker = interval(Duration::from_secs(
                cleanup_service.config.cleanup_interval_seconds,
            ));
            let mut backoff_seconds = 1_u64;
            loop {
                ticker.tick().await;
                match cleanup_service.cleanup_once().await {
                    Ok(()) => backoff_seconds = 1,
                    Err(error) => {
                        warn!("cleanup loop error: {error:#}");
                        tokio::time::sleep(Duration::from_secs(backoff_seconds)).await;
                        backoff_seconds = (backoff_seconds * 2).min(30);
                    }
                }
            }
            #[allow(unreachable_code)]
            Ok::<(), anyhow::Error>(())
        });

        let heartbeat_service = self.clone();
        let heartbeat_health = runtime_health.clone();
        tasks.spawn(async move {
            let mut ticker = interval(Duration::from_secs(
                heartbeat_service.config.heartbeat_interval_seconds,
            ));
            let mut backoff_seconds = 1_u64;
            loop {
                ticker.tick().await;
                match heartbeat_service
                    .emit_heartbeat_once(&heartbeat_health)
                    .await
                {
                    Ok(()) => backoff_seconds = 1,
                    Err(error) => {
                        warn!("heartbeat loop error: {error:#}");
                        tokio::time::sleep(Duration::from_secs(backoff_seconds)).await;
                        backoff_seconds = (backoff_seconds * 2).min(30);
                    }
                }
            }
            #[allow(unreachable_code)]
            Ok::<(), anyhow::Error>(())
        });

        while let Some(result) = tasks.join_next().await {
            result??;
        }
        Ok(())
    }
}

#[derive(Debug, Parser)]
#[command(name = "codexwatch-client")]
#[command(about = "CodexWatch passive monitoring client")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<CliCommand>,
}

#[derive(Debug, Subcommand)]
pub enum CliCommand {
    Daemon {
        #[arg(long)]
        once: bool,
    },
    FixtureIngest {
        #[arg(long)]
        input: Option<PathBuf>,
        #[arg(long)]
        flush: bool,
    },
    Health,
    Cleanup,
}

pub async fn run_cli(cli: Cli) -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init()
        .ok();
    let config = ClientConfig::load()?;
    let service = ClientService::open(config).await?;
    match cli.command.unwrap_or(CliCommand::Daemon { once: false }) {
        CliCommand::Daemon { once } => {
            if once {
                service.run_once().await?;
            } else {
                service.run_daemon().await?;
            }
        }
        CliCommand::FixtureIngest { input, flush } => {
            let fixture = read_fixture(input).await?;
            let outcome = service.ingest_fixture(fixture).await?;
            if flush {
                service.flush_outbox_once().await?;
            }
            info!("fixture ingested: {outcome:?}");
        }
        CliCommand::Health => {
            println!("{}", service.health_json().await?);
        }
        CliCommand::Cleanup => {
            service.cleanup_once().await?;
        }
    }
    Ok(())
}

async fn read_fixture(path: Option<PathBuf>) -> Result<FixtureBundle> {
    let bytes = if let Some(path) = path {
        tokio::fs::read(path).await?
    } else {
        let mut stdin = tokio::io::stdin();
        let mut bytes = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut stdin, &mut bytes).await?;
        bytes
    };
    serde_json::from_slice(&bytes).context("parse fixture json")
}

fn base64_decode(value: &str) -> Result<Vec<u8>> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut reverse = [255u8; 256];
    for (index, byte) in TABLE.iter().enumerate() {
        reverse[*byte as usize] = index as u8;
    }

    let filtered: Vec<u8> = value
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    if filtered.len() % 4 != 0 {
        anyhow::bail!("invalid base64 length");
    }

    let mut out = Vec::with_capacity((filtered.len() / 4) * 3);
    for chunk in filtered.chunks(4) {
        let mut nums = [0u8; 4];
        let mut padding = 0usize;
        for (index, byte) in chunk.iter().enumerate() {
            if *byte == b'=' {
                nums[index] = 0;
                padding += 1;
            } else {
                let decoded = reverse[*byte as usize];
                if decoded == 255 {
                    anyhow::bail!("invalid base64 character");
                }
                nums[index] = decoded;
            }
        }
        out.push((nums[0] << 2) | (nums[1] >> 4));
        if padding < 2 {
            out.push((nums[1] << 4) | (nums[2] >> 2));
        }
        if padding < 1 {
            out.push((nums[2] << 6) | nums[3]);
        }
    }
    Ok(out)
}

async fn run_capture_ingest_loop(
    mut lane: LiveCaptureLane,
    mut rx: mpsc::Receiver<CaptureInput>,
) -> Result<()> {
    while let Some(input) = rx.recv().await {
        lane.ingest_input(input).await?;
    }
    Ok(())
}

async fn run_capture_source_loop(
    mut source: Box<dyn LiveCaptureSource>,
    tx: mpsc::Sender<CaptureInput>,
    poll: Duration,
) -> Result<()> {
    let mut scratch = vec![0_u8; crate::capture_lane::CAPTURE_BUFFER_BYTES];
    loop {
        match source.recv(&mut scratch) {
            Ok(Some(input)) => {
                if tx.send(input).await.is_err() {
                    return Ok(());
                }
            }
            Ok(None) => tokio::time::sleep(poll).await,
            Err(error) => return Err(error),
        }
    }
}

async fn run_process_source_loop(
    mut discovery: Box<dyn ProcessDiscovery>,
    tx: mpsc::Sender<CaptureInput>,
    interval: Duration,
) -> Result<()> {
    let mut backoff_seconds = 1_u64;
    loop {
        match discovery.poll(OffsetDateTime::now_utc()) {
            Ok(events) => {
                backoff_seconds = 1;
                for event in events {
                    if tx.send(event).await.is_err() {
                        return Ok(());
                    }
                }
                tokio::time::sleep(interval).await;
            }
            Err(error) => {
                warn!("process discovery error: {error:#}");
                tokio::time::sleep(Duration::from_secs(backoff_seconds)).await;
                backoff_seconds = (backoff_seconds * 2).min(30);
            }
        }
    }
}

#[cfg(test)]
mod cli_tests {
    use clap::Parser as _;

    use super::*;

    #[test]
    fn no_arguments_select_daemon_mode() {
        let cli = Cli::try_parse_from(["codexwatch-client"]).expect("cli");
        assert!(cli.command.is_none());
    }
}
