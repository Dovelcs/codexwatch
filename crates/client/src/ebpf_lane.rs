use std::{
    path::PathBuf,
    sync::{Arc, RwLock},
};

use anyhow::Result;
use codexwatch_capture_ebpf::{
    CaptureLoader, LoaderEvent, OwnedCaptureRecord, RunningCapture, abi::ProbeKind,
    profile::BuildFingerprint,
};
use time::OffsetDateTime;
use tokio::{sync::mpsc, time::Duration};
use uuid::Uuid;

use crate::{
    capture_lane::{CaptureInput, SharedProcessIndex},
    config::ClientConfig,
    model::{CaptureHealth, ProcessSummary, StructuredError, UnsupportedCodexBuild},
};

#[derive(Debug, Clone)]
pub struct SharedCaptureHealth {
    inner: Arc<RwLock<RuntimeCaptureHealth>>,
}

#[derive(Debug, Clone)]
struct RuntimeCaptureHealth {
    af_packet_active: bool,
    uprobe_active: bool,
    profile_supported: bool,
    ring_buffer_drops: u64,
    last_error: Option<StructuredError>,
}

impl Default for SharedCaptureHealth {
    fn default() -> Self {
        Self {
            inner: Arc::new(RwLock::new(RuntimeCaptureHealth {
                af_packet_active: false,
                uprobe_active: false,
                profile_supported: true,
                ring_buffer_drops: 0,
                last_error: None,
            })),
        }
    }
}

impl SharedCaptureHealth {
    pub fn set_af_packet_active(&self, active: bool) {
        if let Ok(mut guard) = self.inner.write() {
            guard.af_packet_active = active;
        }
    }

    pub fn set_unsupported_build(&self, fingerprint: &BuildFingerprint) {
        if let Ok(mut guard) = self.inner.write() {
            guard.uprobe_active = false;
            guard.profile_supported = false;
            guard.last_error = Some(StructuredError::UnsupportedCodexBuild(
                UnsupportedCodexBuild {
                    executable_sha256: fingerprint.executable_sha256.clone(),
                    architecture: fingerprint.architecture.clone(),
                    codex_version: fingerprint.codex_version_hint.clone(),
                },
            ));
        }
    }

    pub fn set_ebpf_runtime_state(
        &self,
        uprobe_active: bool,
        profile_supported: bool,
        last_error: Option<StructuredError>,
    ) {
        if let Ok(mut guard) = self.inner.write() {
            guard.uprobe_active = uprobe_active;
            guard.profile_supported = profile_supported;
            guard.last_error = last_error;
        }
    }

    pub fn snapshot(&self, active_flows: u32, outbox_bytes: u64) -> CaptureHealth {
        let guard = self.inner.read().expect("capture health lock");
        CaptureHealth {
            af_packet_active: guard.af_packet_active,
            uprobe_active: guard.uprobe_active,
            profile_supported: guard.profile_supported,
            ring_buffer_drops: guard.ring_buffer_drops,
            active_flows,
            outbox_bytes,
            last_error: guard.last_error.clone(),
        }
    }
}

pub trait EbpfRuntime: Send {
    fn next_event(&mut self) -> Result<Option<LoaderEvent>>;
    fn uprobe_active(&self) -> bool;
    fn profile_supported(&self) -> bool;
}

pub trait EbpfFactory: Send + Sync {
    fn start(&self) -> Result<Box<dyn EbpfRuntime>>;
}

pub struct RealEbpfFactory {
    object_path: PathBuf,
    codex_binary_path: PathBuf,
}

impl RealEbpfFactory {
    #[must_use]
    pub fn new(object_path: PathBuf, codex_binary_path: PathBuf) -> Self {
        Self {
            object_path,
            codex_binary_path,
        }
    }
}

impl EbpfFactory for RealEbpfFactory {
    fn start(&self) -> Result<Box<dyn EbpfRuntime>> {
        let running = CaptureLoader::new().load(&self.object_path, &self.codex_binary_path)?;
        Ok(Box::new(RealEbpfRuntime { running }))
    }
}

struct RealEbpfRuntime {
    running: RunningCapture,
}

impl EbpfRuntime for RealEbpfRuntime {
    fn next_event(&mut self) -> Result<Option<LoaderEvent>> {
        self.running.next_event()
    }

    fn uprobe_active(&self) -> bool {
        self.running
            .attached_profile
            .as_ref()
            .is_some_and(|profile| profile.verified)
    }

    fn profile_supported(&self) -> bool {
        self.running
            .attached_profile
            .as_ref()
            .is_some_and(|profile| profile.verified)
    }
}

pub fn ebpf_factory_from_config(config: &ClientConfig) -> Result<Option<Box<dyn EbpfFactory>>> {
    config.validate_ebpf_config()?;
    match (&config.ebpf_object_path, &config.codex_binary_path) {
        (Some(object_path), Some(codex_binary_path)) => Ok(Some(Box::new(RealEbpfFactory::new(
            object_path.clone(),
            codex_binary_path.clone(),
        )))),
        (None, None) => Ok(None),
        _ => unreachable!("validated config"),
    }
}

pub async fn run_ebpf_loop(
    factory: Box<dyn EbpfFactory>,
    health: SharedCaptureHealth,
    process_index: SharedProcessIndex,
    tx: mpsc::Sender<CaptureInput>,
    retry_backoff: Duration,
) -> Result<()> {
    let mut backoff = retry_backoff;
    loop {
        match factory.start() {
            Ok(mut runtime) => {
                health.set_ebpf_runtime_state(
                    runtime.uprobe_active(),
                    runtime.profile_supported(),
                    None,
                );
                backoff = retry_backoff;
                loop {
                    match runtime.next_event() {
                        Ok(Some(LoaderEvent::UnsupportedBuild(fingerprint))) => {
                            health.set_unsupported_build(&fingerprint);
                        }
                        Ok(Some(LoaderEvent::Capture(record))) => {
                            if let Some(input) = map_loader_record(&record, &process_index)
                                && tx.send(input).await.is_err()
                            {
                                return Ok(());
                            }
                        }
                        Ok(None) => tokio::time::sleep(Duration::from_millis(50)).await,
                        Err(error) => {
                            health.set_ebpf_runtime_state(
                                false,
                                false,
                                Some(crate::model::StructuredError::CaptureLost(
                                    crate::model::CaptureLoss {
                                        reason: format!("ebpf_runtime_error:{error}"),
                                        lost_bytes: None,
                                    },
                                )),
                            );
                            tokio::time::sleep(backoff).await;
                            backoff = (backoff * 2).min(Duration::from_secs(30));
                            break;
                        }
                    }
                }
            }
            Err(error) => {
                health.set_ebpf_runtime_state(
                    false,
                    false,
                    Some(crate::model::StructuredError::CaptureLost(
                        crate::model::CaptureLoss {
                            reason: format!("ebpf_loader_error:{error}"),
                            lost_bytes: None,
                        },
                    )),
                );
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(30));
            }
        }
    }
}

fn map_loader_record(
    record: &OwnedCaptureRecord,
    process_index: &SharedProcessIndex,
) -> Option<CaptureInput> {
    let pid = record.header.connection.tgid;
    let tracked = process_index.process(pid)?;
    match record.header.kind {
        ProbeKind::ProcessExec => Some(CaptureInput::ProcessObserved(ProcessSummary {
            process_instance_id: tracked.process_instance_id,
            client_instance_id: tracked.client_instance_id,
            pid,
            executable_sha256: tracked.executable_sha256,
            codex_version: tracked.codex_version,
            started_at: tracked.started_at,
            exited_at: None,
            exit_code: None,
            signal: None,
        })),
        ProbeKind::ProcessExit => Some(CaptureInput::ProcessExit {
            process: ProcessSummary {
                process_instance_id: tracked.process_instance_id,
                client_instance_id: tracked.client_instance_id,
                pid,
                executable_sha256: tracked.executable_sha256,
                codex_version: tracked.codex_version,
                started_at: tracked.started_at,
                exited_at: Some(OffsetDateTime::now_utc()),
                exit_code: None,
                signal: None,
            },
        }),
        _ => None,
    }
}

#[derive(Debug, Clone)]
pub struct TrackedProcess {
    pub process_instance_id: Uuid,
    pub client_instance_id: Uuid,
    pub executable_sha256: String,
    pub codex_version: Option<String>,
    pub started_at: OffsetDateTime,
}
