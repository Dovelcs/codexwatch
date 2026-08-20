#![allow(clippy::cast_possible_truncation, clippy::too_many_lines)]

use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::post,
};
use codexwatch_capture_ebpf::{LoaderEvent, profile::BuildFingerprint};
use codexwatch_client::{
    ClientConfig, ClientService, TcpSegment,
    capture_lane::{
        CaptureInput, LiveCaptureSource, NoopProcessDiscovery, ProcessDiscovery, SharedProcessIndex,
    },
    ebpf_lane::{EbpfFactory, EbpfRuntime, SharedCaptureHealth},
};
use codexwatch_protocol::{self as wire, decode_batch_with_payload};
use tempfile::TempDir;
use tokio::{net::TcpListener, time::timeout};
use uuid::Uuid;

#[derive(Debug, Default)]
struct ServerState {
    heartbeats: Vec<wire::Heartbeat>,
}

#[derive(Clone)]
struct SharedState(Arc<tokio::sync::Mutex<ServerState>>);

async fn spawn_server(state: Arc<tokio::sync::Mutex<ServerState>>) -> String {
    async fn ingest(
        State(state): State<SharedState>,
        headers: HeaderMap,
        body: bytes::Bytes,
    ) -> impl IntoResponse {
        let decoded = decode_batch_with_payload(&body).expect("decode");
        let accepted_heartbeats = decoded.batch.heartbeats.len() as u32;
        state
            .0
            .lock()
            .await
            .heartbeats
            .extend(decoded.batch.heartbeats);
        (
            StatusCode::OK,
            Json(wire::IngestAck {
                batch_id: decoded.batch.batch_id,
                payload_sha256: headers
                    .get("x-payload-sha256")
                    .expect("sha")
                    .to_str()
                    .expect("sha string")
                    .to_string(),
                accepted_tasks: decoded.batch.tasks.len() as u32,
                accepted_heartbeats,
                duplicate: false,
            }),
        )
            .into_response()
    }

    let router = Router::new()
        .route("/api/v1/ingest", post(ingest))
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
        client_id: "client-ebpf".into(),
        client_instance_id: Uuid::now_v7(),
        data_dir: dir.path().join("data"),
        database_path: dir.path().join("data/client.db"),
        blob_dir: dir.path().join("data/blobs"),
        server_url,
        api_token: "token".into(),
        poll_wait_seconds: 0,
        cleanup_interval_seconds: 1,
        flush_interval_millis: 100,
        heartbeat_interval_seconds: 1,
        process_scan_interval_seconds: 30,
        capture_poll_interval_millis: 10,
        capture_interface_index: None,
        capture_codex_pid: None,
        capture_process_name: "codex".into(),
        capture_remote_ports: Vec::new(),
        ebpf_object_path: None,
        codex_binary_path: None,
        codex_home: None,
        client_version: "0.1.0-test".into(),
    }
}

#[derive(Default)]
struct FakeSource {
    inputs: VecDeque<CaptureInput>,
}

impl LiveCaptureSource for FakeSource {
    fn recv(&mut self, _buffer: &mut [u8]) -> anyhow::Result<Option<CaptureInput>> {
        Ok(self.inputs.pop_front())
    }
}

#[derive(Default)]
struct FlakyDiscovery {
    failures: usize,
}

impl ProcessDiscovery for FlakyDiscovery {
    fn poll(&mut self, _now: time::OffsetDateTime) -> anyhow::Result<Vec<CaptureInput>> {
        self.failures += 1;
        Err(anyhow::anyhow!("discovery failed {}", self.failures))
    }
}

struct QueueRuntime {
    events: VecDeque<anyhow::Result<Option<LoaderEvent>>>,
    uprobe_active: bool,
    profile_supported: bool,
}

impl EbpfRuntime for QueueRuntime {
    fn next_event(&mut self) -> anyhow::Result<Option<LoaderEvent>> {
        self.events.pop_front().unwrap_or_else(|| Ok(None))
    }

    fn uprobe_active(&self) -> bool {
        self.uprobe_active
    }

    fn profile_supported(&self) -> bool {
        self.profile_supported
    }
}

struct QueueFactory {
    runtime: Arc<Mutex<VecDeque<anyhow::Result<QueueRuntime>>>>,
}

impl EbpfFactory for QueueFactory {
    fn start(&self) -> anyhow::Result<Box<dyn EbpfRuntime>> {
        let mut guard = self.runtime.lock().expect("runtime queue");
        match guard.pop_front().unwrap_or_else(|| {
            Ok(QueueRuntime {
                events: VecDeque::new(),
                uprobe_active: false,
                profile_supported: true,
            })
        }) {
            Ok(runtime) => Ok(Box::new(runtime)),
            Err(error) => Err(error),
        }
    }
}

fn sample_segment() -> CaptureInput {
    CaptureInput::TcpSegment(TcpSegment {
        source_ip: "10.0.0.2".into(),
        source_port: 50100,
        destination_ip: "100.111.233.0".into(),
        destination_port: 8080,
        sequence: 1,
        ack: 0,
        syn: false,
        fin: false,
        rst: false,
        payload: b"POST /v1/responses HTTP/1.1\r\nContent-Length: 0\r\n\r\n".to_vec(),
    })
}

#[tokio::test]
async fn heartbeat_reports_unsupported_build_from_ebpf_runtime() {
    let state = Arc::new(tokio::sync::Mutex::new(ServerState::default()));
    let server_url = spawn_server(state.clone()).await;
    let dir = TempDir::new().expect("tmp");
    let service = ClientService::open(config(&dir, server_url))
        .await
        .expect("service");
    let runtime = QueueRuntime {
        events: VecDeque::from([Ok(Some(LoaderEvent::UnsupportedBuild(BuildFingerprint {
            executable_sha256: "deadbeef".repeat(8),
            architecture: "x86_64".into(),
            codex_version_hint: Some("0.144.1".into()),
        })))]),
        uprobe_active: false,
        profile_supported: false,
    };
    let factory = QueueFactory {
        runtime: Arc::new(Mutex::new(VecDeque::from([Ok(runtime)]))),
    };

    let result = timeout(
        std::time::Duration::from_millis(350),
        service.run_daemon_with_components(
            None,
            Box::new(NoopProcessDiscovery),
            Some(Box::new(factory)),
            SharedCaptureHealth::default(),
            SharedProcessIndex::default(),
        ),
    )
    .await;
    assert!(result.is_err(), "daemon should still be running");

    let heartbeats = state.lock().await.heartbeats.clone();
    assert!(!heartbeats.is_empty());
    assert!(
        heartbeats.iter().any(|heartbeat| {
            !matches!(heartbeat.capture_health, wire::IntegrityState::Complete)
        })
    );
}

#[tokio::test]
async fn no_ebpf_configuration_keeps_compatible_health_defaults() {
    let dir = TempDir::new().expect("tmp");
    let cfg = config(&dir, "http://127.0.0.1:1".into());
    cfg.validate_ebpf_config().expect("valid");
    assert!(!cfg.ebpf_enabled());
    let health = SharedCaptureHealth::default().snapshot(0, 0);
    assert!(!health.uprobe_active);
    assert!(health.profile_supported);
    assert!(health.last_error.is_none());
}

#[tokio::test]
async fn ebpf_runtime_error_does_not_stop_daemon() {
    let dir = TempDir::new().expect("tmp");
    let service = ClientService::open(config(&dir, "http://127.0.0.1:1".into()))
        .await
        .expect("service");
    let runtime = QueueRuntime {
        events: VecDeque::from([Err(anyhow::anyhow!("ring failed"))]),
        uprobe_active: false,
        profile_supported: true,
    };
    let factory = QueueFactory {
        runtime: Arc::new(Mutex::new(VecDeque::from([Ok(runtime)]))),
    };
    let source = FakeSource {
        inputs: VecDeque::from([sample_segment()]),
    };

    let result = timeout(
        std::time::Duration::from_millis(300),
        service.run_daemon_with_components(
            Some(Box::new(source)),
            Box::new(NoopProcessDiscovery),
            Some(Box::new(factory)),
            SharedCaptureHealth::default(),
            SharedProcessIndex::default(),
        ),
    )
    .await;
    assert!(result.is_err(), "daemon should continue running");
    service.store().health_snapshot().await.expect("health");
}

#[test]
fn partial_ebpf_configuration_is_rejected() {
    let dir = TempDir::new().expect("tmp");
    let mut cfg = config(&dir, "http://127.0.0.1:1".into());
    cfg.ebpf_object_path = Some(dir.path().join("capture-ebpf.o"));
    let err = cfg.validate_ebpf_config().expect_err("must fail");
    assert!(err.to_string().contains("codex_binary_path"));
}

#[tokio::test]
async fn process_discovery_error_does_not_stop_daemon() {
    let dir = TempDir::new().expect("tmp");
    let service = ClientService::open(config(&dir, "http://127.0.0.1:1".into()))
        .await
        .expect("service");

    let result = timeout(
        std::time::Duration::from_millis(250),
        service.run_daemon_with_components(
            None,
            Box::new(FlakyDiscovery::default()),
            None,
            SharedCaptureHealth::default(),
            SharedProcessIndex::default(),
        ),
    )
    .await;
    assert!(result.is_err(), "daemon should continue running");
}
