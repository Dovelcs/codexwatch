#![allow(clippy::cast_possible_truncation, clippy::too_many_lines)]

use std::{collections::VecDeque, fs, os::unix::fs::symlink};

use codexwatch_client::{
    ClientConfig, ClientService, ProcessFlowDirection, ProcessFlowIndex, TcpSegment,
    capture_lane::{
        CaptureInput, LiveCaptureLane, LiveCaptureSource, NoopProcessDiscovery, SharedProcessIndex,
    },
    model::{TaskKey, TaskPhase},
};
use codexwatch_protocol::{
    ClientCommand, CommandPollResponse, ContentPart, ContentRequest, ContentRequestCommand,
};
use tempfile::TempDir;
use time::{Duration, OffsetDateTime};
use tokio::time::timeout;
use uuid::Uuid;

fn config(dir: &TempDir) -> ClientConfig {
    ClientConfig {
        client_id: "client-live".into(),
        client_instance_id: Uuid::now_v7(),
        data_dir: dir.path().join("data"),
        database_path: dir.path().join("data/client.db"),
        blob_dir: dir.path().join("data/blobs"),
        server_url: "http://127.0.0.1:1".into(),
        api_token: "token".into(),
        poll_wait_seconds: 0,
        cleanup_interval_seconds: 1,
        flush_interval_millis: 1_000,
        heartbeat_interval_seconds: 30,
        process_scan_interval_seconds: 30,
        capture_poll_interval_millis: 10,
        capture_interface_index: Some(2),
        capture_codex_pid: None,
        capture_process_name: "codex".into(),
        capture_remote_ports: vec![8080],
        ebpf_object_path: None,
        codex_binary_path: None,
        client_version: "0.1.0-test".into(),
    }
}

fn task_key() -> TaskKey {
    TaskKey {
        client_id: "client-live".into(),
        provider: codexwatch_client::ProviderId::new("codex"),
        session_id: "session-live".into(),
        thread_id: "thread-live".into(),
        turn_id: "turn-live".into(),
    }
}

fn request_bytes(request_kind: &str) -> Vec<u8> {
    let metadata = format!(
        "{{\"session_id\":\"session-live\",\"thread_id\":\"thread-live\",\"turn_id\":\"turn-live\",\"request_kind\":\"{request_kind}\"}}"
    );
    let body = format!(
        "{{\"model\":\"gpt-5\",\"client_metadata\":{{\"x-codex-turn-metadata\":\"{}\"}}}}",
        metadata.replace('"', "\\\"")
    );
    format!(
        "POST /v1/responses HTTP/1.1\r\nHost: upstream\r\nContent-Type: application/json\r\nContent-Length: {}\r\nx-codex-turn-metadata: {}\r\n\r\n{}",
        body.len(),
        metadata,
        body
    )
    .into_bytes()
}

fn failed_response_bytes() -> Vec<u8> {
    let body = concat!(
        "event: response.failed\n",
        "data: {\"type\":\"response.failed\",\"response\":{\"id\":\"resp-fail\",\"error\":{\"code\":\"rate_limit_exceeded\",\"message\":\"slow down\"}}}\n\n"
    );
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    )
    .into_bytes()
}

fn completed_response_bytes() -> Vec<u8> {
    let body = concat!(
        "event: response.completed\n",
        "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp-ok\",\"end_turn\":true,\"usage\":{\"input_tokens\":11,\"output_tokens\":7,\"total_tokens\":18}}}\n\n"
    );
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    )
    .into_bytes()
}

fn models_request_bytes() -> Vec<u8> {
    b"GET /v1/models HTTP/1.1\r\nHost: upstream\r\n\r\n".to_vec()
}

fn models_response_bytes() -> Vec<u8> {
    let body = b"{\"data\":[]}";
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        String::from_utf8_lossy(body)
    )
    .into_bytes()
}

fn chunked_terminal_without_trailer_bytes() -> Vec<u8> {
    let body = concat!(
        "event: response.completed\n",
        "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp-stream\",\"end_turn\":true}}\n\n"
    );
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{}\r\n",
        body.len(),
        body
    )
    .into_bytes()
}

fn response_without_terminal_bytes() -> Vec<u8> {
    let body = concat!(
        "event: response.output_text.delta\n",
        "data: {\"type\":\"response.output_text.delta\",\"delta\":\"partial\"}\n\n"
    );
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    )
    .into_bytes()
}

fn request_with_tool_output_bytes() -> Vec<u8> {
    let metadata = "{\"session_id\":\"session-live\",\"thread_id\":\"thread-live\",\"turn_id\":\"turn-live\",\"request_kind\":\"turn\"}";
    let body = format!(
        "{{\"model\":\"gpt-5\",\"input\":[{{\"type\":\"function_call_output\",\"call_id\":\"call-1\",\"output\":\"42\"}}],\"client_metadata\":{{\"x-codex-turn-metadata\":\"{}\"}}}}",
        metadata.replace('"', "\\\"")
    );
    format!(
        "POST /v1/responses HTTP/1.1\r\nHost: upstream\r\nContent-Type: application/json\r\nContent-Length: {}\r\nx-codex-turn-metadata: {}\r\nAuthorization: Bearer secret\r\n\r\n{}",
        body.len(),
        metadata,
        body
    )
    .into_bytes()
}

fn response_with_tool_input_and_text_bytes() -> Vec<u8> {
    let body = concat!(
        "event: response.output_item.done\n",
        "data: {\"type\":\"response.output_item.done\",\"item\":{\"type\":\"function_call\",\"name\":\"bash\",\"arguments\":\"{\\\"cmd\\\":\\\"echo hi\\\"}\"}}\n\n",
        "event: response.output_text.delta\n",
        "data: {\"type\":\"response.output_text.delta\",\"delta\":\"hello\"}\n\n",
        "event: response.completed\n",
        "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp-parts\",\"end_turn\":true,\"usage\":{\"input_tokens\":1,\"output_tokens\":1,\"total_tokens\":2}}}\n\n"
    );
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    )
    .into_bytes()
}

fn segment(
    source_port: u16,
    destination_port: u16,
    sequence: u32,
    syn: bool,
    fin: bool,
    payload: Vec<u8>,
) -> CaptureInput {
    let (source_ip, destination_ip) = if source_port == 8080 {
        ("100.111.233.0", "10.0.0.2")
    } else {
        ("10.0.0.2", "100.111.233.0")
    };
    CaptureInput::TcpSegment(TcpSegment {
        source_ip: source_ip.into(),
        source_port,
        destination_ip: destination_ip.into(),
        destination_port,
        sequence,
        ack: 0,
        syn,
        fin,
        rst: false,
        payload,
    })
}

#[derive(Default)]
struct FakeCaptureSource {
    inputs: VecDeque<CaptureInput>,
}

impl LiveCaptureSource for FakeCaptureSource {
    fn recv(&mut self, _buffer: &mut [u8]) -> anyhow::Result<Option<CaptureInput>> {
        Ok(self.inputs.pop_front())
    }
}

#[tokio::test]
async fn syn_then_payload_and_retrying_attempts_do_not_terminal_task() {
    let dir = TempDir::new().expect("tmp");
    let cfg = config(&dir);
    let service = ClientService::open(cfg.clone()).await.expect("service");
    let mut lane = LiveCaptureLane::new(cfg, service.store().clone());

    let request1 = request_bytes("turn");
    let response1 = failed_response_bytes();
    let request2 = request_bytes("turn");
    let response2 = completed_response_bytes();

    lane.ingest_input(segment(50000, 8080, 1000, true, false, Vec::new()))
        .await
        .expect("syn");
    lane.ingest_input(segment(50000, 8080, 1001, false, false, request1))
        .await
        .expect("request1");
    lane.ingest_input(segment(8080, 50000, 9000, false, false, response1))
        .await
        .expect("response1");

    let after_first = service
        .store()
        .load_task_cursor(&task_key())
        .await
        .expect("cursor")
        .expect("task");
    assert_eq!(after_first.phase, TaskPhase::Retrying);
    assert_eq!(after_first.attempt_count, 1);
    assert!(after_first.outcome.is_none());

    lane.ingest_input(segment(
        50000,
        8080,
        1001 + request_bytes("turn").len() as u32,
        false,
        false,
        request2,
    ))
    .await
    .expect("request2");
    lane.ingest_input(segment(
        8080,
        50000,
        9000 + failed_response_bytes().len() as u32,
        false,
        true,
        response2,
    ))
    .await
    .expect("response2");

    let after_second = service
        .store()
        .load_task_cursor(&task_key())
        .await
        .expect("cursor")
        .expect("task");
    assert_eq!(after_second.phase, TaskPhase::Running);
    assert_eq!(after_second.attempt_count, 2);
    assert!(after_second.outcome.is_none());
    assert!(after_second.response_ids.iter().any(|id| id == "resp-ok"));
}

#[tokio::test]
async fn non_turn_request_kind_is_ignored() {
    let dir = TempDir::new().expect("tmp");
    let cfg = config(&dir);
    let service = ClientService::open(cfg.clone()).await.expect("service");
    let mut lane = LiveCaptureLane::new(cfg, service.store().clone());

    lane.ingest_input(segment(
        50001,
        8080,
        2000,
        false,
        false,
        request_bytes("background"),
    ))
    .await
    .expect("request");
    lane.ingest_input(segment(
        8080,
        50001,
        12000,
        false,
        true,
        completed_response_bytes(),
    ))
    .await
    .expect("response");

    let task = service
        .store()
        .load_task_cursor(&task_key())
        .await
        .expect("cursor");
    assert!(task.is_none());
}

#[tokio::test]
async fn capture_gap_only_degrades_existing_task() {
    let dir = TempDir::new().expect("tmp");
    let cfg = config(&dir);
    let service = ClientService::open(cfg.clone()).await.expect("service");
    let mut lane = LiveCaptureLane::new(cfg.clone(), service.store().clone());

    lane.ingest_input(segment(
        50002,
        8080,
        3000,
        false,
        false,
        request_bytes("turn"),
    ))
    .await
    .expect("request");
    lane.ingest_input(segment(
        8080,
        50002,
        13000,
        false,
        false,
        completed_response_bytes(),
    ))
    .await
    .expect("response");

    lane.ingest_input(CaptureInput::CaptureGap {
        flow_id: Uuid::now_v7(),
        task: Some(task_key()),
        observed_at: OffsetDateTime::now_utc(),
        reason: "simulated_gap".into(),
        lost_bytes: Some(128),
    })
    .await
    .expect("gap");

    let task = service
        .store()
        .load_task_cursor(&task_key())
        .await
        .expect("cursor")
        .expect("task");
    assert_eq!(task.phase, TaskPhase::Running);
    assert!(task.outcome.is_none());
    assert_eq!(task.completeness, codexwatch_client::Completeness::Degraded);
}

#[tokio::test]
async fn eof_without_terminal_becomes_transport_lost() {
    let dir = TempDir::new().expect("tmp");
    let cfg = config(&dir);
    let service = ClientService::open(cfg.clone()).await.expect("service");
    let mut lane = LiveCaptureLane::new(cfg, service.store().clone());

    lane.ingest_input(segment(
        50003,
        8080,
        4000,
        false,
        false,
        request_bytes("turn"),
    ))
    .await
    .expect("request");
    lane.ingest_input(segment(
        8080,
        50003,
        14000,
        false,
        true,
        response_without_terminal_bytes(),
    ))
    .await
    .expect("response");

    let task = service
        .store()
        .load_task_cursor(&task_key())
        .await
        .expect("cursor")
        .expect("task");
    assert_eq!(task.phase, TaskPhase::Retrying);
    assert!(task.outcome.is_none());
    assert_eq!(task.completeness, codexwatch_client::Completeness::Degraded);
}

#[tokio::test]
async fn extracted_tool_and_model_parts_are_uploadable() {
    let dir = TempDir::new().expect("tmp");
    let cfg = config(&dir);
    let service = ClientService::open(cfg.clone()).await.expect("service");
    let mut lane = LiveCaptureLane::new(cfg, service.store().clone());

    lane.ingest_input(segment(
        50004,
        8080,
        5000,
        false,
        false,
        request_with_tool_output_bytes(),
    ))
    .await
    .expect("request");
    lane.ingest_input(segment(
        8080,
        50004,
        15000,
        false,
        true,
        response_with_tool_input_and_text_bytes(),
    ))
    .await
    .expect("response");

    let command_id = Uuid::now_v7();
    let request_id = Uuid::now_v7();
    service
        .store()
        .save_commands(&CommandPollResponse {
            server_time_ms: 0,
            commands: vec![ClientCommand::RequestContent(ContentRequestCommand {
                command_id,
                request: ContentRequest {
                    request_id,
                    client_id: "client-live".into(),
                    task_ref: task_key().task_ref(),
                    session_id: "session-live".into(),
                    thread_id: "thread-live".into(),
                    created_at_ms: OffsetDateTime::now_utc().unix_timestamp() * 1000,
                    expires_at_ms: Some(
                        (OffsetDateTime::now_utc() + Duration::minutes(5)).unix_timestamp() * 1000,
                    ),
                    parts: vec![
                        ContentPart::ToolInput,
                        ContentPart::ToolOutput,
                        ContentPart::ModelText,
                    ],
                },
            })],
        })
        .await
        .expect("save");

    let prepared = service
        .store()
        .prepare_upload(&ClientCommand::RequestContent(ContentRequestCommand {
            command_id,
            request: ContentRequest {
                request_id,
                client_id: "client-live".into(),
                task_ref: task_key().task_ref(),
                session_id: "session-live".into(),
                thread_id: "thread-live".into(),
                created_at_ms: OffsetDateTime::now_utc().unix_timestamp() * 1000,
                expires_at_ms: Some(
                    (OffsetDateTime::now_utc() + Duration::minutes(5)).unix_timestamp() * 1000,
                ),
                parts: vec![
                    ContentPart::ToolInput,
                    ContentPart::ToolOutput,
                    ContentPart::ModelText,
                ],
            },
        }))
        .await
        .expect("prepare");
    let codexwatch_client::store::UploadPreparation::Ready(work) = prepared else {
        panic!("expected upload work");
    };
    assert_eq!(work.manifests.len(), 3);
    for manifest in &work.manifests {
        let chunks = service.store().load_chunks(manifest).await.expect("chunks");
        assert!(!chunks.is_empty());
    }
}

#[tokio::test]
async fn daemon_keeps_running_when_command_endpoint_is_offline() {
    let dir = TempDir::new().expect("tmp");
    let cfg = config(&dir);
    let service = ClientService::open(cfg.clone()).await.expect("service");
    let source = FakeCaptureSource {
        inputs: VecDeque::from([
            segment(50005, 8080, 6000, false, false, request_bytes("turn")),
            segment(8080, 50005, 16000, false, true, completed_response_bytes()),
        ]),
    };
    let result = timeout(
        Duration::milliseconds(250)
            .try_into()
            .expect("timeout conversion"),
        service.run_daemon_with_sources(Some(Box::new(source)), Box::new(NoopProcessDiscovery)),
    )
    .await;
    assert!(result.is_err(), "daemon should keep running");
    let task = service
        .store()
        .load_task_cursor(&task_key())
        .await
        .expect("cursor")
        .expect("task");
    assert_eq!(task.phase, TaskPhase::Running);
    assert!(
        service
            .store()
            .health_snapshot()
            .await
            .expect("health")
            .outbox_batches
            >= 1
    );
}

#[test]
fn shared_process_index_drops_same_target_non_codex_flow() {
    let root = TempDir::new().expect("tmp");
    let proc_root = root.path().join("proc");
    fs::create_dir_all(proc_root.join("123").join("fd")).expect("fd");
    fs::create_dir_all(proc_root.join("net")).expect("net");
    symlink("socket:[456]", proc_root.join("123").join("fd").join("5")).expect("symlink");
    fs::write(
        proc_root.join("net").join("tcp"),
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0200000A:C350 00E96F64:1F90 01 00000000:00000000 00:00000000 00000000 1000        0 456 1 0000000000000000 20 4 30 10 -1\n",
    )
    .expect("tcp");
    fs::write(
        proc_root.join("net").join("tcp6"),
        "  sl  local_address                         rem_address                          st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n",
    )
    .expect("tcp6");

    let index = ProcessFlowIndex::from_proc_root(&proc_root, 123).expect("index");
    let shared = SharedProcessIndex::default();
    let process_id = Uuid::now_v7();
    shared.upsert(
        123,
        process_id,
        index,
        codexwatch_client::ebpf_lane::TrackedProcess {
            process_instance_id: process_id,
            client_instance_id: Uuid::now_v7(),
            executable_sha256: "deadbeef".repeat(8),
            codex_version: Some("0.148.0".into()),
            started_at: OffsetDateTime::now_utc(),
        },
    );
    let matching = TcpSegment {
        source_ip: "10.0.0.2".into(),
        source_port: 50000,
        destination_ip: "100.111.233.0".into(),
        destination_port: 8080,
        sequence: 1,
        ack: 0,
        syn: false,
        fin: false,
        rst: false,
        payload: Vec::new(),
    };
    let other = TcpSegment {
        source_port: 50001,
        ..matching.clone()
    };
    assert_eq!(
        shared.match_segment(&matching),
        Some((process_id, ProcessFlowDirection::LocalToRemote))
    );
    assert_eq!(shared.match_segment(&other), None);
}

#[tokio::test]
async fn process_exit_marks_associated_active_task_lost() {
    let dir = TempDir::new().expect("tmp");
    let cfg = config(&dir);
    let service = ClientService::open(cfg.clone()).await.expect("service");
    let mut lane = LiveCaptureLane::new(cfg.clone(), service.store().clone());
    let process_instance_id = Uuid::now_v7();
    let request = request_bytes("turn");
    let client_fin_sequence = 7000 + u32::try_from(request.len()).expect("request length");

    lane.ingest_input(CaptureInput::AttributedTcpSegment {
        segment: match segment(50006, 8080, 7000, false, false, request) {
            CaptureInput::TcpSegment(segment) => segment,
            _ => unreachable!(),
        },
        process_instance_id,
        direction: ProcessFlowDirection::LocalToRemote,
    })
    .await
    .expect("request");
    lane.ingest_input(CaptureInput::AttributedTcpSegment {
        segment: match segment(8080, 50006, 17000, false, true, completed_response_bytes()) {
            CaptureInput::TcpSegment(segment) => segment,
            _ => unreachable!(),
        },
        process_instance_id,
        direction: ProcessFlowDirection::RemoteToLocal,
    })
    .await
    .expect("response");
    lane.ingest_input(CaptureInput::AttributedTcpSegment {
        segment: match segment(50006, 8080, client_fin_sequence, false, true, Vec::new()) {
            CaptureInput::TcpSegment(segment) => segment,
            _ => unreachable!(),
        },
        process_instance_id,
        direction: ProcessFlowDirection::LocalToRemote,
    })
    .await
    .expect("flow close");

    lane.ingest_input(CaptureInput::ProcessExit {
        process: codexwatch_client::ProcessSummary {
            process_instance_id,
            client_instance_id: cfg.client_instance_id,
            pid: 4321,
            executable_sha256: "deadbeef".repeat(8),
            codex_version: Some("0.148.0".into()),
            started_at: OffsetDateTime::now_utc() - Duration::minutes(1),
            exited_at: Some(OffsetDateTime::now_utc()),
            exit_code: None,
            signal: None,
        },
    })
    .await
    .expect("exit");

    let task = service
        .store()
        .load_task_cursor(&task_key())
        .await
        .expect("cursor")
        .expect("task");
    assert_eq!(task.phase, TaskPhase::Terminal);
    assert_eq!(task.outcome, Some(codexwatch_client::TaskOutcome::Lost));
}

#[tokio::test]
async fn attributed_server_packet_before_request_keeps_flow_direction() {
    let dir = TempDir::new().expect("tmp");
    let cfg = config(&dir);
    let service = ClientService::open(cfg.clone()).await.expect("service");
    let mut lane = LiveCaptureLane::new(cfg, service.store().clone());
    let process_instance_id = Uuid::now_v7();

    lane.ingest_input(CaptureInput::AttributedTcpSegment {
        segment: match segment(8080, 50007, 18000, false, false, Vec::new()) {
            CaptureInput::TcpSegment(segment) => segment,
            _ => unreachable!(),
        },
        process_instance_id,
        direction: ProcessFlowDirection::RemoteToLocal,
    })
    .await
    .expect("initial server packet");
    lane.ingest_input(CaptureInput::AttributedTcpSegment {
        segment: match segment(50007, 8080, 8000, false, false, request_bytes("turn")) {
            CaptureInput::TcpSegment(segment) => segment,
            _ => unreachable!(),
        },
        process_instance_id,
        direction: ProcessFlowDirection::LocalToRemote,
    })
    .await
    .expect("request");
    lane.ingest_input(CaptureInput::AttributedTcpSegment {
        segment: match segment(8080, 50007, 18000, false, false, completed_response_bytes()) {
            CaptureInput::TcpSegment(segment) => segment,
            _ => unreachable!(),
        },
        process_instance_id,
        direction: ProcessFlowDirection::RemoteToLocal,
    })
    .await
    .expect("response");

    let task = service
        .store()
        .load_task_cursor(&task_key())
        .await
        .expect("cursor")
        .expect("task");
    assert_eq!(task.attempt_count, 1);
    assert!(task.response_ids.iter().any(|id| id == "resp-ok"));
}

#[tokio::test]
async fn ignores_models_exchange_before_responses_on_same_connection() {
    let dir = TempDir::new().expect("tmp");
    let cfg = config(&dir);
    let service = ClientService::open(cfg.clone()).await.expect("service");
    let mut lane = LiveCaptureLane::new(cfg, service.store().clone());

    let models_request = models_request_bytes();
    let models_response = models_response_bytes();
    lane.ingest_input(segment(
        50008,
        8080,
        9000,
        false,
        false,
        models_request.clone(),
    ))
    .await
    .expect("models request");
    lane.ingest_input(segment(
        8080,
        50008,
        19000,
        false,
        false,
        models_response.clone(),
    ))
    .await
    .expect("models response");
    lane.ingest_input(segment(
        50008,
        8080,
        9000 + models_request.len() as u32,
        false,
        false,
        request_bytes("turn"),
    ))
    .await
    .expect("responses request");
    lane.ingest_input(segment(
        8080,
        50008,
        19000 + models_response.len() as u32,
        false,
        false,
        completed_response_bytes(),
    ))
    .await
    .expect("responses response");

    let task = service
        .store()
        .load_task_cursor(&task_key())
        .await
        .expect("cursor")
        .expect("task");
    assert_eq!(task.attempt_count, 1);
    assert!(task.response_ids.iter().any(|id| id == "resp-ok"));
}

#[tokio::test]
async fn terminal_sse_projects_before_chunked_trailer() {
    let dir = TempDir::new().expect("tmp");
    let cfg = config(&dir);
    let service = ClientService::open(cfg.clone()).await.expect("service");
    let mut lane = LiveCaptureLane::new(cfg, service.store().clone());

    lane.ingest_input(segment(
        50009,
        8080,
        10000,
        false,
        false,
        request_bytes("turn"),
    ))
    .await
    .expect("request");
    lane.ingest_input(segment(
        8080,
        50009,
        20000,
        false,
        false,
        chunked_terminal_without_trailer_bytes(),
    ))
    .await
    .expect("terminal response");

    let task = service
        .store()
        .load_task_cursor(&task_key())
        .await
        .expect("cursor")
        .expect("task");
    assert_eq!(task.attempt_count, 1);
    assert!(task.response_ids.iter().any(|id| id == "resp-stream"));
    assert_eq!(task.completeness, codexwatch_client::Completeness::Complete);
}
