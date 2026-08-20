use std::{
    collections::{BTreeSet, HashMap, HashSet, VecDeque},
    fs,
    path::PathBuf,
    sync::{Arc, RwLock},
    time::{Duration as StdDuration, Instant},
};

use anyhow::{Result, bail};
use codexwatch_protocol::ContentPart;
use serde_json::Value;
use time::OffsetDateTime;
use tokio::time::sleep;
use uuid::Uuid;

use crate::{
    blob::StoredContentInput,
    config::ClientConfig,
    conversation_titles::ConversationTitleIndex,
    decode_support::{
        AssemblerResult, DecodedAttempt, DecodedError, DecodedEvent, H2Decoder, H2Event,
        HttpParseError, PassiveTap, ProcessFlowDirection, ProcessFlowIndex, TapError, TcpAssembler,
        TcpSegment, WebSocketDecoder, decode_http_exchange, headers_to_map, parse_http_request,
        parse_http_response, parse_sse_events,
    },
    ebpf_lane::TrackedProcess,
    model::{
        AttemptStatus, AttemptSummary, CaptureGapSummary, CaptureLoss, Completeness, HttpError,
        HttpExchangeSummary, IncompleteResponse, ProcessSummary, ProcessTermination, ProviderError,
        SessionSummary, StructuredError, SummaryRecord, TaskKey, TaskOutcome, TaskPhase,
        TaskSummary, TaskTransition, TokenUsage, TransitionCause,
    },
    store::{ClientStore, PersistOutcome},
};

#[derive(Debug, Clone)]
pub struct CaptureBatch {
    pub records: Vec<SummaryRecord>,
    pub contents: Vec<StoredContentInput>,
}

impl CaptureBatch {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty() && self.contents.is_empty()
    }
}

#[derive(Debug, Clone)]
pub enum CaptureInput {
    TcpSegment(TcpSegment),
    AttributedTcpSegment {
        segment: TcpSegment,
        process_instance_id: Uuid,
        direction: ProcessFlowDirection,
    },
    CaptureGap {
        flow_id: Uuid,
        task: Option<TaskKey>,
        observed_at: OffsetDateTime,
        reason: String,
        lost_bytes: Option<u64>,
    },
    ProcessObserved(ProcessSummary),
    ProcessExit {
        process: ProcessSummary,
    },
}

pub trait LiveCaptureSource: Send {
    fn recv(&mut self, buffer: &mut [u8]) -> Result<Option<CaptureInput>>;
}

pub trait ProcessDiscovery: Send {
    fn poll(&mut self, now: OffsetDateTime) -> Result<Vec<CaptureInput>>;
}

#[derive(Debug)]
pub struct PassiveTapSource {
    tap: PassiveTap,
    index: SharedProcessIndex,
    pending: VecDeque<PendingSegment>,
    pending_bytes: usize,
    remote_ports: BTreeSet<u16>,
}

#[derive(Debug)]
struct PendingSegment {
    received_at: Instant,
    segment: TcpSegment,
}

const PENDING_SEGMENT_TTL: StdDuration = StdDuration::from_secs(15);
const MAX_PENDING_SEGMENTS: usize = 4096;
const MAX_PENDING_BYTES: usize = 8 * 1024 * 1024;
const MAX_CAPTURE_DRAIN_BATCH: usize = 256;
pub(crate) const CAPTURE_BUFFER_BYTES: usize = 256 * 1024;

impl PassiveTapSource {
    pub fn open(
        interface_index: i32,
        index: SharedProcessIndex,
        remote_ports: impl IntoIterator<Item = u16>,
    ) -> Result<Self> {
        Ok(Self {
            tap: PassiveTap::open(interface_index)?,
            index,
            pending: VecDeque::new(),
            pending_bytes: 0,
            remote_ports: remote_ports.into_iter().collect(),
        })
    }

    fn is_candidate(&self, segment: &TcpSegment) -> bool {
        self.remote_ports.is_empty()
            || self.remote_ports.contains(&segment.source_port)
            || self.remote_ports.contains(&segment.destination_port)
    }

    fn pop_attributed_pending(&mut self) -> Option<CaptureInput> {
        self.expire_pending();
        let index = self
            .pending
            .iter()
            .position(|pending| self.index.match_segment(&pending.segment).is_some())?;
        let pending = self.pending.remove(index)?;
        self.pending_bytes = self
            .pending_bytes
            .saturating_sub(segment_size(&pending.segment));
        let (process_instance_id, direction) = self.index.match_segment(&pending.segment)?;
        Some(CaptureInput::AttributedTcpSegment {
            segment: pending.segment,
            process_instance_id,
            direction,
        })
    }

    fn push_pending(&mut self, segment: TcpSegment) {
        let segment_bytes = segment_size(&segment);
        while self.pending.len() >= MAX_PENDING_SEGMENTS
            || self.pending_bytes.saturating_add(segment_bytes) > MAX_PENDING_BYTES
        {
            let Some(dropped) = self.pending.pop_front() else {
                break;
            };
            self.pending_bytes = self
                .pending_bytes
                .saturating_sub(segment_size(&dropped.segment));
        }
        if segment_bytes <= MAX_PENDING_BYTES {
            self.pending.push_back(PendingSegment {
                received_at: Instant::now(),
                segment,
            });
            self.pending_bytes = self.pending_bytes.saturating_add(segment_bytes);
        }
    }

    fn expire_pending(&mut self) {
        let now = Instant::now();
        while self
            .pending
            .front()
            .is_some_and(|pending| now.duration_since(pending.received_at) >= PENDING_SEGMENT_TTL)
        {
            let Some(expired) = self.pending.pop_front() else {
                break;
            };
            self.pending_bytes = self
                .pending_bytes
                .saturating_sub(segment_size(&expired.segment));
        }
    }
}

fn segment_size(segment: &TcpSegment) -> usize {
    segment.payload.len().saturating_add(64)
}

impl LiveCaptureSource for PassiveTapSource {
    fn recv(&mut self, buffer: &mut [u8]) -> Result<Option<CaptureInput>> {
        if let Some(input) = self.pop_attributed_pending() {
            return Ok(Some(input));
        }
        for _ in 0..MAX_CAPTURE_DRAIN_BATCH {
            match self.tap.recv(buffer) {
                Ok(Some(segment)) => {
                    if let Some((process_instance_id, direction)) =
                        self.index.match_segment(&segment)
                    {
                        return Ok(Some(CaptureInput::AttributedTcpSegment {
                            segment,
                            process_instance_id,
                            direction,
                        }));
                    }
                    if self.is_candidate(&segment) {
                        self.push_pending(segment);
                    }
                }
                Ok(None) => return Ok(None),
                Err(TapError::Decode(_)) => bail!("failed to decode AF_PACKET frame"),
                Err(TapError::Proc(error)) => return Err(error.into()),
                Err(TapError::Io(error)) => return Err(error.into()),
            }
        }
        Ok(None)
    }
}

#[derive(Debug, Default)]
pub struct NoopProcessDiscovery;

impl ProcessDiscovery for NoopProcessDiscovery {
    fn poll(&mut self, _now: OffsetDateTime) -> Result<Vec<CaptureInput>> {
        Ok(Vec::new())
    }
}

#[derive(Debug, Clone)]
struct ObservedProcess {
    pid: u32,
    process_instance_id: Uuid,
    executable_sha256: String,
    codex_version: Option<String>,
    executable_path: PathBuf,
    started_at: OffsetDateTime,
}

pub struct ProcfsProcessDiscovery {
    config: ClientConfig,
    observed: HashMap<u32, ObservedProcess>,
    executable_hashes: HashMap<PathBuf, String>,
    shared_index: SharedProcessIndex,
}

impl ProcfsProcessDiscovery {
    #[must_use]
    pub fn new(config: ClientConfig, shared_index: SharedProcessIndex) -> Self {
        let mut executable_hashes = HashMap::new();
        if let Some(path) = config.codex_binary_path.as_ref()
            && let Ok(bytes) = fs::read(path)
        {
            executable_hashes.insert(path.clone(), codexwatch_protocol::sha256_hex(&bytes));
        }
        Self {
            config,
            observed: HashMap::new(),
            executable_hashes,
            shared_index,
        }
    }

    fn discover_pids(&self) -> Vec<u32> {
        if let Some(pid) = self.config.capture_codex_pid {
            return vec![pid];
        }

        fs::read_dir("/proc")
            .ok()
            .into_iter()
            .flat_map(|entries| entries.filter_map(Result::ok))
            .filter_map(|entry| entry.file_name().to_string_lossy().parse::<u32>().ok())
            .filter(|pid| {
                self.process_name(*pid)
                    .is_some_and(|name| name == self.config.capture_process_name)
            })
            .collect()
    }

    fn process_name(&self, pid: u32) -> Option<String> {
        let path = PathBuf::from("/proc").join(pid.to_string()).join("comm");
        fs::read_to_string(path)
            .ok()
            .map(|value| value.trim().to_string())
    }

    fn executable_path(&self, pid: u32) -> Option<PathBuf> {
        fs::read_link(PathBuf::from("/proc").join(pid.to_string()).join("exe")).ok()
    }
}

impl ProcessDiscovery for ProcfsProcessDiscovery {
    fn poll(&mut self, now: OffsetDateTime) -> Result<Vec<CaptureInput>> {
        let mut events = Vec::new();
        let mut active = HashMap::new();
        for pid in self.discover_pids() {
            let Some(executable_path) = self.executable_path(pid) else {
                events.push(CaptureInput::CaptureGap {
                    flow_id: Uuid::now_v7(),
                    task: None,
                    observed_at: now,
                    reason: format!("proc_exe_unavailable:{pid}"),
                    lost_bytes: None,
                });
                continue;
            };
            let existing = self
                .observed
                .get(&pid)
                .filter(|observed| observed.executable_path == executable_path)
                .cloned();
            let is_new = existing.is_none();
            let observed = if let Some(existing) = existing {
                existing
            } else {
                let executable_sha256 =
                    if let Some(hash) = self.executable_hashes.get(&executable_path) {
                        hash.clone()
                    } else {
                        match fs::read(&executable_path) {
                            Ok(bytes) => {
                                let hash = codexwatch_protocol::sha256_hex(&bytes);
                                self.executable_hashes
                                    .insert(executable_path.clone(), hash.clone());
                                hash
                            }
                            Err(error) => {
                                events.push(CaptureInput::CaptureGap {
                                    flow_id: Uuid::now_v7(),
                                    task: None,
                                    observed_at: now,
                                    reason: format!("proc_exe_read_failed:{pid}:{error}"),
                                    lost_bytes: None,
                                });
                                continue;
                            }
                        }
                    };
                ObservedProcess {
                    pid,
                    process_instance_id: Uuid::now_v7(),
                    executable_sha256,
                    codex_version: detect_codex_version(&executable_path),
                    executable_path: executable_path.clone(),
                    started_at: now,
                }
            };
            self.observed.insert(pid, observed.clone());
            active.insert(pid, observed.clone());
            match ProcessFlowIndex::from_pid(pid) {
                Ok(index) => self.shared_index.upsert(
                    pid,
                    observed.process_instance_id,
                    index,
                    TrackedProcess {
                        process_instance_id: observed.process_instance_id,
                        client_instance_id: self.config.client_instance_id,
                        executable_sha256: observed.executable_sha256.clone(),
                        codex_version: observed.codex_version.clone(),
                        started_at: observed.started_at,
                    },
                ),
                Err(error) => {
                    events.push(CaptureInput::CaptureGap {
                        flow_id: Uuid::now_v7(),
                        task: None,
                        observed_at: now,
                        reason: format!("attribution_index_unavailable:{error}"),
                        lost_bytes: None,
                    });
                    continue;
                }
            }
            if is_new {
                events.push(CaptureInput::ProcessObserved(ProcessSummary {
                    process_instance_id: observed.process_instance_id,
                    client_instance_id: self.config.client_instance_id,
                    pid,
                    executable_sha256: observed.executable_sha256.clone(),
                    codex_version: observed.codex_version.clone(),
                    started_at: observed.started_at,
                    exited_at: None,
                    exit_code: None,
                    signal: None,
                }));
            }
        }

        let stale: Vec<_> = self
            .observed
            .keys()
            .copied()
            .filter(|pid| !active.contains_key(pid))
            .collect();
        for pid in stale {
            let Some(observed) = self.observed.remove(&pid) else {
                continue;
            };
            self.shared_index.remove(pid);
            events.push(CaptureInput::ProcessExit {
                process: ProcessSummary {
                    process_instance_id: observed.process_instance_id,
                    client_instance_id: self.config.client_instance_id,
                    pid: observed.pid,
                    executable_sha256: observed.executable_sha256,
                    codex_version: observed.codex_version,
                    started_at: observed.started_at,
                    exited_at: Some(now),
                    exit_code: None,
                    signal: None,
                },
            });
        }
        Ok(events)
    }
}

#[derive(Debug, Clone, Default)]
pub struct SharedProcessIndex {
    inner: Arc<RwLock<HashMap<u32, IndexedProcess>>>,
}

#[derive(Debug, Clone)]
struct IndexedProcess {
    process_instance_id: Uuid,
    index: ProcessFlowIndex,
    tracked: TrackedProcess,
}

impl SharedProcessIndex {
    pub fn upsert(
        &self,
        pid: u32,
        process_instance_id: Uuid,
        index: ProcessFlowIndex,
        tracked: TrackedProcess,
    ) {
        if let Ok(mut guard) = self.inner.write() {
            guard.insert(
                pid,
                IndexedProcess {
                    process_instance_id,
                    index,
                    tracked,
                },
            );
        }
    }

    pub fn remove(&self, pid: u32) {
        if let Ok(mut guard) = self.inner.write() {
            guard.remove(&pid);
        }
    }

    pub fn match_segment(&self, segment: &TcpSegment) -> Option<(Uuid, ProcessFlowDirection)> {
        self.inner.read().ok().and_then(|guard| {
            guard.values().find_map(|indexed| {
                indexed
                    .index
                    .direction_for_segment(segment)
                    .map(|direction| (indexed.process_instance_id, direction))
            })
        })
    }

    pub fn process(&self, pid: u32) -> Option<TrackedProcess> {
        self.inner
            .read()
            .ok()
            .and_then(|guard| guard.get(&pid).map(|indexed| indexed.tracked.clone()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct Endpoint {
    ip: std::net::IpAddr,
    port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FlowKey {
    low: Endpoint,
    high: Endpoint,
}

impl FlowKey {
    fn new(a: Endpoint, b: Endpoint) -> Self {
        if a <= b {
            Self { low: a, high: b }
        } else {
            Self { low: b, high: a }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Direction {
    ClientToServer,
    ServerToClient,
}

enum ProtocolState {
    Unknown,
    Http1,
    Http2(H2Decoder),
    WebSocket(WebSocketState),
}

#[derive(Debug, Default)]
struct WebSocketState {
    client: WebSocketDecoder,
    server: WebSocketDecoder,
    current_request: Option<WebSocketRequest>,
}

#[derive(Debug, Clone)]
struct WebSocketRequest {
    body: Vec<u8>,
    observed_at: i64,
    response_events: Vec<String>,
}

#[derive(Debug, Default)]
struct H2StreamState {
    request_headers: Vec<(String, String)>,
    request_body: Vec<u8>,
    request_end: bool,
    response_headers: Vec<(String, String)>,
    response_body: Vec<u8>,
    response_end: bool,
    request_at_ms: i64,
}

struct FlowState {
    flow_id: Uuid,
    process_instance_id: Option<Uuid>,
    client: Endpoint,
    server: Endpoint,
    protocol: ProtocolState,
    client_assembler: TcpAssembler,
    server_assembler: TcpAssembler,
    client_buffer: Vec<u8>,
    server_buffer: Vec<u8>,
    client_closed: bool,
    server_closed: bool,
    request_queue: VecDeque<RequestEnvelope>,
    h2_streams: HashMap<u32, H2StreamState>,
    current_task: Option<TaskKey>,
}

#[derive(Debug, Clone)]
struct RequestEnvelope {
    raw: Vec<u8>,
    observed_at_ms: i64,
}

#[derive(Debug, Clone)]
struct DecodedExchange {
    attempt: DecodedAttempt,
    request_raw: Vec<u8>,
    response_raw: Vec<u8>,
    request_headers: std::collections::BTreeMap<String, String>,
    response_headers: std::collections::BTreeMap<String, String>,
    response_status: Option<u16>,
}

pub struct LiveCaptureLane {
    config: ClientConfig,
    store: ClientStore,
    conversation_titles: Arc<ConversationTitleIndex>,
    flows: HashMap<FlowKey, FlowState>,
    process_tasks: HashMap<Uuid, HashSet<TaskKey>>,
}

impl LiveCaptureLane {
    #[must_use]
    pub fn new(config: ClientConfig, store: ClientStore) -> Self {
        let titles =
            ConversationTitleIndex::open(config.codex_session_index_path()).unwrap_or_default();
        Self::with_conversation_titles(config, store, Arc::new(titles))
    }

    #[must_use]
    pub fn with_conversation_titles(
        config: ClientConfig,
        store: ClientStore,
        conversation_titles: Arc<ConversationTitleIndex>,
    ) -> Self {
        Self {
            config,
            store,
            conversation_titles,
            flows: HashMap::new(),
            process_tasks: HashMap::new(),
        }
    }

    pub async fn ingest_input(&mut self, input: CaptureInput) -> Result<Option<PersistOutcome>> {
        let Some(batch) = self.handle_input(input).await? else {
            return Ok(None);
        };
        if batch.is_empty() {
            return Ok(None);
        }
        self.store
            .persist_ingress(batch.records, batch.contents)
            .await
            .map(Some)
    }

    pub async fn handle_input(&mut self, input: CaptureInput) -> Result<Option<CaptureBatch>> {
        match input {
            CaptureInput::TcpSegment(segment) => self.handle_segment(segment, None, None).await,
            CaptureInput::AttributedTcpSegment {
                segment,
                process_instance_id,
                direction,
            } => {
                self.handle_segment(segment, Some(process_instance_id), Some(direction))
                    .await
            }
            CaptureInput::CaptureGap {
                flow_id,
                task,
                observed_at,
                reason,
                lost_bytes,
            } => {
                let batch = self
                    .project_gap(flow_id, task, observed_at, reason, lost_bytes)
                    .await?;
                Ok((!batch.is_empty()).then_some(batch))
            }
            CaptureInput::ProcessObserved(process) => Ok(Some(CaptureBatch {
                records: vec![SummaryRecord::Process(process)],
                contents: Vec::new(),
            })),
            CaptureInput::ProcessExit { process } => {
                let mut tasks = self
                    .process_tasks
                    .remove(&process.process_instance_id)
                    .unwrap_or_default();
                tasks.extend(
                    self.flows
                        .values()
                        .filter(|flow| {
                            flow.process_instance_id == Some(process.process_instance_id)
                        })
                        .filter_map(|flow| flow.current_task.clone()),
                );
                let batch = self
                    .project_process_exit(process, tasks.into_iter().collect())
                    .await?;
                Ok((!batch.is_empty()).then_some(batch))
            }
        }
    }

    async fn handle_segment(
        &mut self,
        segment: TcpSegment,
        process_instance_id: Option<Uuid>,
        attributed_direction: Option<ProcessFlowDirection>,
    ) -> Result<Option<CaptureBatch>> {
        let source = parse_endpoint(&segment.source_ip, segment.source_port)?;
        let destination = parse_endpoint(&segment.destination_ip, segment.destination_port)?;
        let key = FlowKey::new(source, destination);
        let now = OffsetDateTime::now_utc();
        let (initial_client, initial_server) = match attributed_direction {
            Some(ProcessFlowDirection::RemoteToLocal) => (destination, source),
            Some(ProcessFlowDirection::LocalToRemote) | None => (source, destination),
        };
        let mut state = self.flows.remove(&key).unwrap_or_else(|| FlowState {
            flow_id: Uuid::now_v7(),
            process_instance_id,
            client: initial_client,
            server: initial_server,
            protocol: ProtocolState::Unknown,
            client_assembler: TcpAssembler::new(),
            server_assembler: TcpAssembler::new(),
            client_buffer: Vec::new(),
            server_buffer: Vec::new(),
            client_closed: false,
            server_closed: false,
            request_queue: VecDeque::new(),
            h2_streams: HashMap::new(),
            current_task: None,
        });
        if state.process_instance_id.is_none() {
            state.process_instance_id = process_instance_id;
        }
        self.store
            .note_flow_open(
                state.flow_id,
                state.process_instance_id,
                &format!("{}:{}", state.client.ip, state.client.port),
                &format!("{}:{}", state.server.ip, state.server.port),
                "tcp",
                now,
            )
            .await?;

        let direction = match attributed_direction {
            Some(ProcessFlowDirection::LocalToRemote) => {
                state.client = source;
                state.server = destination;
                Direction::ClientToServer
            }
            Some(ProcessFlowDirection::RemoteToLocal) => {
                state.client = destination;
                state.server = source;
                Direction::ServerToClient
            }
            None if source == state.client && destination == state.server => {
                Direction::ClientToServer
            }
            None if source == state.server && destination == state.client => {
                Direction::ServerToClient
            }
            None if looks_like_request(&segment.payload) || segment.syn => {
                state.client = source;
                state.server = destination;
                Direction::ClientToServer
            }
            None => Direction::ServerToClient,
        };

        let assembler = match direction {
            Direction::ClientToServer => &mut state.client_assembler,
            Direction::ServerToClient => &mut state.server_assembler,
        };
        let result = assembler.push_segment(
            segment.sequence.wrapping_add(u32::from(segment.syn)),
            &segment.payload,
            segment.fin,
            segment.rst,
        );
        let mut batch = CaptureBatch {
            records: Vec::new(),
            contents: Vec::new(),
        };

        match result {
            AssemblerResult::Advanced(chunk) => {
                self.process_bytes(&mut state, direction, chunk.bytes, now, &mut batch)
                    .await?;
            }
            AssemblerResult::GapDetected | AssemblerResult::ConflictDetected => {
                let task = state.current_task.clone();
                let gap = self
                    .project_gap(
                        state.flow_id,
                        task,
                        now,
                        "tcp_reassembly_gap".into(),
                        Some(segment.payload.len() as u64),
                    )
                    .await?;
                batch.records.extend(gap.records);
                batch.contents.extend(gap.contents);
            }
            AssemblerResult::Pending => {}
        }

        match direction {
            Direction::ClientToServer => {
                if segment.fin || segment.rst {
                    state.client_closed = true;
                    if matches!(
                        state.client_assembler.finish(),
                        AssemblerResult::GapDetected | AssemblerResult::ConflictDetected
                    ) {
                        let gap = self
                            .project_gap(
                                state.flow_id,
                                state.current_task.clone(),
                                now,
                                "client_stream_finish_with_gap".into(),
                                None,
                            )
                            .await?;
                        batch.records.extend(gap.records);
                        batch.contents.extend(gap.contents);
                    }
                }
            }
            Direction::ServerToClient => {
                if segment.fin || segment.rst {
                    state.server_closed = true;
                    if matches!(
                        state.server_assembler.finish(),
                        AssemblerResult::GapDetected | AssemblerResult::ConflictDetected
                    ) {
                        let gap = self
                            .project_gap(
                                state.flow_id,
                                state.current_task.clone(),
                                now,
                                "server_stream_finish_with_gap".into(),
                                None,
                            )
                            .await?;
                        batch.records.extend(gap.records);
                        batch.contents.extend(gap.contents);
                    }
                }
            }
        }

        if state.client_closed && state.server_closed {
            self.store.note_flow_closed(state.flow_id, now).await?;
        } else {
            self.flows.insert(key, state);
        }

        Ok((!batch.is_empty()).then_some(batch))
    }

    async fn process_bytes(
        &mut self,
        state: &mut FlowState,
        direction: Direction,
        bytes: Vec<u8>,
        now: OffsetDateTime,
        batch: &mut CaptureBatch,
    ) -> Result<()> {
        match direction {
            Direction::ClientToServer => state.client_buffer.extend_from_slice(&bytes),
            Direction::ServerToClient => state.server_buffer.extend_from_slice(&bytes),
        }

        loop {
            match state.protocol {
                ProtocolState::Unknown => {
                    if state.client_buffer.starts_with(b"PRI * HTTP/2.0") {
                        state.protocol = ProtocolState::Http2(H2Decoder::new());
                        continue;
                    }
                    if looks_like_websocket_handshake(&state.client_buffer)
                        || looks_like_http1(&state.client_buffer)
                        || looks_like_http1_response(&state.server_buffer)
                    {
                        state.protocol = ProtocolState::Http1;
                        continue;
                    }
                }
                ProtocolState::Http1 => {
                    self.consume_http1(state, now, batch).await?;
                }
                ProtocolState::Http2(_) => {
                    let mut decoder =
                        match std::mem::replace(&mut state.protocol, ProtocolState::Unknown) {
                            ProtocolState::Http2(decoder) => decoder,
                            _ => unreachable!("protocol changed"),
                        };
                    self.consume_h2(state, &mut decoder, direction, &bytes, batch)
                        .await?;
                    state.protocol = ProtocolState::Http2(decoder);
                }
                ProtocolState::WebSocket(_) => {
                    let mut websocket =
                        match std::mem::replace(&mut state.protocol, ProtocolState::Unknown) {
                            ProtocolState::WebSocket(websocket) => websocket,
                            _ => unreachable!("protocol changed"),
                        };
                    self.consume_websocket(state, &mut websocket, direction, &bytes, batch)
                        .await?;
                    state.protocol = ProtocolState::WebSocket(websocket);
                }
            }
            break;
        }
        Ok(())
    }

    async fn consume_http1(
        &mut self,
        state: &mut FlowState,
        now: OffsetDateTime,
        batch: &mut CaptureBatch,
    ) -> Result<()> {
        while let Some(request_raw) = try_take_http1_request(&mut state.client_buffer)? {
            state.request_queue.push_back(RequestEnvelope {
                raw: request_raw,
                observed_at_ms: ts(now),
            });
        }

        while !state.request_queue.is_empty() {
            align_http1_response(&mut state.server_buffer);
            let Some(response_raw) = try_take_http1_response_or_terminal(&mut state.server_buffer)?
            else {
                break;
            };
            let request = state.request_queue.pop_front().expect("request checked");
            let request_msg = parse_http_request(&request.raw)?;
            let response_msg = parse_http_response(&response_raw)?;
            if response_msg
                .status
                .is_some_and(|status| status == http::StatusCode::SWITCHING_PROTOCOLS)
                && is_websocket_upgrade(&request_msg.headers, &response_msg.headers)
            {
                state.protocol = ProtocolState::WebSocket(WebSocketState::default());
                continue;
            }
            if !is_responses_request(&request_msg) {
                continue;
            }
            let exchange = DecodedExchange {
                attempt: decode_http_exchange(&request.raw, &response_raw, request.observed_at_ms)?,
                request_raw: request.raw,
                response_raw,
                request_headers: headers_to_map(&request_msg.headers),
                response_headers: headers_to_map(&response_msg.headers),
                response_status: response_msg.status.map(|status| status.as_u16()),
            };
            let projected = self.project_exchange(exchange).await?;
            if let Some(task) = projected.records.iter().find_map(summary_record_task) {
                state.current_task = Some(task.clone());
                self.associate_task(state.process_instance_id, task);
            }
            batch.records.extend(projected.records);
            batch.contents.extend(projected.contents);
        }
        Ok(())
    }

    async fn consume_h2(
        &mut self,
        state: &mut FlowState,
        decoder: &mut H2Decoder,
        direction: Direction,
        bytes: &[u8],
        batch: &mut CaptureBatch,
    ) -> Result<()> {
        let events = match direction {
            Direction::ClientToServer => decoder.push_client(bytes)?,
            Direction::ServerToClient => decoder.push_server(bytes)?,
        };
        for event in events {
            match event {
                H2Event::Headers(block) => {
                    let stream = state.h2_streams.entry(block.stream_id).or_default();
                    match direction {
                        Direction::ClientToServer => {
                            stream.request_headers.extend(block.headers);
                            stream.request_end = block.end_stream;
                            if stream.request_at_ms == 0 {
                                stream.request_at_ms = now_ms();
                            }
                        }
                        Direction::ServerToClient => {
                            stream.response_headers.extend(block.headers);
                            stream.response_end = block.end_stream;
                        }
                    }
                }
                H2Event::Data {
                    stream_id,
                    payload,
                    end_stream,
                } => {
                    let stream = state.h2_streams.entry(stream_id).or_default();
                    match direction {
                        Direction::ClientToServer => {
                            stream.request_body.extend_from_slice(&payload);
                            stream.request_end |= end_stream;
                            if stream.request_at_ms == 0 {
                                stream.request_at_ms = now_ms();
                            }
                        }
                        Direction::ServerToClient => {
                            stream.response_body.extend_from_slice(&payload);
                            stream.response_end |= end_stream;
                        }
                    }
                }
                H2Event::Priority(_) | H2Event::RstStream { .. } | H2Event::GoAway { .. } => {}
            }
        }

        let complete_streams: Vec<u32> = state
            .h2_streams
            .iter()
            .filter_map(|(stream_id, stream)| {
                (stream.request_end
                    && stream.response_end
                    && !stream.request_headers.is_empty()
                    && !stream.response_headers.is_empty())
                .then_some(*stream_id)
            })
            .collect();

        for stream_id in complete_streams {
            let Some(stream) = state.h2_streams.remove(&stream_id) else {
                continue;
            };
            let request_raw = synthesize_h2_request(&stream.request_headers, &stream.request_body)?;
            let response_raw =
                synthesize_h2_response(&stream.response_headers, &stream.response_body)?;
            let request_msg = parse_http_request(&request_raw)?;
            let response_msg = parse_http_response(&response_raw)?;
            if !is_responses_request(&request_msg) {
                continue;
            }
            let exchange = DecodedExchange {
                attempt: decode_http_exchange(&request_raw, &response_raw, stream.request_at_ms)?,
                request_raw,
                response_raw,
                request_headers: headers_to_map(&request_msg.headers),
                response_headers: headers_to_map(&response_msg.headers),
                response_status: response_msg.status.map(|status| status.as_u16()),
            };
            let projected = self.project_exchange(exchange).await?;
            if let Some(task) = projected.records.iter().find_map(summary_record_task) {
                state.current_task = Some(task.clone());
                self.associate_task(state.process_instance_id, task);
            }
            batch.records.extend(projected.records);
            batch.contents.extend(projected.contents);
        }
        Ok(())
    }

    async fn consume_websocket(
        &mut self,
        state: &mut FlowState,
        ws: &mut WebSocketState,
        direction: Direction,
        bytes: &[u8],
        batch: &mut CaptureBatch,
    ) -> Result<()> {
        let frames = match direction {
            Direction::ClientToServer => ws.client.push(bytes)?,
            Direction::ServerToClient => ws.server.push(bytes)?,
        };
        for frame in frames {
            if frame.opcode != 0x1 {
                continue;
            }
            match direction {
                Direction::ClientToServer => {
                    ws.current_request = Some(WebSocketRequest {
                        body: frame.payload,
                        observed_at: now_ms(),
                        response_events: Vec::new(),
                    });
                }
                Direction::ServerToClient => {
                    let Some(request) = &mut ws.current_request else {
                        continue;
                    };
                    let text = String::from_utf8_lossy(&frame.payload).to_string();
                    if text.trim_start().starts_with('{') {
                        request.response_events.push(text.clone());
                        let terminal = serde_json::from_str::<Value>(&text)
                            .ok()
                            .and_then(|value| {
                                value.get("type").and_then(Value::as_str).map(str::to_owned)
                            })
                            .is_some_and(|kind| {
                                matches!(
                                    kind.as_str(),
                                    "response.completed"
                                        | "response.failed"
                                        | "response.incomplete"
                                        | "response.cancelled"
                                )
                            });
                        if terminal {
                            let request_raw = synthesize_ws_request(&request.body);
                            let response_raw = synthesize_ws_response(&request.response_events);
                            let request_msg = parse_http_request(&request_raw)?;
                            let response_msg = parse_http_response(&response_raw)?;
                            let exchange = DecodedExchange {
                                attempt: decode_http_exchange(
                                    &request_raw,
                                    &response_raw,
                                    request.observed_at,
                                )?,
                                request_raw,
                                response_raw,
                                request_headers: headers_to_map(&request_msg.headers),
                                response_headers: headers_to_map(&response_msg.headers),
                                response_status: response_msg.status.map(|status| status.as_u16()),
                            };
                            let projected = self.project_exchange(exchange).await?;
                            if let Some(task) =
                                projected.records.iter().find_map(summary_record_task)
                            {
                                state.current_task = Some(task.clone());
                                self.associate_task(state.process_instance_id, task);
                            }
                            batch.records.extend(projected.records);
                            batch.contents.extend(projected.contents);
                            ws.current_request = None;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn associate_task(&mut self, process_instance_id: Option<Uuid>, task: TaskKey) {
        if let Some(process_instance_id) = process_instance_id {
            self.process_tasks
                .entry(process_instance_id)
                .or_default()
                .insert(task);
        }
    }

    async fn project_exchange(&self, exchange: DecodedExchange) -> Result<CaptureBatch> {
        if exchange.attempt.codex.request_kind != "turn" {
            return Ok(CaptureBatch {
                records: Vec::new(),
                contents: Vec::new(),
            });
        }

        let task = TaskKey {
            client_id: self.config.client_id.clone(),
            provider: crate::model::ProviderId::new(exchange.attempt.identity.provider.clone()),
            session_id: exchange.attempt.identity.session_id.clone(),
            thread_id: exchange.attempt.identity.thread_id.clone(),
            turn_id: exchange.attempt.identity.turn_id.clone(),
        };
        let attempt_projection = map_attempt_projection(&exchange.attempt);
        if let Some(response_id) = attempt_projection.response_id.as_deref()
            && self.store.has_attempt_response(&task, response_id).await?
        {
            return Ok(CaptureBatch {
                records: Vec::new(),
                contents: Vec::new(),
            });
        }
        let current = self.store.load_task_cursor(&task).await?;
        let sequence = current.as_ref().map_or(1, |cursor| cursor.sequence + 1);
        let ordinal = current
            .as_ref()
            .map_or(1, |cursor| cursor.attempt_count + 1);
        let started_at = current
            .as_ref()
            .map_or(from_ms(exchange.attempt.request_at_ms), |cursor| {
                cursor.started_at
            });

        let merged_tools = merge_unique(
            current
                .as_ref()
                .map_or_else(Vec::new, |cursor| cursor.tool_names.clone()),
            attempt_projection.tool_names.clone(),
        );
        let merged_responses = merge_unique(
            current
                .as_ref()
                .map_or_else(Vec::new, |cursor| cursor.response_ids.clone()),
            attempt_projection.response_id.clone().into_iter().collect(),
        );
        let task_summary = TaskSummary {
            task: task.clone(),
            conversation_title: self
                .conversation_titles
                .title(&task.session_id)
                .or_else(|| {
                    current
                        .as_ref()
                        .and_then(|cursor| cursor.conversation_title.clone())
                }),
            phase: attempt_projection.task_phase,
            outcome: None,
            sequence,
            last_event_id: Uuid::now_v7(),
            started_at,
            updated_at: OffsetDateTime::now_utc(),
            terminal_at: None,
            attempt_count: ordinal,
            model: exchange
                .attempt
                .model
                .clone()
                .or_else(|| current.as_ref().and_then(|cursor| cursor.model.clone())),
            tool_names: merged_tools,
            response_ids: merged_responses,
            usage: merge_usage(
                current.as_ref().map(|cursor| &cursor.usage),
                Some(&attempt_projection.usage),
            ),
            completeness: attempt_projection.completeness,
            last_error: attempt_projection.error.clone(),
        };
        let transition = TaskTransition {
            event_id: task_summary.last_event_id,
            task: task.clone(),
            sequence,
            observed_at: task_summary.updated_at,
            phase: task_summary.phase,
            outcome: None,
            cause: attempt_projection.cause,
            completeness: task_summary.completeness,
            error: task_summary.last_error.clone(),
        };
        let attempt = AttemptSummary {
            attempt_id: exchange.attempt.attempt_id,
            task: task.clone(),
            ordinal,
            status: attempt_projection.attempt_status,
            started_at: from_ms(exchange.attempt.request_at_ms),
            finished_at: Some(OffsetDateTime::now_utc()),
            response_id: attempt_projection.response_id.clone(),
            model: exchange.attempt.model.clone(),
            tool_names: attempt_projection.tool_names.clone(),
            usage: attempt_projection.usage.clone(),
            completeness: attempt_projection.completeness,
            error: attempt_projection.error.clone(),
        };
        let status = exchange.response_status;
        let request_body = parse_http_request(&exchange.request_raw)?.body.decoded;
        let response_body = parse_http_response(&exchange.response_raw)?.body.decoded;
        let request_len = request_body.len() as u64;
        let response_len = response_body.len() as u64;
        let request_sha = codexwatch_protocol::sha256_hex(&request_body);
        let response_sha = codexwatch_protocol::sha256_hex(&response_body);
        let mut contents = vec![
            StoredContentInput {
                task: task.clone(),
                part: ContentPart::Request,
                media_type: exchange
                    .request_headers
                    .get("content-type")
                    .cloned()
                    .unwrap_or_else(|| "application/json".into()),
                body: request_body,
                headers: exchange.request_headers,
                created_at: OffsetDateTime::now_utc(),
            },
            StoredContentInput {
                task: task.clone(),
                part: ContentPart::Response,
                media_type: exchange
                    .response_headers
                    .get("content-type")
                    .cloned()
                    .unwrap_or_else(|| "text/event-stream".into()),
                body: response_body,
                headers: exchange.response_headers,
                created_at: OffsetDateTime::now_utc(),
            },
        ];
        contents.extend(extract_additional_contents(&task, &exchange.attempt));
        Ok(CaptureBatch {
            records: vec![
                SummaryRecord::Session(SessionSummary {
                    task: task.clone(),
                    parent_turn_id: exchange.attempt.codex.parent_turn_id.clone(),
                    root_turn_id: exchange.attempt.codex.root_turn_id.clone(),
                    first_seen_at: started_at,
                }),
                SummaryRecord::Attempt(attempt.clone()),
                SummaryRecord::HttpExchange(HttpExchangeSummary {
                    exchange_id: Uuid::now_v7(),
                    task: task.clone(),
                    attempt_id: attempt.attempt_id,
                    observed_at: OffsetDateTime::now_utc(),
                    method: "POST".into(),
                    path: "/v1/responses".into(),
                    status,
                    request_bytes: request_len,
                    response_bytes: response_len,
                    request_sha256: Some(request_sha),
                    response_sha256: Some(response_sha),
                    completeness: attempt_projection.completeness,
                }),
                SummaryRecord::Task(task_summary),
                SummaryRecord::TaskTransition(transition),
            ],
            contents,
        })
    }

    async fn project_gap(
        &self,
        flow_id: Uuid,
        task: Option<TaskKey>,
        observed_at: OffsetDateTime,
        reason: String,
        lost_bytes: Option<u64>,
    ) -> Result<CaptureBatch> {
        let mut records = vec![SummaryRecord::CaptureGap(CaptureGapSummary {
            gap_id: Uuid::now_v7(),
            client_instance_id: self.config.client_instance_id,
            task: task.clone(),
            observed_at,
            reason: reason.clone(),
            lost_bytes,
            flow_id: Some(flow_id),
        })];

        if let Some(task) = task {
            let cursor = self.store.load_task_cursor(&task).await?;
            if let Some(cursor) = cursor {
                let error = StructuredError::CaptureLost(CaptureLoss { reason, lost_bytes });
                let summary = TaskSummary {
                    task: task.clone(),
                    conversation_title: self
                        .conversation_titles
                        .title(&task.session_id)
                        .or(cursor.conversation_title),
                    phase: cursor.phase,
                    outcome: cursor.outcome,
                    sequence: cursor.sequence + 1,
                    last_event_id: Uuid::now_v7(),
                    started_at: cursor.started_at,
                    updated_at: observed_at,
                    terminal_at: None,
                    attempt_count: cursor.attempt_count,
                    model: cursor.model,
                    tool_names: cursor.tool_names,
                    response_ids: cursor.response_ids,
                    usage: cursor.usage,
                    completeness: Completeness::Degraded,
                    last_error: Some(error.clone()),
                };
                records.push(SummaryRecord::Task(summary.clone()));
                records.push(SummaryRecord::TaskTransition(TaskTransition {
                    event_id: summary.last_event_id,
                    task,
                    sequence: summary.sequence,
                    observed_at,
                    phase: summary.phase,
                    outcome: summary.outcome,
                    cause: TransitionCause::CaptureLost,
                    completeness: summary.completeness,
                    error: Some(error),
                }));
            }
        }

        Ok(CaptureBatch {
            records,
            contents: Vec::new(),
        })
    }

    async fn project_process_exit(
        &self,
        process: ProcessSummary,
        tasks: Vec<TaskKey>,
    ) -> Result<CaptureBatch> {
        let observed_at = process.exited_at.unwrap_or_else(OffsetDateTime::now_utc);
        let mut records = vec![SummaryRecord::Process(process.clone())];
        for task in tasks {
            let Some(cursor) = self.store.load_task_cursor(&task).await? else {
                continue;
            };
            if cursor.phase == TaskPhase::Terminal {
                continue;
            }
            let (outcome, error) =
                if process.signal.is_some() || process.exit_code.is_some_and(|code| code != 0) {
                    (
                        TaskOutcome::Terminated,
                        StructuredError::ProcessTerminated(ProcessTermination {
                            exit_code: process.exit_code,
                            signal: process.signal,
                        }),
                    )
                } else {
                    (
                        TaskOutcome::Lost,
                        StructuredError::CaptureLost(CaptureLoss {
                            reason: "process exited without validated terminal turn event".into(),
                            lost_bytes: None,
                        }),
                    )
                };
            let summary = TaskSummary {
                task: task.clone(),
                conversation_title: self
                    .conversation_titles
                    .title(&task.session_id)
                    .or(cursor.conversation_title),
                phase: TaskPhase::Terminal,
                outcome: Some(outcome),
                sequence: cursor.sequence + 1,
                last_event_id: Uuid::now_v7(),
                started_at: cursor.started_at,
                updated_at: observed_at,
                terminal_at: Some(observed_at),
                attempt_count: cursor.attempt_count,
                model: cursor.model,
                tool_names: cursor.tool_names,
                response_ids: cursor.response_ids,
                usage: cursor.usage,
                completeness: cursor.completeness,
                last_error: Some(error.clone()),
            };
            records.push(SummaryRecord::Task(summary.clone()));
            records.push(SummaryRecord::TaskTransition(TaskTransition {
                event_id: summary.last_event_id,
                task,
                sequence: summary.sequence,
                observed_at,
                phase: TaskPhase::Terminal,
                outcome: summary.outcome,
                cause: TransitionCause::ProcessExited,
                completeness: summary.completeness,
                error: Some(error),
            }));
        }
        Ok(CaptureBatch {
            records,
            contents: Vec::new(),
        })
    }
}

#[derive(Debug, Clone)]
struct AttemptProjection {
    attempt_status: AttemptStatus,
    task_phase: TaskPhase,
    completeness: Completeness,
    error: Option<StructuredError>,
    response_id: Option<String>,
    tool_names: Vec<String>,
    usage: TokenUsage,
    cause: TransitionCause,
}

fn map_attempt_projection(attempt: &DecodedAttempt) -> AttemptProjection {
    let mut response_id = None;
    let mut tool_names = Vec::new();
    let mut usage = TokenUsage::default();
    let mut error = None;
    let mut end_turn = true;
    let mut status = AttemptStatus::Running;
    let mut phase = TaskPhase::Running;
    let mut cause = TransitionCause::AttemptStarted;
    let mut saw_terminal = false;
    for event in &attempt.decoded_events {
        match event {
            DecodedEvent::ToolCall { tool_name, .. } => {
                if !tool_names.iter().any(|item| item == tool_name) {
                    tool_names.push(tool_name.clone());
                }
            }
            DecodedEvent::AttemptCompleted {
                response_id: current_response_id,
                end_turn: current_end_turn,
                usage: current_usage,
                ..
            } => {
                response_id = current_response_id.clone();
                end_turn = *current_end_turn;
                usage = TokenUsage {
                    input_tokens: Some(current_usage.input_tokens),
                    output_tokens: Some(current_usage.output_tokens),
                    cached_input_tokens: None,
                    reasoning_tokens: Some(current_usage.reasoning_tokens),
                    total_tokens: Some(current_usage.total_tokens),
                };
                status = AttemptStatus::Completed;
                phase = TaskPhase::Running;
                cause = TransitionCause::AttemptCompleted;
                saw_terminal = true;
            }
            DecodedEvent::AttemptFailed {
                response_id: current_response_id,
                error: current_error,
                ..
            } => {
                status = AttemptStatus::Failed;
                phase = TaskPhase::Retrying;
                cause = TransitionCause::RetryScheduled;
                response_id = current_response_id.clone();
                error = Some(structured_error_from_decoded(current_error));
                saw_terminal = true;
            }
            DecodedEvent::AttemptIncomplete {
                response_id: current_response_id,
                error: current_error,
                ..
            } => {
                status = AttemptStatus::Incomplete;
                phase = TaskPhase::Retrying;
                cause = TransitionCause::RetryScheduled;
                response_id = current_response_id.clone();
                error = Some(structured_error_from_decoded(current_error));
                saw_terminal = true;
            }
            DecodedEvent::AttemptCancelled {
                response_id: current_response_id,
                error: current_error,
                ..
            } => {
                status = AttemptStatus::Cancelled;
                phase = TaskPhase::Retrying;
                cause = TransitionCause::RetryScheduled;
                response_id = current_response_id.clone();
                error = Some(structured_error_from_decoded(current_error));
                saw_terminal = true;
            }
            DecodedEvent::HttpError {
                error: current_error,
                ..
            } => {
                status = AttemptStatus::Failed;
                phase = TaskPhase::Retrying;
                cause = TransitionCause::RetryScheduled;
                error = Some(structured_error_from_decoded(current_error));
                saw_terminal = true;
            }
            DecodedEvent::TaskObserved { .. } | DecodedEvent::AttemptStarted { .. } => {}
        }
    }

    let mut completeness =
        if attempt.request_complete && (attempt.response_complete || saw_terminal) {
            Completeness::Complete
        } else {
            Completeness::Degraded
        };

    if !saw_terminal || completeness == Completeness::Degraded {
        completeness = Completeness::Degraded;
        status = AttemptStatus::TransportLost;
        phase = TaskPhase::Retrying;
        cause = TransitionCause::CaptureLost;
        error = Some(StructuredError::CaptureLost(CaptureLoss {
            reason: if !saw_terminal {
                "stream closed before response.completed".into()
            } else {
                "request or response body incomplete".into()
            },
            lost_bytes: None,
        }));
    } else if status == AttemptStatus::Completed && (!tool_names.is_empty() || !end_turn) {
        phase = TaskPhase::AwaitingTool;
        cause = TransitionCause::ToolCallObserved;
    }

    AttemptProjection {
        attempt_status: status,
        task_phase: phase,
        completeness,
        error,
        response_id,
        tool_names,
        usage,
        cause,
    }
}

fn structured_error_from_decoded(error: &DecodedError) -> StructuredError {
    if let Some(status) = error.http_status {
        return StructuredError::Http(HttpError {
            status,
            provider_error: Some(ProviderError {
                wire_type: error
                    .wire_type
                    .clone()
                    .unwrap_or_else(|| "http_error".into()),
                code: error.code.clone(),
                message: error
                    .message
                    .clone()
                    .unwrap_or_else(|| format!("http {}", status)),
                param: error.param.clone(),
            }),
        });
    }
    if let Some(reason) = &error.reason {
        return StructuredError::Incomplete(IncompleteResponse {
            reason: reason.clone(),
        });
    }
    StructuredError::Provider(ProviderError {
        wire_type: error
            .wire_type
            .clone()
            .unwrap_or_else(|| "response.failed".into()),
        code: error.code.clone(),
        message: error
            .message
            .clone()
            .unwrap_or_else(|| "unknown error".into()),
        param: error.param.clone(),
    })
}

fn merge_usage(current: Option<&TokenUsage>, update: Option<&TokenUsage>) -> TokenUsage {
    let mut merged = current.cloned().unwrap_or_default();
    if let Some(update) = update {
        merged.input_tokens = update.input_tokens.or(merged.input_tokens);
        merged.output_tokens = update.output_tokens.or(merged.output_tokens);
        merged.cached_input_tokens = update.cached_input_tokens.or(merged.cached_input_tokens);
        merged.reasoning_tokens = update.reasoning_tokens.or(merged.reasoning_tokens);
        merged.total_tokens = update.total_tokens.or(merged.total_tokens);
    }
    merged
}

fn merge_unique(mut current: Vec<String>, appended: Vec<String>) -> Vec<String> {
    for value in appended {
        if !value.is_empty() && !current.iter().any(|existing| existing == &value) {
            current.push(value);
        }
    }
    current
}

fn summary_record_task(record: &SummaryRecord) -> Option<TaskKey> {
    match record {
        SummaryRecord::Task(summary) => Some(summary.task.clone()),
        SummaryRecord::Attempt(attempt) => Some(attempt.task.clone()),
        SummaryRecord::TaskTransition(transition) => Some(transition.task.clone()),
        SummaryRecord::Session(session) => Some(session.task.clone()),
        SummaryRecord::CaptureGap(gap) => gap.task.clone(),
        SummaryRecord::HttpExchange(exchange) => Some(exchange.task.clone()),
        SummaryRecord::Process(_) | SummaryRecord::Heartbeat(_) => None,
    }
}

fn parse_endpoint(ip: &str, port: u16) -> Result<Endpoint> {
    Ok(Endpoint {
        ip: ip.parse()?,
        port,
    })
}

fn looks_like_request(bytes: &[u8]) -> bool {
    bytes.starts_with(b"GET ")
        || bytes.starts_with(b"POST ")
        || bytes.starts_with(b"PUT ")
        || bytes.starts_with(b"DELETE ")
        || bytes.starts_with(b"PATCH ")
        || bytes.starts_with(b"PRI * HTTP/2.0")
}

fn looks_like_http1(bytes: &[u8]) -> bool {
    looks_like_request(bytes)
}

fn looks_like_http1_response(bytes: &[u8]) -> bool {
    bytes.starts_with(b"HTTP/1.")
}

fn looks_like_websocket_handshake(bytes: &[u8]) -> bool {
    bytes
        .windows(19)
        .any(|window| window.eq_ignore_ascii_case(b"upgrade: websocket"))
}

fn is_websocket_upgrade(
    request_headers: &http::HeaderMap,
    response_headers: &http::HeaderMap,
) -> bool {
    request_headers
        .get(http::header::UPGRADE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("websocket"))
        && response_headers
            .get(http::header::UPGRADE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.eq_ignore_ascii_case("websocket"))
}

fn is_responses_request(request: &crate::decode_support::HttpMessage) -> bool {
    request
        .uri
        .as_ref()
        .is_some_and(|uri| uri.path().trim_end_matches('/').ends_with("/responses"))
}

fn try_take_http1_request(buffer: &mut Vec<u8>) -> Result<Option<Vec<u8>>, HttpParseError> {
    try_take_http1_message(buffer, true)
}

fn try_take_http1_response(buffer: &mut Vec<u8>) -> Result<Option<Vec<u8>>, HttpParseError> {
    try_take_http1_message(buffer, false)
}

fn try_take_http1_response_or_terminal(
    buffer: &mut Vec<u8>,
) -> Result<Option<Vec<u8>>, HttpParseError> {
    if let Some(response) = try_take_http1_response(buffer)? {
        return Ok(Some(response));
    }
    if find_header_end(buffer).is_none() {
        return Ok(None);
    }
    let response = parse_http_response(buffer)?;
    let is_stream = response
        .headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.to_ascii_lowercase().contains("text/event-stream"));
    if is_stream && has_terminal_sse_event(&response.body.decoded) {
        return Ok(Some(std::mem::take(buffer)));
    }
    Ok(None)
}

fn has_terminal_sse_event(body: &[u8]) -> bool {
    parse_sse_events(body).is_ok_and(|events| {
        events.into_iter().any(|event| {
            serde_json::from_str::<Value>(&event.data)
                .ok()
                .and_then(|value| value.get("type").and_then(Value::as_str).map(str::to_owned))
                .is_some_and(|kind| {
                    matches!(
                        kind.as_str(),
                        "error"
                            | "response.completed"
                            | "response.failed"
                            | "response.incomplete"
                            | "response.cancelled"
                    )
                })
        })
    })
}

fn align_http1_response(buffer: &mut Vec<u8>) {
    const PREFIX: &[u8] = b"HTTP/1.";
    if buffer.starts_with(PREFIX) || buffer.is_empty() {
        return;
    }
    if let Some(offset) = buffer
        .windows(PREFIX.len())
        .position(|window| window == PREFIX)
    {
        buffer.drain(..offset);
        return;
    }
    let suffix_len = (1..=buffer.len().min(PREFIX.len()))
        .rev()
        .find(|length| buffer.ends_with(&PREFIX[..*length]))
        .unwrap_or(0);
    buffer.drain(..buffer.len() - suffix_len);
}

fn try_take_http1_message(
    buffer: &mut Vec<u8>,
    request: bool,
) -> Result<Option<Vec<u8>>, HttpParseError> {
    let Some(header_end) = find_header_end(buffer) else {
        return Ok(None);
    };
    let headers = if request {
        parse_http_request(&buffer[..header_end])?.headers
    } else {
        parse_http_response(&buffer[..header_end])?.headers
    };
    let total_len = if is_chunked_headers(&headers) {
        let Some(chunk_end) = find_chunked_end(buffer, header_end) else {
            return Ok(None);
        };
        chunk_end
    } else {
        let content_len = headers
            .get(http::header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0);
        let total = header_end + content_len;
        if buffer.len() < total {
            return Ok(None);
        }
        total
    };
    Ok(Some(buffer.drain(..total_len).collect()))
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
}

fn is_chunked_headers(headers: &http::HeaderMap) -> bool {
    headers
        .get(http::header::TRANSFER_ENCODING)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.to_ascii_lowercase().contains("chunked"))
}

fn find_chunked_end(bytes: &[u8], header_end: usize) -> Option<usize> {
    bytes[header_end..]
        .windows(5)
        .position(|window| window == b"0\r\n\r\n")
        .map(|offset| header_end + offset + 5)
}

fn synthesize_h2_request(headers: &[(String, String)], body: &[u8]) -> Result<Vec<u8>> {
    let method = header_value(headers, ":method").unwrap_or("POST");
    let path = header_value(headers, ":path").unwrap_or("/v1/responses");
    let mut output = format!("{method} {path} HTTP/1.1\r\n");
    for (name, value) in headers {
        if name.starts_with(':') {
            continue;
        }
        output.push_str(name);
        output.push_str(": ");
        output.push_str(value);
        output.push_str("\r\n");
    }
    output.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
    let mut bytes = output.into_bytes();
    bytes.extend_from_slice(body);
    Ok(bytes)
}

fn synthesize_h2_response(headers: &[(String, String)], body: &[u8]) -> Result<Vec<u8>> {
    let status = header_value(headers, ":status").unwrap_or("200");
    let mut output = format!("HTTP/1.1 {status} OK\r\n");
    for (name, value) in headers {
        if name.starts_with(':') {
            continue;
        }
        output.push_str(name);
        output.push_str(": ");
        output.push_str(value);
        output.push_str("\r\n");
    }
    output.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
    let mut bytes = output.into_bytes();
    bytes.extend_from_slice(body);
    Ok(bytes)
}

fn synthesize_ws_request(body: &[u8]) -> Vec<u8> {
    let head = format!(
        "POST /v1/responses HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    let mut bytes = head.into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

fn synthesize_ws_response(events: &[String]) -> Vec<u8> {
    let mut body = String::new();
    for event in events {
        body.push_str("event: message\n");
        body.push_str("data: ");
        body.push_str(event);
        body.push_str("\n\n");
    }
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    let mut bytes = head.into_bytes();
    bytes.extend_from_slice(body.as_bytes());
    bytes
}

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(current, _)| current.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn extract_additional_contents(
    task: &TaskKey,
    attempt: &DecodedAttempt,
) -> Vec<StoredContentInput> {
    let mut contents = Vec::new();
    if let Some(body) = extract_tool_inputs(attempt) {
        contents.push(StoredContentInput {
            task: task.clone(),
            part: ContentPart::ToolInput,
            media_type: "application/json".into(),
            body,
            headers: std::collections::BTreeMap::new(),
            created_at: OffsetDateTime::now_utc(),
        });
    }
    if let Some(body) = extract_tool_outputs(attempt) {
        contents.push(StoredContentInput {
            task: task.clone(),
            part: ContentPart::ToolOutput,
            media_type: "application/json".into(),
            body,
            headers: std::collections::BTreeMap::new(),
            created_at: OffsetDateTime::now_utc(),
        });
    }
    if let Some(body) = extract_model_text(attempt) {
        contents.push(StoredContentInput {
            task: task.clone(),
            part: ContentPart::ModelText,
            media_type: "text/plain".into(),
            body,
            headers: std::collections::BTreeMap::new(),
            created_at: OffsetDateTime::now_utc(),
        });
    }
    contents
}

fn extract_tool_inputs(attempt: &DecodedAttempt) -> Option<Vec<u8>> {
    let items = attempt
        .response_json_events
        .iter()
        .filter_map(|event| event.get("item"))
        .filter(|item| {
            item.get("type")
                .and_then(Value::as_str)
                .is_some_and(|kind| {
                    matches!(
                        kind,
                        "function_call" | "tool_search_call" | "custom_tool_call"
                    )
                })
        })
        .cloned()
        .collect::<Vec<_>>();
    (!items.is_empty()).then(|| serde_json::to_vec(&items).expect("serialize tool input"))
}

fn extract_tool_outputs(attempt: &DecodedAttempt) -> Option<Vec<u8>> {
    let items = attempt
        .request_json
        .get("input")
        .and_then(Value::as_array)
        .into_iter()
        .flat_map(|items| items.iter())
        .filter(|item| {
            item.get("type")
                .and_then(Value::as_str)
                .is_some_and(|kind| {
                    matches!(kind, "function_call_output" | "tool_result" | "tool_output")
                })
        })
        .cloned()
        .collect::<Vec<_>>();
    (!items.is_empty()).then(|| serde_json::to_vec(&items).expect("serialize tool output"))
}

fn extract_model_text(attempt: &DecodedAttempt) -> Option<Vec<u8>> {
    let mut lines = Vec::new();
    for event in &attempt.response_json_events {
        collect_text_nodes(event, &mut lines);
    }
    let text = lines
        .into_iter()
        .filter(|line| !line.trim().is_empty())
        .collect::<Vec<_>>();
    (!text.is_empty()).then(|| text.join("\n").into_bytes())
}

fn collect_text_nodes(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                if matches!(key.as_str(), "text" | "output_text" | "delta") && value.is_string() {
                    out.push(value.as_str().unwrap_or_default().to_string());
                } else {
                    collect_text_nodes(value, out);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_text_nodes(item, out);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

fn ts(value: OffsetDateTime) -> i64 {
    value.unix_timestamp() * 1000
}

fn from_ms(value: i64) -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(value) * 1_000_000)
        .expect("valid timestamp")
}

fn detect_codex_version(executable_path: &std::path::Path) -> Option<String> {
    executable_path
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| {
            name.split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '.'))
                .find(|part| part.chars().filter(|ch| *ch == '.').count() >= 2)
                .map(str::to_string)
        })
}

fn now_ms() -> i64 {
    ts(OffsetDateTime::now_utc())
}

pub async fn run_capture_loop(
    lane: &mut LiveCaptureLane,
    source: &mut dyn LiveCaptureSource,
    poll_interval: StdDuration,
) -> Result<()> {
    let mut scratch = vec![0_u8; CAPTURE_BUFFER_BYTES];
    loop {
        match source.recv(&mut scratch)? {
            Some(input) => {
                let _ = lane.ingest_input(input).await?;
            }
            None => sleep(poll_interval).await,
        }
    }
}

pub async fn run_process_discovery_loop(
    lane: &mut LiveCaptureLane,
    discovery: &mut dyn ProcessDiscovery,
    interval: StdDuration,
) -> Result<()> {
    loop {
        for event in discovery.poll(OffsetDateTime::now_utc())? {
            let _ = lane.ingest_input(event).await?;
        }
        sleep(interval).await;
    }
}
