pub const ABI_VERSION: u16 = 1;
pub const MAX_CAPTURE_BYTES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ProbeDirection {
    None = 0,
    Read = 1,
    Write = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ProbeKind {
    ProcessExec = 0,
    ProcessExit = 1,
    TcpStateChange = 2,
    ConnectionCreate = 3,
    ConnectionDrop = 4,
    PlaintextWrite = 5,
    PlaintextRead = 6,
    TurnComplete = 7,
    TurnAbort = 8,
    TerminalError = 9,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct ConnectionIdentity {
    pub boot_id: [u8; 16],
    pub tgid: u32,
    pub pid: u32,
    pub start_ticks: u64,
    pub connection_ptr: u64,
    pub epoch: u64,
    pub call_sequence: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct CaptureRecordHeader {
    pub abi_version: u16,
    pub header_len: u16,
    pub kind: ProbeKind,
    pub direction: ProbeDirection,
    pub cpu: u16,
    pub pad0: u16,
    pub connection: ConnectionIdentity,
    pub file_offset: u64,
    pub data_offset: u64,
    pub data_length: u32,
    pub aux_value: u32,
    pub aux_value2: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct CaptureRecord {
    pub header: CaptureRecordHeader,
    pub payload: [u8; MAX_CAPTURE_BYTES],
}

impl CaptureRecord {
    #[must_use]
    pub const fn empty(kind: ProbeKind, direction: ProbeDirection) -> Self {
        Self {
            header: CaptureRecordHeader {
                abi_version: ABI_VERSION,
                header_len: core::mem::size_of::<CaptureRecordHeader>() as u16,
                kind,
                direction,
                cpu: 0,
                pad0: 0,
                connection: ConnectionIdentity {
                    boot_id: [0; 16],
                    tgid: 0,
                    pid: 0,
                    start_ticks: 0,
                    connection_ptr: 0,
                    epoch: 0,
                    call_sequence: 0,
                },
                file_offset: 0,
                data_offset: 0,
                data_length: 0,
                aux_value: 0,
                aux_value2: 0,
            },
            payload: [0; MAX_CAPTURE_BYTES],
        }
    }
}
