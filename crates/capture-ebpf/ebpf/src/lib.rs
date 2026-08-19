#![allow(dead_code)]
#![no_std]
#![no_main]

#[path = "../../src/abi.rs"]
mod abi;

use abi::{
    ABI_VERSION, CaptureRecord, CaptureRecordHeader, ConnectionIdentity, MAX_CAPTURE_BYTES,
    ProbeDirection, ProbeKind,
};
use aya_ebpf::PtRegs;
use aya_ebpf::cty::c_long;
use aya_ebpf::helpers::{
    bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_user_buf,
};
use aya_ebpf::macros::{kprobe, map, tracepoint, uprobe, uretprobe};
use aya_ebpf::maps::{Array, HashMap, PerCpuArray, RingBuf};
use aya_ebpf::programs::{ProbeContext, RetProbeContext, TracePointContext};
use core::cmp::min;
use core::mem::size_of;
use core::panic::PanicInfo;

#[repr(C)]
#[derive(Clone, Copy)]
struct InflightIo {
    connection_ptr: u64,
    buf_ptr: u64,
    requested_len: u32,
    file_offset: u64,
    epoch: u64,
    call_sequence: u64,
    tgid: u32,
    pid: u32,
    start_ticks: u64,
}

#[map]
static BOOT_ID: Array<[u8; 16]> = Array::with_max_entries(1, 0);

#[map]
static PROCESS_START: HashMap<u32, u64> = HashMap::with_max_entries(4096, 0);

#[map]
static CONNECTION_EPOCH: HashMap<u64, u64> = HashMap::with_max_entries(8192, 0);

#[map]
static CONNECTION_SEQUENCE: HashMap<u64, u64> = HashMap::with_max_entries(8192, 0);

#[map]
static INFLIGHT_WRITES: HashMap<u64, InflightIo> = HashMap::with_max_entries(8192, 0);

#[map]
static INFLIGHT_READS: HashMap<u64, InflightIo> = HashMap::with_max_entries(8192, 0);

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(1 << 22, 0);

#[map]
static SCRATCH_RECORDS: PerCpuArray<CaptureRecord> = PerCpuArray::with_max_entries(1, 0);

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[tracepoint(name = "sched_process_exec", category = "sched")]
pub fn process_exec(ctx: TracePointContext) -> u32 {
    let _ = try_process_exec(ctx);
    0
}

#[tracepoint(name = "sched_process_exit", category = "sched")]
pub fn process_exit(ctx: TracePointContext) -> u32 {
    let _ = try_process_exit(ctx);
    0
}

#[kprobe(function = "tcp_set_state")]
pub fn tcp_state(ctx: ProbeContext) -> u32 {
    let _ = try_tcp_state(ctx);
    0
}

#[uprobe]
pub fn plaintext_write_enter(ctx: ProbeContext) -> u32 {
    let _ = try_plaintext_write_enter(ctx, 0x27f34b0);
    0
}

#[uretprobe]
pub fn plaintext_write_return(ctx: RetProbeContext) -> u32 {
    let _ = try_plaintext_write_return(ctx);
    0
}

#[uprobe]
pub fn plaintext_write_enter_alt(ctx: ProbeContext) -> u32 {
    let _ = try_plaintext_write_enter(ctx, 0x27f3560);
    0
}

#[uretprobe]
pub fn plaintext_write_return_alt(ctx: RetProbeContext) -> u32 {
    let _ = try_plaintext_write_return(ctx);
    0
}

#[uprobe]
pub fn plaintext_read_enter_candidate(ctx: ProbeContext) -> u32 {
    let _ = try_plaintext_read_enter(ctx, 0x0b506f60);
    0
}

#[uretprobe]
pub fn plaintext_read_return_candidate(ctx: RetProbeContext) -> u32 {
    let _ = try_plaintext_read_return(ctx);
    0
}

fn try_process_exec(_ctx: TracePointContext) -> Result<(), c_long> {
    let identity = current_identity(0, 0, 0)?;
    let now = identity.start_ticks;
    let _ = PROCESS_START.insert(&identity.tgid, &now, 0);
    let comm = bpf_get_current_comm()?;
    emit_with_payload(
        ProbeKind::ProcessExec,
        ProbeDirection::None,
        identity,
        0,
        0,
        0,
        0,
        &comm,
    )
}

fn try_process_exit(_ctx: TracePointContext) -> Result<(), c_long> {
    let identity = current_identity(0, 0, 0)?;
    let _ = PROCESS_START.remove(&identity.tgid);
    let comm = bpf_get_current_comm()?;
    emit_with_payload(
        ProbeKind::ProcessExit,
        ProbeDirection::None,
        identity,
        0,
        0,
        0,
        0,
        &comm,
    )
}

fn try_tcp_state(ctx: ProbeContext) -> Result<(), c_long> {
    let sock: *const u8 = ctx.arg(0).ok_or(0)?;
    let state: i32 = ctx.arg(1).ok_or(0)?;
    let identity = current_identity(sock as u64, 0, 0)?;
    emit_with_payload(
        ProbeKind::TcpStateChange,
        ProbeDirection::None,
        identity,
        0,
        0,
        state as u32,
        0,
        &[],
    )
}

fn try_plaintext_write_enter(ctx: ProbeContext, file_offset: u64) -> Result<(), c_long> {
    let connection: *const u8 = ctx.arg(0).ok_or(0)?;
    let buf: *const u8 = ctx.arg(1).ok_or(0)?;
    let len: usize = ctx.arg(2).ok_or(0)?;
    let pid_tgid = bpf_get_current_pid_tgid();
    let connection_ptr = connection as u64;
    let (epoch, created) = connection_epoch(connection_ptr)?;
    let sequence = next_sequence(connection_ptr)?;
    let identity = current_identity(connection_ptr, epoch, sequence)?;
    if created {
        emit_with_payload(
            ProbeKind::ConnectionCreate,
            ProbeDirection::None,
            identity,
            file_offset,
            0,
            0,
            0,
            &[],
        )?;
    }

    let inflight = InflightIo {
        connection_ptr,
        buf_ptr: buf as u64,
        requested_len: min(len, u32::MAX as usize) as u32,
        file_offset,
        epoch,
        call_sequence: sequence,
        tgid: identity.tgid,
        pid: identity.pid,
        start_ticks: identity.start_ticks,
    };
    let _ = INFLIGHT_WRITES.insert(&pid_tgid, &inflight, 0);
    Ok(())
}

fn try_plaintext_write_return(ctx: RetProbeContext) -> Result<(), c_long> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let Some(inflight) = (unsafe { INFLIGHT_WRITES.get(&pid_tgid) }) else {
        return Ok(());
    };

    let regs = PtRegs::new(ctx.regs);
    let raw_tag = regs.ret::<u64>().unwrap_or_default();
    let raw_len = reg_rdx(ctx);
    let ok = raw_tag == 0;
    let actual_len = if ok {
        min(raw_len as usize, inflight.requested_len as usize)
    } else {
        0
    };
    let identity = connection_identity_from_inflight(*inflight)?;
    emit_record_from_user_ptr(
        ProbeKind::PlaintextWrite,
        ProbeDirection::Write,
        identity,
        inflight.file_offset,
        0,
        raw_tag as u32,
        raw_len,
        inflight.buf_ptr as *const u8,
        min(actual_len, MAX_CAPTURE_BYTES),
    )?;
    let _ = INFLIGHT_WRITES.remove(&pid_tgid);
    Ok(())
}

fn try_plaintext_read_enter(ctx: ProbeContext, file_offset: u64) -> Result<(), c_long> {
    let reader: *const u8 = ctx.arg(0).ok_or(0)?;
    let buf: *const u8 = ctx.arg(1).ok_or(0)?;
    let len: usize = ctx.arg(2).ok_or(0)?;
    let pid_tgid = bpf_get_current_pid_tgid();
    let connection_ptr = reader as u64;
    let (epoch, created) = connection_epoch(connection_ptr)?;
    let sequence = next_sequence(connection_ptr)?;
    let identity = current_identity(connection_ptr, epoch, sequence)?;
    if created {
        emit_with_payload(
            ProbeKind::ConnectionCreate,
            ProbeDirection::None,
            identity,
            file_offset,
            0,
            0,
            0,
            &[],
        )?;
    }
    let inflight = InflightIo {
        connection_ptr,
        buf_ptr: buf as u64,
        requested_len: min(len, u32::MAX as usize) as u32,
        file_offset,
        epoch,
        call_sequence: sequence,
        tgid: identity.tgid,
        pid: identity.pid,
        start_ticks: identity.start_ticks,
    };
    let _ = INFLIGHT_READS.insert(&pid_tgid, &inflight, 0);
    Ok(())
}

fn try_plaintext_read_return(ctx: RetProbeContext) -> Result<(), c_long> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let Some(inflight) = (unsafe { INFLIGHT_READS.get(&pid_tgid) }) else {
        return Ok(());
    };
    let regs = PtRegs::new(ctx.regs);
    let raw_tag = regs.ret::<u64>().unwrap_or_default();
    let raw_len = reg_rdx(ctx);
    let identity = connection_identity_from_inflight(*inflight)?;
    emit_record(
        ProbeKind::PlaintextRead,
        ProbeDirection::Read,
        identity,
        inflight.file_offset,
        0,
        raw_tag as u32,
        raw_len,
        &[],
    )?;
    let _ = INFLIGHT_READS.remove(&pid_tgid);
    Ok(())
}

fn current_identity(
    connection_ptr: u64,
    epoch: u64,
    call_sequence: u64,
) -> Result<ConnectionIdentity, c_long> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;
    let tgid = (pid_tgid >> 32) as u32;
    let start_ticks = unsafe { PROCESS_START.get(&tgid).copied() }
        .unwrap_or_else(|| unsafe { bpf_ktime_get_ns() });
    let boot_id = BOOT_ID.get(0).copied().unwrap_or([0; 16]);
    Ok(ConnectionIdentity {
        boot_id,
        tgid,
        pid,
        start_ticks,
        connection_ptr,
        epoch,
        call_sequence,
    })
}

fn connection_identity_from_inflight(inflight: InflightIo) -> Result<ConnectionIdentity, c_long> {
    let boot_id = BOOT_ID.get(0).copied().unwrap_or([0; 16]);
    Ok(ConnectionIdentity {
        boot_id,
        tgid: inflight.tgid,
        pid: inflight.pid,
        start_ticks: inflight.start_ticks,
        connection_ptr: inflight.connection_ptr,
        epoch: inflight.epoch,
        call_sequence: inflight.call_sequence,
    })
}

fn connection_epoch(connection_ptr: u64) -> Result<(u64, bool), c_long> {
    if let Some(existing) = unsafe { CONNECTION_EPOCH.get(&connection_ptr) } {
        return Ok((*existing, false));
    }
    let epoch = 1_u64;
    let _ = CONNECTION_EPOCH.insert(&connection_ptr, &epoch, 0);
    Ok((epoch, true))
}

fn next_sequence(connection_ptr: u64) -> Result<u64, c_long> {
    if let Some(existing) = CONNECTION_SEQUENCE.get_ptr_mut(&connection_ptr) {
        unsafe {
            *existing = (*existing).saturating_add(1);
            return Ok(*existing);
        }
    }
    let initial = 1_u64;
    let _ = CONNECTION_SEQUENCE.insert(&connection_ptr, &initial, 0);
    Ok(initial)
}

fn emit_with_payload(
    kind: ProbeKind,
    direction: ProbeDirection,
    identity: ConnectionIdentity,
    file_offset: u64,
    data_offset: u64,
    aux_value: u32,
    aux_value2: u64,
    payload: &[u8],
) -> Result<(), c_long> {
    emit_record(
        kind,
        direction,
        identity,
        file_offset,
        data_offset,
        aux_value,
        aux_value2,
        payload,
    )
}

fn emit_record(
    kind: ProbeKind,
    direction: ProbeDirection,
    identity: ConnectionIdentity,
    file_offset: u64,
    data_offset: u64,
    aux_value: u32,
    aux_value2: u64,
    payload: &[u8],
) -> Result<(), c_long> {
    let Some(record_ptr) = SCRATCH_RECORDS.get_ptr_mut(0) else {
        return Err(0);
    };
    let record = unsafe { &mut *record_ptr };
    record.header = CaptureRecordHeader {
        abi_version: ABI_VERSION,
        header_len: size_of::<CaptureRecordHeader>() as u16,
        kind,
        direction,
        cpu: 0,
        pad0: 0,
        connection: identity,
        file_offset,
        data_offset,
        data_length: min(payload.len(), MAX_CAPTURE_BYTES) as u32,
        aux_value,
        aux_value2,
    };
    let len = min(payload.len(), MAX_CAPTURE_BYTES);
    let mut index = 0;
    while index < len {
        record.payload[index] = payload[index];
        index += 1;
    }
    EVENTS.output(&record, 0)
}

fn emit_record_from_user_ptr(
    kind: ProbeKind,
    direction: ProbeDirection,
    identity: ConnectionIdentity,
    file_offset: u64,
    data_offset: u64,
    aux_value: u32,
    aux_value2: u64,
    payload_ptr: *const u8,
    payload_len: usize,
) -> Result<(), c_long> {
    let Some(record_ptr) = SCRATCH_RECORDS.get_ptr_mut(0) else {
        return Err(0);
    };
    let record = unsafe { &mut *record_ptr };
    record.header = CaptureRecordHeader {
        abi_version: ABI_VERSION,
        header_len: size_of::<CaptureRecordHeader>() as u16,
        kind,
        direction,
        cpu: 0,
        pad0: 0,
        connection: identity,
        file_offset,
        data_offset,
        data_length: min(payload_len, MAX_CAPTURE_BYTES) as u32,
        aux_value,
        aux_value2,
    };
    let len = min(payload_len, MAX_CAPTURE_BYTES);
    if len != 0 {
        unsafe {
            let _ = bpf_probe_read_user_buf(payload_ptr, &mut record.payload[..len]);
        }
    }
    EVENTS.output(&record, 0)
}

#[cfg(target_arch = "bpf")]
fn reg_rdx(ctx: RetProbeContext) -> u64 {
    unsafe { (*ctx.regs).rdx }
}

#[cfg(not(target_arch = "bpf"))]
fn reg_rdx(_ctx: RetProbeContext) -> u64 {
    0
}
