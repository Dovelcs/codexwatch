use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use aya::Ebpf;
use aya::maps::{Array, MapData, RingBuf};
use aya::programs::{KProbe, TracePoint, UProbe};
use codexwatch_profile::{AttachKind, AttachPlan, KernelHook};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::profile::{AttachmentDecision, BuildFingerprint, LoadedProfile, ProfileRegistry};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootIdentity {
    pub boot_id: [u8; 16],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedCaptureRecord {
    pub header: crate::abi::CaptureRecordHeader,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoaderEvent {
    Capture(OwnedCaptureRecord),
    UnsupportedBuild(BuildFingerprint),
}

pub struct RunningCapture {
    pub bpf: Ebpf,
    pub attached_profile: Option<LoadedProfile>,
    pub object_path: PathBuf,
    ring: RingBuf<MapData>,
    pending_event: Option<LoaderEvent>,
}

#[derive(Debug, Error)]
pub enum LoaderError {
    #[error("unsupported_codex_build")]
    UnsupportedCodexBuild,
    #[error("missing eBPF map {0}")]
    MissingMap(&'static str),
    #[error("unsupported attach kind for site {program}")]
    UnsupportedAttachKind { program: String },
}

pub struct CaptureLoader {
    registry: ProfileRegistry,
}

impl Default for CaptureLoader {
    fn default() -> Self {
        Self::new()
    }
}

impl CaptureLoader {
    #[must_use]
    pub fn new() -> Self {
        Self {
            registry: ProfileRegistry::with_builtin_profiles(),
        }
    }

    pub fn fingerprint(binary_path: &Path) -> Result<BuildFingerprint> {
        let bytes = fs::read(binary_path)
            .with_context(|| format!("read native codex binary {}", binary_path.display()))?;
        Ok(BuildFingerprint {
            executable_sha256: hex::encode(Sha256::digest(&bytes)),
            architecture: std::env::consts::ARCH.to_owned(),
            codex_version_hint: None,
        })
    }

    pub fn resolve(&self, fingerprint: &BuildFingerprint) -> AttachmentDecision {
        self.registry.resolve(fingerprint)
    }

    pub fn load(
        &self,
        object_path: impl AsRef<Path>,
        codex_binary: impl AsRef<Path>,
    ) -> Result<RunningCapture> {
        let object_path = object_path.as_ref().to_path_buf();
        let codex_binary = codex_binary.as_ref().to_path_buf();
        let fingerprint = Self::fingerprint(&codex_binary)?;
        let decision = self.resolve(&fingerprint);

        let mut bpf = Ebpf::load_file(&object_path)
            .with_context(|| format!("load ebpf object {}", object_path.display()))?;
        self.seed_boot_id(&mut bpf)?;
        let ring_map = bpf
            .take_map("EVENTS")
            .ok_or(LoaderError::MissingMap("EVENTS"))?;
        let ring = RingBuf::try_from(ring_map).context("EVENTS ring buffer map")?;

        let mut attached_profile = None;
        let mut pending_event = None;
        match decision {
            AttachmentDecision::UnsupportedBuild(fingerprint) => {
                self.attach_kernel_hooks(&mut bpf, &[])?;
                pending_event = Some(LoaderEvent::UnsupportedBuild(fingerprint));
            }
            AttachmentDecision::Attach(profile) => {
                self.attach_kernel_hooks(&mut bpf, &profile.profile.kernel_hooks)?;
                if profile.verified {
                    let elf_bytes = fs::read(&codex_binary)?;
                    let plan =
                        codexwatch_profile::resolve_attach_plan(&profile.profile, &elf_bytes)
                            .map_err(|_| LoaderError::UnsupportedCodexBuild)?;
                    self.attach_uprobes(&mut bpf, &codex_binary, &plan)?;
                } else {
                    pending_event = Some(LoaderEvent::UnsupportedBuild(fingerprint));
                }
                attached_profile = Some(profile);
            }
        }

        Ok(RunningCapture {
            bpf,
            attached_profile,
            object_path,
            ring,
            pending_event,
        })
    }

    fn seed_boot_id(&self, bpf: &mut Ebpf) -> Result<()> {
        let boot_id_map = bpf
            .take_map("BOOT_ID")
            .ok_or(LoaderError::MissingMap("BOOT_ID"))?;
        let mut boot_id =
            Array::<_, [u8; 16]>::try_from(boot_id_map).context("BOOT_ID array map")?;
        boot_id
            .set(0, parse_boot_id()?, 0)
            .context("write boot id map")?;
        Ok(())
    }

    fn attach_kernel_hooks(&self, bpf: &mut Ebpf, hooks: &[KernelHook]) -> Result<()> {
        if hooks.is_empty() {
            for (program, category, name) in [
                ("process_exec", "sched", "sched_process_exec"),
                ("process_exit", "sched", "sched_process_exit"),
            ] {
                let tracepoint: &mut TracePoint =
                    bpf.program_mut(program).context(program)?.try_into()?;
                tracepoint.load()?;
                tracepoint.attach(category, name)?;
            }

            let tcp_state: &mut KProbe = bpf
                .program_mut("tcp_state")
                .context("tcp_state")?
                .try_into()?;
            tcp_state.load()?;
            tcp_state.attach("tcp_set_state", 0)?;
            return Ok(());
        }

        for hook in hooks {
            match hook.attach_kind {
                AttachKind::Tracepoint => {
                    let tracepoint: &mut TracePoint = bpf
                        .program_mut(&hook.program)
                        .with_context(|| hook.program.clone())?
                        .try_into()?;
                    tracepoint.load()?;
                    let category = hook.target.as_str();
                    let name = hook
                        .target_detail
                        .as_deref()
                        .context("tracepoint target_detail missing")?;
                    tracepoint.attach(category, name)?;
                }
                AttachKind::Kprobe => {
                    let program: &mut KProbe = bpf
                        .program_mut(&hook.program)
                        .with_context(|| hook.program.clone())?
                        .try_into()?;
                    program.load()?;
                    program.attach(&hook.target, 0)?;
                }
                _ => {
                    return Err(LoaderError::UnsupportedAttachKind {
                        program: hook.program.clone(),
                    }
                    .into());
                }
            }
        }

        Ok(())
    }

    fn attach_uprobes(&self, bpf: &mut Ebpf, binary: &Path, plan: &AttachPlan) -> Result<()> {
        for (_, probe) in &plan.probes {
            let program: &mut UProbe = bpf
                .program_mut(&probe.program)
                .with_context(|| probe.program.clone())?
                .try_into()?;
            program.load()?;
            program.attach(None, probe.file_offset, binary, None)?;
        }
        Ok(())
    }
}

impl RunningCapture {
    pub fn next_event(&mut self) -> Result<Option<LoaderEvent>> {
        if let Some(event) = self.pending_event.take() {
            return Ok(Some(event));
        }

        let Some(item) = self.ring.next() else {
            return Ok(None);
        };
        let bytes = &*item;
        let Some(record) = decode_capture_record(bytes) else {
            return Ok(None);
        };
        Ok(Some(LoaderEvent::Capture(OwnedCaptureRecord {
            header: record.header,
            payload: record.payload,
        })))
    }
}

fn decode_capture_record(bytes: &[u8]) -> Option<OwnedCaptureRecord> {
    let header_len = core::mem::size_of::<crate::abi::CaptureRecordHeader>();
    if bytes.len() < header_len {
        return None;
    }

    let mut offset = 0usize;
    let abi_version = read_u16(bytes, &mut offset)?;
    let header_size = read_u16(bytes, &mut offset)?;
    let kind = decode_probe_kind(read_u8(bytes, &mut offset)?)?;
    let direction = decode_probe_direction(read_u8(bytes, &mut offset)?)?;
    let cpu = read_u16(bytes, &mut offset)?;
    let pad0 = read_u16(bytes, &mut offset)?;
    let mut boot_id = [0u8; 16];
    boot_id.copy_from_slice(read_bytes(bytes, &mut offset, 16)?);
    let tgid = read_u32(bytes, &mut offset)?;
    let pid = read_u32(bytes, &mut offset)?;
    let start_ticks = read_u64(bytes, &mut offset)?;
    let connection_ptr = read_u64(bytes, &mut offset)?;
    let epoch = read_u64(bytes, &mut offset)?;
    let call_sequence = read_u64(bytes, &mut offset)?;
    let file_offset = read_u64(bytes, &mut offset)?;
    let data_offset = read_u64(bytes, &mut offset)?;
    let data_length = read_u32(bytes, &mut offset)?;
    let aux_value = read_u32(bytes, &mut offset)?;
    let aux_value2 = read_u64(bytes, &mut offset)?;
    let payload_len = usize::try_from(data_length)
        .ok()?
        .min(crate::abi::MAX_CAPTURE_BYTES);
    let payload_bytes = read_bytes(bytes, &mut offset, crate::abi::MAX_CAPTURE_BYTES)?;

    Some(OwnedCaptureRecord {
        header: crate::abi::CaptureRecordHeader {
            abi_version,
            header_len: header_size,
            kind,
            direction,
            cpu,
            pad0,
            connection: crate::abi::ConnectionIdentity {
                boot_id,
                tgid,
                pid,
                start_ticks,
                connection_ptr,
                epoch,
                call_sequence,
            },
            file_offset,
            data_offset,
            data_length,
            aux_value,
            aux_value2,
        },
        payload: payload_bytes[..payload_len].to_vec(),
    })
}

fn read_bytes<'a>(bytes: &'a [u8], offset: &mut usize, len: usize) -> Option<&'a [u8]> {
    let end = offset.checked_add(len)?;
    let slice = bytes.get(*offset..end)?;
    *offset = end;
    Some(slice)
}

fn read_u8(bytes: &[u8], offset: &mut usize) -> Option<u8> {
    Some(*read_bytes(bytes, offset, 1)?.first()?)
}

fn read_u16(bytes: &[u8], offset: &mut usize) -> Option<u16> {
    Some(u16::from_ne_bytes(
        read_bytes(bytes, offset, 2)?.try_into().ok()?,
    ))
}

fn read_u32(bytes: &[u8], offset: &mut usize) -> Option<u32> {
    Some(u32::from_ne_bytes(
        read_bytes(bytes, offset, 4)?.try_into().ok()?,
    ))
}

fn read_u64(bytes: &[u8], offset: &mut usize) -> Option<u64> {
    Some(u64::from_ne_bytes(
        read_bytes(bytes, offset, 8)?.try_into().ok()?,
    ))
}

fn decode_probe_kind(value: u8) -> Option<crate::abi::ProbeKind> {
    Some(match value {
        0 => crate::abi::ProbeKind::ProcessExec,
        1 => crate::abi::ProbeKind::ProcessExit,
        2 => crate::abi::ProbeKind::TcpStateChange,
        3 => crate::abi::ProbeKind::ConnectionCreate,
        4 => crate::abi::ProbeKind::ConnectionDrop,
        5 => crate::abi::ProbeKind::PlaintextWrite,
        6 => crate::abi::ProbeKind::PlaintextRead,
        7 => crate::abi::ProbeKind::TurnComplete,
        8 => crate::abi::ProbeKind::TurnAbort,
        9 => crate::abi::ProbeKind::TerminalError,
        _ => return None,
    })
}

fn decode_probe_direction(value: u8) -> Option<crate::abi::ProbeDirection> {
    Some(match value {
        0 => crate::abi::ProbeDirection::None,
        1 => crate::abi::ProbeDirection::Read,
        2 => crate::abi::ProbeDirection::Write,
        _ => return None,
    })
}

fn parse_boot_id() -> Result<[u8; 16]> {
    let text = fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .context("read /proc/sys/kernel/random/boot_id")?;
    let compact: String = text.trim().chars().filter(|value| *value != '-').collect();
    let bytes = hex::decode(compact).context("decode boot id")?;
    let mut boot_id = [0_u8; 16];
    boot_id.copy_from_slice(&bytes[..16]);
    Ok(boot_id)
}
