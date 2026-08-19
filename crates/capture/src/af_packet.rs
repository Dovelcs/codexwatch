use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Read};
use std::path::Path;

use afpacket::sync::RawPacketStream;
use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use thiserror::Error;

const SYS_CLASS_NET: &str = "/sys/class/net";
const PROC_ROOT: &str = "/proc";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpSegment {
    pub source_ip: String,
    pub source_port: u16,
    pub destination_ip: String,
    pub destination_port: u16,
    pub sequence: u32,
    pub ack: u32,
    pub syn: bool,
    pub fin: bool,
    pub rst: bool,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessSocketFlow {
    pub pid: u32,
    pub fd: i32,
    pub inode: u64,
    pub local_ip: String,
    pub local_port: u16,
    pub remote_ip: String,
    pub remote_port: u16,
    pub ipv6: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessFlowDirection {
    LocalToRemote,
    RemoteToLocal,
}

pub type SocketInodeMap = BTreeMap<i32, u64>;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProcessFlowIndex {
    pid: u32,
    flows: Vec<ProcessSocketFlow>,
}

#[derive(Debug)]
pub struct PassiveTap {
    interface_index: i32,
    interface_name: String,
    stream: RawPacketStream,
}

#[derive(Debug, Error)]
pub enum PacketDecodeError {
    #[error("frame parse failed: {0}")]
    Parse(String),
}

#[derive(Debug, Error)]
pub enum ProcLookupError {
    #[error("I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("interface index {0} was not found")]
    MissingInterface(i32),
    #[error("invalid /proc table line: {0}")]
    InvalidProcLine(String),
}

#[derive(Debug, Error)]
pub enum TapError {
    #[error("I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error(transparent)]
    Proc(#[from] ProcLookupError),
    #[error(transparent)]
    Decode(#[from] PacketDecodeError),
}

impl PassiveTap {
    pub fn open(interface_index: i32) -> Result<Self, TapError> {
        Self::open_with_sysfs(interface_index, Path::new(SYS_CLASS_NET))
    }

    fn open_with_sysfs(interface_index: i32, sys_class_net: &Path) -> Result<Self, TapError> {
        let interface_name = interface_name_from_index(interface_index, sys_class_net)?;
        let mut stream = RawPacketStream::new()?;
        stream.bind(&interface_name)?;
        stream.set_non_blocking()?;
        Ok(Self {
            interface_index,
            interface_name,
            stream,
        })
    }

    #[must_use]
    pub fn interface_index(&self) -> i32 {
        self.interface_index
    }

    #[must_use]
    pub fn interface_name(&self) -> &str {
        &self.interface_name
    }

    pub fn recv(&self, buffer: &mut [u8]) -> Result<Option<TcpSegment>, TapError> {
        let mut stream = &self.stream;
        let bytes = match stream.read(buffer) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(None),
            Err(error) => return Err(TapError::Io(error)),
        };
        decode_segment(&buffer[..bytes]).map_err(TapError::Decode)
    }
}

impl ProcessFlowIndex {
    pub fn from_pid(pid: u32) -> Result<Self, ProcLookupError> {
        Self::from_proc_root(Path::new(PROC_ROOT), pid)
    }

    pub fn from_proc_root(proc_root: &Path, pid: u32) -> Result<Self, ProcLookupError> {
        let inode_map = socket_inodes_for_pid(proc_root, pid)?;
        let tcp_entries = load_tcp_entries(proc_root)?;
        let inode_set = inode_map.values().copied().collect::<BTreeSet<_>>();
        let flows = inode_map
            .into_iter()
            .filter_map(|(fd, inode)| {
                tcp_entries.get(&inode).map(|entry| ProcessSocketFlow {
                    pid,
                    fd,
                    inode,
                    local_ip: entry.local_ip.clone(),
                    local_port: entry.local_port,
                    remote_ip: entry.remote_ip.clone(),
                    remote_port: entry.remote_port,
                    ipv6: entry.ipv6,
                })
            })
            .collect::<Vec<_>>();
        let _ = inode_set;
        Ok(Self { pid, flows })
    }

    #[must_use]
    pub fn pid(&self) -> u32 {
        self.pid
    }

    #[must_use]
    pub fn flows(&self) -> &[ProcessSocketFlow] {
        &self.flows
    }

    #[must_use]
    pub fn matches_segment(&self, segment: &TcpSegment) -> bool {
        self.direction_for_segment(segment).is_some()
    }

    #[must_use]
    pub fn direction_for_segment(&self, segment: &TcpSegment) -> Option<ProcessFlowDirection> {
        self.flows.iter().find_map(|flow| {
            if flow.local_ip == segment.source_ip
                && flow.local_port == segment.source_port
                && flow.remote_ip == segment.destination_ip
                && flow.remote_port == segment.destination_port
            {
                Some(ProcessFlowDirection::LocalToRemote)
            } else if flow.local_ip == segment.destination_ip
                && flow.local_port == segment.destination_port
                && flow.remote_ip == segment.source_ip
                && flow.remote_port == segment.source_port
            {
                Some(ProcessFlowDirection::RemoteToLocal)
            } else {
                None
            }
        })
    }
}

pub fn socket_inodes_for_pid(
    proc_root: &Path,
    pid: u32,
) -> Result<SocketInodeMap, ProcLookupError> {
    let fd_dir = proc_root.join(pid.to_string()).join("fd");
    let mut sockets = BTreeMap::new();
    for entry in fs::read_dir(fd_dir)? {
        let entry = entry?;
        let fd_name = entry.file_name();
        let Ok(fd) = fd_name.to_string_lossy().parse::<i32>() else {
            continue;
        };
        let target = fs::read_link(entry.path())?;
        let Some(inode) = parse_socket_inode(&target) else {
            continue;
        };
        sockets.insert(fd, inode);
    }
    Ok(sockets)
}

pub fn decode_segment(frame: &[u8]) -> Result<Option<TcpSegment>, PacketDecodeError> {
    let packet = match SlicedPacket::from_ethernet(frame) {
        Ok(packet)
            if (packet.net.is_some() || packet.transport.is_some())
                || !matches!(frame.first().map(|byte| byte >> 4), Some(4 | 6)) =>
        {
            packet
        }
        Ok(_) => SlicedPacket::from_ip(frame)
            .map_err(|error| PacketDecodeError::Parse(error.to_string()))?,
        Err(ethernet_error) => {
            if let Some(4 | 6) = frame.first().map(|byte| byte >> 4) {
                SlicedPacket::from_ip(frame)
                    .map_err(|error| PacketDecodeError::Parse(error.to_string()))?
            } else {
                let _ = ethernet_error;
                return Ok(None);
            }
        }
    };
    let (source_ip, destination_ip) = match packet.net {
        Some(NetSlice::Ipv4(ref ip)) => (
            ip.header().source_addr().to_string(),
            ip.header().destination_addr().to_string(),
        ),
        Some(NetSlice::Ipv6(ref ip)) => (
            ip.header().source_addr().to_string(),
            ip.header().destination_addr().to_string(),
        ),
        _ => return Ok(None),
    };

    let Some(transport) = packet.transport.as_ref() else {
        return Ok(None);
    };
    match transport {
        TransportSlice::Tcp(tcp) => Ok(Some(TcpSegment {
            source_ip,
            source_port: tcp.source_port(),
            destination_ip,
            destination_port: tcp.destination_port(),
            sequence: tcp.sequence_number(),
            ack: tcp.acknowledgment_number(),
            syn: tcp.syn(),
            fin: tcp.fin(),
            rst: tcp.rst(),
            payload: tcp.payload().to_vec(),
        })),
        _ => Ok(None),
    }
}

fn interface_name_from_index(index: i32, sys_class_net: &Path) -> Result<String, ProcLookupError> {
    for entry in fs::read_dir(sys_class_net)? {
        let entry = entry?;
        let path = entry.path().join("ifindex");
        let Ok(contents) = fs::read_to_string(path) else {
            continue;
        };
        let Ok(candidate) = contents.trim().parse::<i32>() else {
            continue;
        };
        if candidate == index {
            return Ok(entry.file_name().to_string_lossy().into_owned());
        }
    }
    Err(ProcLookupError::MissingInterface(index))
}

fn parse_socket_inode(target: &Path) -> Option<u64> {
    let text = target.to_string_lossy();
    let value = text.strip_prefix("socket:[")?.strip_suffix(']')?;
    value.parse::<u64>().ok()
}

#[derive(Debug, Clone)]
struct TcpEntry {
    local_ip: String,
    local_port: u16,
    remote_ip: String,
    remote_port: u16,
    ipv6: bool,
}

fn load_tcp_entries(proc_root: &Path) -> Result<BTreeMap<u64, TcpEntry>, ProcLookupError> {
    let mut entries = BTreeMap::new();
    for (file_name, ipv6) in [("tcp", false), ("tcp6", true)] {
        let path = proc_root.join("net").join(file_name);
        let contents = fs::read_to_string(path)?;
        for line in contents
            .lines()
            .skip(1)
            .filter(|line| !line.trim().is_empty())
        {
            let (inode, entry) = parse_tcp_line(line, ipv6)?;
            entries.insert(inode, entry);
        }
    }
    Ok(entries)
}

fn parse_tcp_line(line: &str, ipv6: bool) -> Result<(u64, TcpEntry), ProcLookupError> {
    let parts = line.split_whitespace().collect::<Vec<_>>();
    if parts.len() <= 9 {
        return Err(ProcLookupError::InvalidProcLine(line.to_owned()));
    }
    let (local_ip, local_port) = parse_proc_socket_address(parts[1], ipv6)?;
    let (remote_ip, remote_port) = parse_proc_socket_address(parts[2], ipv6)?;
    let inode = parts[9]
        .parse::<u64>()
        .map_err(|_| ProcLookupError::InvalidProcLine(line.to_owned()))?;
    Ok((
        inode,
        TcpEntry {
            local_ip,
            local_port,
            remote_ip,
            remote_port,
            ipv6,
        },
    ))
}

fn parse_proc_socket_address(value: &str, ipv6: bool) -> Result<(String, u16), ProcLookupError> {
    let (address, port) = value
        .split_once(':')
        .ok_or_else(|| ProcLookupError::InvalidProcLine(value.to_owned()))?;
    let port = u16::from_str_radix(port, 16)
        .map_err(|_| ProcLookupError::InvalidProcLine(value.to_owned()))?;
    let address = if ipv6 {
        parse_ipv6_address(address)?
    } else {
        parse_ipv4_address(address)?
    };
    Ok((address, port))
}

fn parse_ipv4_address(value: &str) -> Result<String, ProcLookupError> {
    let raw = u32::from_str_radix(value, 16)
        .map_err(|_| ProcLookupError::InvalidProcLine(value.to_owned()))?;
    Ok(std::net::Ipv4Addr::from(raw.to_le_bytes()).to_string())
}

fn parse_ipv6_address(value: &str) -> Result<String, ProcLookupError> {
    if value.len() != 32 {
        return Err(ProcLookupError::InvalidProcLine(value.to_owned()));
    }
    let mut bytes = [0u8; 16];
    for (index, chunk) in value.as_bytes().chunks(8).enumerate() {
        let chunk = std::str::from_utf8(chunk)
            .map_err(|_| ProcLookupError::InvalidProcLine(value.to_owned()))?;
        let word = u32::from_str_radix(chunk, 16)
            .map_err(|_| ProcLookupError::InvalidProcLine(value.to_owned()))?;
        bytes[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    Ok(std::net::Ipv6Addr::from(bytes).to_string())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;

    use super::{
        PassiveTap, ProcessFlowIndex, decode_segment, interface_name_from_index,
        parse_proc_socket_address,
    };

    fn temp_root(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "codexwatch-capture-{name}-{}",
            uuid::Uuid::now_v7()
        ));
        fs::create_dir_all(&root).expect("temp root");
        root
    }

    #[test]
    fn decodes_basic_ipv4_frame() {
        let mut frame = vec![0u8; 14 + 20 + 20 + 5];
        frame[12] = 0x08;
        frame[13] = 0x00;
        frame[14] = 0x45;
        frame[16..18].copy_from_slice(&(45u16).to_be_bytes());
        frame[23] = 6;
        frame[26..30].copy_from_slice(&[10, 0, 0, 1]);
        frame[30..34].copy_from_slice(&[10, 0, 0, 2]);
        let tcp = 14 + 20;
        frame[tcp..tcp + 2].copy_from_slice(&1234u16.to_be_bytes());
        frame[tcp + 2..tcp + 4].copy_from_slice(&443u16.to_be_bytes());
        frame[tcp + 4..tcp + 8].copy_from_slice(&1u32.to_be_bytes());
        frame[tcp + 12] = 0x50;
        frame[tcp + 13] = 0x18;
        frame[tcp + 20..tcp + 25].copy_from_slice(b"hello");
        let packet = decode_segment(&frame).expect("decode").expect("tcp");
        assert_eq!(packet.source_ip, "10.0.0.1");
        assert_eq!(packet.destination_ip, "10.0.0.2");
        assert_eq!(packet.payload, b"hello");
    }

    #[test]
    fn decodes_raw_ipv4_packet() {
        let mut packet = vec![0u8; 20 + 20 + 5];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(45u16).to_be_bytes());
        packet[9] = 6;
        packet[12..16].copy_from_slice(&[10, 0, 0, 1]);
        packet[16..20].copy_from_slice(&[10, 0, 0, 2]);
        let tcp = 20;
        packet[tcp..tcp + 2].copy_from_slice(&1234u16.to_be_bytes());
        packet[tcp + 2..tcp + 4].copy_from_slice(&443u16.to_be_bytes());
        packet[tcp + 4..tcp + 8].copy_from_slice(&1u32.to_be_bytes());
        packet[tcp + 12] = 0x50;
        packet[tcp + 13] = 0x18;
        packet[tcp + 20..tcp + 25].copy_from_slice(b"hello");
        let segment = decode_segment(&packet).expect("decode").expect("tcp");
        assert_eq!(segment.source_ip, "10.0.0.1");
        assert_eq!(segment.destination_ip, "10.0.0.2");
        assert_eq!(segment.payload, b"hello");
    }

    #[test]
    fn decodes_raw_ipv6_packet() {
        let mut packet = vec![0u8; 40 + 20 + 5];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&(25u16).to_be_bytes());
        packet[6] = 6;
        packet[7] = 64;
        packet[23] = 1;
        packet[39] = 1;
        let tcp = 40;
        packet[tcp..tcp + 2].copy_from_slice(&1234u16.to_be_bytes());
        packet[tcp + 2..tcp + 4].copy_from_slice(&443u16.to_be_bytes());
        packet[tcp + 4..tcp + 8].copy_from_slice(&1u32.to_be_bytes());
        packet[tcp + 12] = 0x50;
        packet[tcp + 13] = 0x18;
        packet[tcp + 20..tcp + 25].copy_from_slice(b"hello");
        let segment = decode_segment(&packet).expect("decode").expect("tcp");
        assert_eq!(segment.source_ip, "::1");
        assert_eq!(segment.destination_ip, "::1");
        assert_eq!(segment.payload, b"hello");
    }

    #[test]
    fn returns_none_for_non_ip_non_ethernet_payload() {
        assert!(
            decode_segment(&[0x01, 0x02, 0x03, 0x04])
                .expect("decode")
                .is_none()
        );
    }

    #[test]
    fn resolves_interface_name_from_sysfs() {
        let root = temp_root("sysfs");
        let net = root.join("net");
        fs::create_dir_all(net.join("eth0")).expect("eth0");
        fs::write(net.join("eth0").join("ifindex"), "7\n").expect("ifindex");
        let name = interface_name_from_index(7, &net).expect("interface");
        assert_eq!(name, "eth0");
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn builds_process_flow_index_from_proc() {
        let root = temp_root("proc");
        let proc_root = root.join("proc");
        fs::create_dir_all(proc_root.join("123").join("fd")).expect("fd");
        fs::create_dir_all(proc_root.join("net")).expect("net");
        symlink("socket:[456]", proc_root.join("123").join("fd").join("5")).expect("symlink");
        fs::write(
            proc_root.join("net").join("tcp"),
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0100007F:1F90 0200000A:01BB 01 00000000:00000000 00:00000000 00000000 1000        0 456 1 0000000000000000 20 4 30 10 -1\n",
        )
        .expect("tcp");
        fs::write(
            proc_root.join("net").join("tcp6"),
            "  sl  local_address                         rem_address                          st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n",
        )
        .expect("tcp6");

        let index = ProcessFlowIndex::from_proc_root(&proc_root, 123).expect("index");
        assert_eq!(index.flows().len(), 1);
        let flow = &index.flows()[0];
        assert_eq!(flow.fd, 5);
        assert_eq!(flow.local_ip, "127.0.0.1");
        assert_eq!(flow.remote_ip, "10.0.0.2");
        let response = super::TcpSegment {
            source_ip: "10.0.0.2".to_owned(),
            source_port: 443,
            destination_ip: "127.0.0.1".to_owned(),
            destination_port: 8080,
            sequence: 1,
            ack: 0,
            syn: false,
            fin: false,
            rst: false,
            payload: Vec::new(),
        };
        assert!(index.matches_segment(&response));
        assert_eq!(
            index.direction_for_segment(&response),
            Some(super::ProcessFlowDirection::RemoteToLocal)
        );
        let request = super::TcpSegment {
            source_ip: "127.0.0.1".to_owned(),
            source_port: 8080,
            destination_ip: "10.0.0.2".to_owned(),
            destination_port: 443,
            ..response
        };
        assert_eq!(
            index.direction_for_segment(&request),
            Some(super::ProcessFlowDirection::LocalToRemote)
        );
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn parses_ipv6_proc_address() {
        let (ip, port) =
            parse_proc_socket_address("00000000000000000000000001000000:1F90", true).expect("ipv6");
        assert_eq!(ip, "::1");
        assert_eq!(port, 8080);
    }

    #[test]
    fn open_uses_interface_name_resolution() {
        let root = temp_root("open");
        let net = root.join("net");
        fs::create_dir_all(net.join("lo")).expect("lo");
        fs::write(net.join("lo").join("ifindex"), "1\n").expect("ifindex");
        let result = PassiveTap::open_with_sysfs(99, &net);
        assert!(result.is_err());
        fs::remove_dir_all(root).ok();
    }
}
