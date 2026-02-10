use std::fmt;

/// EventType identifies the kind of eBPF event.
/// Values must match `bpf/include/observoor.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum EventType {
    SyscallRead = 1,
    SyscallWrite = 2,
    SyscallFutex = 3,
    SyscallMmap = 4,
    SyscallEpollWait = 5,
    DiskIO = 6,
    NetTX = 7,
    NetRX = 8,
    SchedSwitch = 9,
    PageFault = 10,
    FDOpen = 11,
    FDClose = 12,
    SyscallFsync = 13,
    SyscallFdatasync = 14,
    SyscallPwrite = 15,
    SchedRunqueue = 16,
    BlockMerge = 17,
    TcpRetransmit = 18,
    TcpState = 19,
    MemReclaim = 20,
    MemCompaction = 21,
    SwapIn = 22,
    SwapOut = 23,
    OOMKill = 24,
    ProcessExit = 25,
}

/// Maximum EventType value, used for array sizing.
pub const MAX_EVENT_TYPE: usize = 25;

impl EventType {
    /// Returns the canonical metric/log label name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SyscallRead => "syscall_read",
            Self::SyscallWrite => "syscall_write",
            Self::SyscallFutex => "syscall_futex",
            Self::SyscallMmap => "syscall_mmap",
            Self::SyscallEpollWait => "syscall_epoll_wait",
            Self::DiskIO => "disk_io",
            Self::NetTX => "net_tx",
            Self::NetRX => "net_rx",
            Self::SchedSwitch => "sched_switch",
            Self::PageFault => "page_fault",
            Self::FDOpen => "fd_open",
            Self::FDClose => "fd_close",
            Self::SyscallFsync => "syscall_fsync",
            Self::SyscallFdatasync => "syscall_fdatasync",
            Self::SyscallPwrite => "syscall_pwrite",
            Self::SchedRunqueue => "sched_runqueue",
            Self::BlockMerge => "block_merge",
            Self::TcpRetransmit => "tcp_retransmit",
            Self::TcpState => "tcp_state",
            Self::MemReclaim => "mem_reclaim",
            Self::MemCompaction => "mem_compaction",
            Self::SwapIn => "swap_in",
            Self::SwapOut => "swap_out",
            Self::OOMKill => "oom_kill",
            Self::ProcessExit => "process_exit",
        }
    }

    /// Convert from a raw u8 value.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::SyscallRead),
            2 => Some(Self::SyscallWrite),
            3 => Some(Self::SyscallFutex),
            4 => Some(Self::SyscallMmap),
            5 => Some(Self::SyscallEpollWait),
            6 => Some(Self::DiskIO),
            7 => Some(Self::NetTX),
            8 => Some(Self::NetRX),
            9 => Some(Self::SchedSwitch),
            10 => Some(Self::PageFault),
            11 => Some(Self::FDOpen),
            12 => Some(Self::FDClose),
            13 => Some(Self::SyscallFsync),
            14 => Some(Self::SyscallFdatasync),
            15 => Some(Self::SyscallPwrite),
            16 => Some(Self::SchedRunqueue),
            17 => Some(Self::BlockMerge),
            18 => Some(Self::TcpRetransmit),
            19 => Some(Self::TcpState),
            20 => Some(Self::MemReclaim),
            21 => Some(Self::MemCompaction),
            22 => Some(Self::SwapIn),
            23 => Some(Self::SwapOut),
            24 => Some(Self::OOMKill),
            25 => Some(Self::ProcessExit),
            _ => None,
        }
    }

    /// Convert from the canonical metric/log label name.
    pub fn from_str(name: &str) -> Option<Self> {
        match name {
            "syscall_read" => Some(Self::SyscallRead),
            "syscall_write" => Some(Self::SyscallWrite),
            "syscall_futex" => Some(Self::SyscallFutex),
            "syscall_mmap" => Some(Self::SyscallMmap),
            "syscall_epoll_wait" => Some(Self::SyscallEpollWait),
            "disk_io" => Some(Self::DiskIO),
            "net_tx" => Some(Self::NetTX),
            "net_rx" => Some(Self::NetRX),
            "sched_switch" => Some(Self::SchedSwitch),
            "page_fault" => Some(Self::PageFault),
            "fd_open" => Some(Self::FDOpen),
            "fd_close" => Some(Self::FDClose),
            "syscall_fsync" => Some(Self::SyscallFsync),
            "syscall_fdatasync" => Some(Self::SyscallFdatasync),
            "syscall_pwrite" => Some(Self::SyscallPwrite),
            "sched_runqueue" => Some(Self::SchedRunqueue),
            "block_merge" => Some(Self::BlockMerge),
            "tcp_retransmit" => Some(Self::TcpRetransmit),
            "tcp_state" => Some(Self::TcpState),
            "mem_reclaim" => Some(Self::MemReclaim),
            "mem_compaction" => Some(Self::MemCompaction),
            "swap_in" => Some(Self::SwapIn),
            "swap_out" => Some(Self::SwapOut),
            "oom_kill" => Some(Self::OOMKill),
            "process_exit" => Some(Self::ProcessExit),
            _ => None,
        }
    }

    /// Return all event types in numeric order.
    pub fn all() -> &'static [Self] {
        &[
            Self::SyscallRead,
            Self::SyscallWrite,
            Self::SyscallFutex,
            Self::SyscallMmap,
            Self::SyscallEpollWait,
            Self::DiskIO,
            Self::NetTX,
            Self::NetRX,
            Self::SchedSwitch,
            Self::PageFault,
            Self::FDOpen,
            Self::FDClose,
            Self::SyscallFsync,
            Self::SyscallFdatasync,
            Self::SyscallPwrite,
            Self::SchedRunqueue,
            Self::BlockMerge,
            Self::TcpRetransmit,
            Self::TcpState,
            Self::MemReclaim,
            Self::MemCompaction,
            Self::SwapIn,
            Self::SwapOut,
            Self::OOMKill,
            Self::ProcessExit,
        ]
    }
}

impl fmt::Display for EventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// ClientType identifies the Ethereum client producing the event.
/// Values must match `bpf/include/observoor.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ClientType {
    Unknown = 0,
    Geth = 1,
    Reth = 2,
    Besu = 3,
    Nethermind = 4,
    Erigon = 5,
    Prysm = 6,
    Lighthouse = 7,
    Teku = 8,
    Lodestar = 9,
    Nimbus = 10,
    Ethrex = 11,
}

/// Maximum ClientType value, used for array sizing.
#[allow(dead_code)]
pub const MAX_CLIENT_TYPE: usize = 11;
/// Number of ClientType variants including Unknown.
pub const CLIENT_TYPE_CARDINALITY: usize = MAX_CLIENT_TYPE + 1;

impl ClientType {
    /// Returns the canonical metric/log label name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Geth => "geth",
            Self::Reth => "reth",
            Self::Besu => "besu",
            Self::Nethermind => "nethermind",
            Self::Erigon => "erigon",
            Self::Prysm => "prysm",
            Self::Lighthouse => "lighthouse",
            Self::Teku => "teku",
            Self::Lodestar => "lodestar",
            Self::Nimbus => "nimbus",
            Self::Ethrex => "ethrex",
        }
    }

    /// Convert from a raw u8 value.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Unknown),
            1 => Some(Self::Geth),
            2 => Some(Self::Reth),
            3 => Some(Self::Besu),
            4 => Some(Self::Nethermind),
            5 => Some(Self::Erigon),
            6 => Some(Self::Prysm),
            7 => Some(Self::Lighthouse),
            8 => Some(Self::Teku),
            9 => Some(Self::Lodestar),
            10 => Some(Self::Nimbus),
            11 => Some(Self::Ethrex),
            _ => None,
        }
    }

    /// Return all known client types (excluding Unknown).
    pub fn all() -> &'static [ClientType] {
        &[
            Self::Geth,
            Self::Reth,
            Self::Besu,
            Self::Nethermind,
            Self::Erigon,
            Self::Prysm,
            Self::Lighthouse,
            Self::Teku,
            Self::Lodestar,
            Self::Nimbus,
            Self::Ethrex,
        ]
    }

    /// Return all client types including Unknown.
    pub fn all_with_unknown() -> &'static [ClientType] {
        &[
            Self::Unknown,
            Self::Geth,
            Self::Reth,
            Self::Besu,
            Self::Nethermind,
            Self::Erigon,
            Self::Prysm,
            Self::Lighthouse,
            Self::Teku,
            Self::Lodestar,
            Self::Nimbus,
            Self::Ethrex,
        ]
    }

    /// Return all client type names including "unknown".
    pub fn all_names() -> Vec<String> {
        Self::all_with_unknown()
            .iter()
            .map(|c| c.to_string())
            .collect()
    }
}

impl fmt::Display for ClientType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Network I/O direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Direction {
    TX = 0,
    RX = 1,
}

impl Direction {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::TX),
            1 => Some(Self::RX),
            _ => None,
        }
    }
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TX => f.write_str("tx"),
            Self::RX => f.write_str("rx"),
        }
    }
}

/// Common event header (24 bytes in BPF, matches event_header in observoor.h).
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct Event {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub tid: u32,
    pub event_type: EventType,
    pub client_type: ClientType,
}

/// Syscall event with latency measurement.
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct SyscallEvent {
    pub event: Event,
    pub latency_ns: u64,
    pub ret: i64,
    pub syscall_nr: u32,
    pub fd: i32,
}

/// Block I/O operation event.
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct DiskIOEvent {
    pub event: Event,
    pub latency_ns: u64,
    pub bytes: u32,
    /// 0 = read, 1 = write.
    pub rw: u8,
    pub queue_depth: u32,
    /// Block device ID (major:minor encoded).
    pub device_id: u32,
}

/// Network send/receive event.
/// When `has_metrics` is true, `srtt_us` and `cwnd` contain inline TCP metrics.
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct NetIOEvent {
    pub event: Event,
    pub bytes: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub direction: Direction,
    pub has_metrics: bool,
    pub srtt_us: u32,
    pub cwnd: u32,
}

/// Context switch event.
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct SchedEvent {
    pub event: Event,
    pub on_cpu_ns: u64,
    pub voluntary: bool,
    pub cpu_id: u32,
}

/// Runqueue/off-CPU latency event.
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct SchedRunqueueEvent {
    pub event: Event,
    pub runqueue_ns: u64,
    pub off_cpu_ns: u64,
}

/// Page fault event.
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct PageFaultEvent {
    pub event: Event,
    pub address: u64,
    pub major: bool,
}

/// File descriptor open/close event.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct FDEvent {
    pub event: Event,
    pub fd: i32,
    pub filename: String,
}

/// Merged block I/O request event.
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct BlockMergeEvent {
    pub event: Event,
    pub bytes: u32,
    /// 0 = read, 1 = write.
    pub rw: u8,
}

/// TCP retransmission event.
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct TcpRetransmitEvent {
    pub event: Event,
    pub bytes: u32,
    pub src_port: u16,
    pub dst_port: u16,
}

/// TCP state transition event.
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct TcpStateEvent {
    pub event: Event,
    pub src_port: u16,
    pub dst_port: u16,
    pub new_state: u8,
    pub old_state: u8,
}

/// Memory reclaim/compaction latency event.
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct MemLatencyEvent {
    pub event: Event,
    pub duration_ns: u64,
}

/// Swap-in/out event.
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct SwapEvent {
    pub event: Event,
    pub pages: u64,
}

/// OOM kill event.
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct OOMKillEvent {
    pub event: Event,
    pub target_pid: u32,
}

/// Process exit event.
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct ProcessExitEvent {
    pub event: Event,
    pub exit_code: u32,
}

/// A parsed event wrapping the common header and a typed payload.
#[derive(Debug, Clone)]
pub struct ParsedEvent {
    /// Common event header.
    pub raw: Event,
    /// Typed event payload.
    pub typed: TypedEvent,
}

/// Typed event payload variants.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum TypedEvent {
    Syscall(SyscallEvent),
    DiskIO(DiskIOEvent),
    NetIO(NetIOEvent),
    Sched(SchedEvent),
    SchedRunqueue(SchedRunqueueEvent),
    PageFault(PageFaultEvent),
    FD(FDEvent),
    BlockMerge(BlockMergeEvent),
    TcpRetransmit(TcpRetransmitEvent),
    TcpState(TcpStateEvent),
    MemLatency(MemLatencyEvent),
    Swap(SwapEvent),
    OOMKill(OOMKillEvent),
    ProcessExit(ProcessExitEvent),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_type_roundtrip() {
        for i in 1..=MAX_EVENT_TYPE as u8 {
            let et = EventType::from_u8(i).expect("valid event type");
            assert_eq!(et as u8, i);
        }
        assert!(EventType::from_u8(0).is_none());
        assert!(EventType::from_u8(26).is_none());
    }

    #[test]
    fn test_client_type_roundtrip() {
        for i in 0..=MAX_CLIENT_TYPE as u8 {
            let ct = ClientType::from_u8(i).expect("valid client type");
            assert_eq!(ct as u8, i);
        }
        assert!(ClientType::from_u8(12).is_none());
    }

    #[test]
    fn test_event_type_display() {
        assert_eq!(EventType::SyscallRead.to_string(), "syscall_read");
        assert_eq!(EventType::NetTX.to_string(), "net_tx");
        assert_eq!(EventType::ProcessExit.to_string(), "process_exit");
    }

    #[test]
    fn test_event_type_from_str() {
        assert_eq!(
            EventType::from_str("syscall_read"),
            Some(EventType::SyscallRead)
        );
        assert_eq!(EventType::from_str("net_rx"), Some(EventType::NetRX));
        assert_eq!(
            EventType::from_str("process_exit"),
            Some(EventType::ProcessExit)
        );
        assert_eq!(EventType::from_str("not_an_event"), None);
    }

    #[test]
    fn test_all_event_types() {
        let all = EventType::all();
        assert_eq!(all.len(), MAX_EVENT_TYPE);
        assert_eq!(all.first().copied(), Some(EventType::SyscallRead));
        assert_eq!(all.last().copied(), Some(EventType::ProcessExit));
    }

    #[test]
    fn test_client_type_display() {
        assert_eq!(ClientType::Geth.to_string(), "geth");
        assert_eq!(ClientType::Unknown.to_string(), "unknown");
        assert_eq!(ClientType::Ethrex.to_string(), "ethrex");
    }

    #[test]
    fn test_all_client_types() {
        let all = ClientType::all();
        assert_eq!(all.len(), 11);
        assert!(!all.contains(&ClientType::Unknown));
    }

    #[test]
    fn test_all_client_names_includes_unknown() {
        let names = ClientType::all_names();
        assert_eq!(names.len(), 12);
        assert!(names.contains(&"unknown".to_string()));
    }

    #[test]
    fn test_direction_display() {
        assert_eq!(Direction::TX.to_string(), "tx");
        assert_eq!(Direction::RX.to_string(), "rx");
    }
}
