package tracer

import "fmt"

// EventType identifies the kind of eBPF event.
type EventType uint8

const (
	EventTypeSyscallRead      EventType = 1
	EventTypeSyscallWrite     EventType = 2
	EventTypeSyscallFutex     EventType = 3
	EventTypeSyscallMmap      EventType = 4
	EventTypeSyscallEpollWait EventType = 5
	EventTypeDiskIO           EventType = 6
	EventTypeNetTX            EventType = 7
	EventTypeNetRX            EventType = 8
	EventTypeSchedSwitch      EventType = 9
	EventTypePageFault        EventType = 10
	EventTypeFDOpen           EventType = 11
	EventTypeFDClose          EventType = 12
	EventTypeSyscallFsync     EventType = 13
	EventTypeSyscallFdatasync EventType = 14
	EventTypeSyscallPwrite    EventType = 15
	EventTypeSchedRunqueue    EventType = 16
	EventTypeBlockMerge       EventType = 17
	EventTypeTcpRetransmit    EventType = 18
	EventTypeTcpState         EventType = 19
	EventTypeTcpMetrics       EventType = 20
	EventTypeMemReclaim       EventType = 21
	EventTypeMemCompaction    EventType = 22
	EventTypeSwapIn           EventType = 23
	EventTypeSwapOut          EventType = 24
	EventTypeOOMKill          EventType = 25
	EventTypeProcessExit      EventType = 26
)

// String returns the human-readable name of the event type.
func (e EventType) String() string {
	switch e {
	case EventTypeSyscallRead:
		return "syscall_read"
	case EventTypeSyscallWrite:
		return "syscall_write"
	case EventTypeSyscallFutex:
		return "syscall_futex"
	case EventTypeSyscallMmap:
		return "syscall_mmap"
	case EventTypeSyscallEpollWait:
		return "syscall_epoll_wait"
	case EventTypeDiskIO:
		return "disk_io"
	case EventTypeNetTX:
		return "net_tx"
	case EventTypeNetRX:
		return "net_rx"
	case EventTypeSchedSwitch:
		return "sched_switch"
	case EventTypePageFault:
		return "page_fault"
	case EventTypeFDOpen:
		return "fd_open"
	case EventTypeFDClose:
		return "fd_close"
	case EventTypeSyscallFsync:
		return "syscall_fsync"
	case EventTypeSyscallFdatasync:
		return "syscall_fdatasync"
	case EventTypeSyscallPwrite:
		return "syscall_pwrite"
	case EventTypeSchedRunqueue:
		return "sched_runqueue"
	case EventTypeBlockMerge:
		return "block_merge"
	case EventTypeTcpRetransmit:
		return "tcp_retransmit"
	case EventTypeTcpState:
		return "tcp_state"
	case EventTypeTcpMetrics:
		return "tcp_metrics"
	case EventTypeMemReclaim:
		return "mem_reclaim"
	case EventTypeMemCompaction:
		return "mem_compaction"
	case EventTypeSwapIn:
		return "swap_in"
	case EventTypeSwapOut:
		return "swap_out"
	case EventTypeOOMKill:
		return "oom_kill"
	case EventTypeProcessExit:
		return "process_exit"
	default:
		return fmt.Sprintf("unknown(%d)", e)
	}
}

// ClientType identifies the Ethereum client producing the event.
type ClientType uint8

const (
	ClientTypeUnknown    ClientType = 0
	ClientTypeGeth       ClientType = 1
	ClientTypeReth       ClientType = 2
	ClientTypeBesu       ClientType = 3
	ClientTypeNethermind ClientType = 4
	ClientTypeErigon     ClientType = 5
	ClientTypePrysm      ClientType = 6
	ClientTypeLighthouse ClientType = 7
	ClientTypeTeku       ClientType = 8
	ClientTypeLodestar   ClientType = 9
	ClientTypeNimbus     ClientType = 10
)

// String returns the human-readable name of the client type.
func (c ClientType) String() string {
	switch c {
	case ClientTypeGeth:
		return "geth"
	case ClientTypeReth:
		return "reth"
	case ClientTypeBesu:
		return "besu"
	case ClientTypeNethermind:
		return "nethermind"
	case ClientTypeErigon:
		return "erigon"
	case ClientTypePrysm:
		return "prysm"
	case ClientTypeLighthouse:
		return "lighthouse"
	case ClientTypeTeku:
		return "teku"
	case ClientTypeLodestar:
		return "lodestar"
	case ClientTypeNimbus:
		return "nimbus"
	default:
		return "unknown"
	}
}

// Direction indicates network I/O direction.
type Direction uint8

const (
	DirectionTX Direction = 0
	DirectionRX Direction = 1
)

// Event is the common header for all eBPF events.
type Event struct {
	TimestampNs uint64     `json:"timestamp_ns"`
	PID         uint32     `json:"pid"`
	TID         uint32     `json:"tid"`
	Type        EventType  `json:"event_type"`
	Client      ClientType `json:"client_type"`
}

// SyscallEvent represents a traced syscall with latency.
type SyscallEvent struct {
	Event
	LatencyNs uint64 `json:"latency_ns"`
	Return    int64  `json:"ret"`
	SyscallNr uint32 `json:"syscall_nr"`
	FD        int32  `json:"fd"`
}

// DiskIOEvent represents a block I/O operation.
type DiskIOEvent struct {
	Event
	LatencyNs  uint64 `json:"latency_ns"`
	Bytes      uint32 `json:"bytes"`
	ReadWrite  uint8  `json:"rw"` // 0=read, 1=write
	QueueDepth uint32 `json:"queue_depth"`
	DeviceID   uint32 `json:"device_id"` // Block device ID (major:minor encoded)
}

// NetIOEvent represents a network send or receive.
type NetIOEvent struct {
	Event
	Bytes   uint32    `json:"bytes"`
	SrcPort uint16    `json:"sport"`
	DstPort uint16    `json:"dport"`
	Dir     Direction `json:"direction"`
}

// SchedEvent represents a context switch.
type SchedEvent struct {
	Event
	OnCpuNs   uint64 `json:"on_cpu_ns"`
	Voluntary bool   `json:"voluntary"`
}

// SchedRunqueueEvent represents runqueue/off-CPU latency for a thread.
type SchedRunqueueEvent struct {
	Event
	RunqueueNs uint64 `json:"runqueue_ns"`
	OffCpuNs   uint64 `json:"off_cpu_ns"`
}

// PageFaultEvent represents a page fault.
type PageFaultEvent struct {
	Event
	Address uint64 `json:"address"`
	Major   bool   `json:"major"`
}

// FDEvent represents a file descriptor open/close.
type FDEvent struct {
	Event
	FD       int32  `json:"fd"`
	Filename string `json:"filename"`
}

// BlockMergeEvent represents a merged block I/O request.
type BlockMergeEvent struct {
	Event
	Bytes     uint32 `json:"bytes"`
	ReadWrite uint8  `json:"rw"` // 0=read, 1=write
}

// TcpRetransmitEvent represents a TCP retransmission.
type TcpRetransmitEvent struct {
	Event
	Bytes   uint32 `json:"bytes"`
	SrcPort uint16 `json:"sport"`
	DstPort uint16 `json:"dport"`
}

// TcpStateEvent represents a TCP state transition.
type TcpStateEvent struct {
	Event
	SrcPort  uint16 `json:"sport"`
	DstPort  uint16 `json:"dport"`
	NewState uint8  `json:"new_state"`
	OldState uint8  `json:"old_state"`
}

// TcpMetricsEvent represents TCP congestion/RTT metrics.
type TcpMetricsEvent struct {
	Event
	SrttUs  uint32 `json:"srtt_us"`
	Cwnd    uint32 `json:"cwnd"`
	SrcPort uint16 `json:"sport"`
	DstPort uint16 `json:"dport"`
}

// MemLatencyEvent represents memory reclaim/compaction latency.
type MemLatencyEvent struct {
	Event
	DurationNs uint64 `json:"duration_ns"`
}

// SwapEvent represents a swap-in/out event.
type SwapEvent struct {
	Event
	Pages uint64 `json:"pages"`
}

// OOMKillEvent represents an OOM kill event.
type OOMKillEvent struct {
	Event
	TargetPID uint32 `json:"target_pid"`
}

// ProcessExitEvent represents a process exit.
type ProcessExitEvent struct {
	Event
	ExitCode uint32 `json:"exit_code"`
}

// ParsedEvent wraps a typed event after parsing from the ring buffer.
type ParsedEvent struct {
	// Raw is the common event header.
	Raw Event

	// Typed is one of SyscallEvent, DiskIOEvent, NetIOEvent,
	// SchedEvent, SchedRunqueueEvent, PageFaultEvent, FDEvent,
	// BlockMergeEvent, TcpRetransmitEvent, TcpStateEvent,
	// TcpMetricsEvent, MemLatencyEvent, SwapEvent, OOMKillEvent,
	// or ProcessExitEvent.
	Typed any
}
