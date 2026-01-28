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
	LatencyNs uint64 `json:"latency_ns"`
	Bytes     uint32 `json:"bytes"`
	ReadWrite uint8  `json:"rw"` // 0=read, 1=write
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

// ParsedEvent wraps a typed event after parsing from the ring buffer.
type ParsedEvent struct {
	// Raw is the common event header.
	Raw Event

	// Typed is one of SyscallEvent, DiskIOEvent, NetIOEvent,
	// SchedEvent, PageFaultEvent, or FDEvent.
	Typed any
}
