package aggregated

import (
	"sync"
	"time"

	"github.com/ethpandaops/observoor/internal/tracer"
)

// Buffer is a thread-safe aggregation buffer that collects events
// and aggregates them by dimension over a time window.
type Buffer struct {
	StartTime                  time.Time
	WallclockSlot              uint64
	WallclockSlotStartDateTime time.Time
	CLSyncing                  bool
	ELOptimistic               bool
	ELOffline                  bool
	mu                         sync.RWMutex

	// Syscalls (BasicDimension key) - 8 syscall types.
	SyscallRead      map[BasicDimension]*LatencyAggregate
	SyscallWrite     map[BasicDimension]*LatencyAggregate
	SyscallFutex     map[BasicDimension]*LatencyAggregate
	SyscallMmap      map[BasicDimension]*LatencyAggregate
	SyscallEpollWait map[BasicDimension]*LatencyAggregate
	SyscallFsync     map[BasicDimension]*LatencyAggregate
	SyscallFdatasync map[BasicDimension]*LatencyAggregate
	SyscallPwrite    map[BasicDimension]*LatencyAggregate

	// Network (NetworkDimension key).
	NetIO         map[NetworkDimension]*CounterAggregate
	TcpRetransmit map[NetworkDimension]*CounterAggregate

	// TCP metrics (TCPMetricsDimension key).
	TcpRTT  map[TCPMetricsDimension]*GaugeAggregate
	TcpCwnd map[TCPMetricsDimension]*GaugeAggregate

	// Disk (DiskDimension key).
	DiskLatency    map[DiskDimension]*LatencyAggregate
	DiskBytes      map[DiskDimension]*CounterAggregate
	DiskQueueDepth map[DiskDimension]*GaugeAggregate

	// Block merge (DiskDimension key, but without latency).
	BlockMerge map[DiskDimension]*CounterAggregate

	// Scheduler (BasicDimension key).
	SchedSwitch   map[BasicDimension]*LatencyAggregate // on_cpu_ns
	SchedRunqueue map[BasicDimension]*LatencyAggregate // runqueue_ns
	SchedOffCpu   map[BasicDimension]*LatencyAggregate // off_cpu_ns

	// Page faults (BasicDimension key).
	PageFaultMajor map[BasicDimension]*CounterAggregate
	PageFaultMinor map[BasicDimension]*CounterAggregate

	// FD operations (BasicDimension key).
	FDOpen  map[BasicDimension]*CounterAggregate
	FDClose map[BasicDimension]*CounterAggregate

	// Memory pressure (BasicDimension key).
	MemReclaim     map[BasicDimension]*LatencyAggregate
	MemCompaction  map[BasicDimension]*LatencyAggregate
	SwapIn         map[BasicDimension]*CounterAggregate
	SwapOut        map[BasicDimension]*CounterAggregate
	OOMKill        map[BasicDimension]*CounterAggregate
	ProcessExit    map[BasicDimension]*CounterAggregate
	TcpStateChange map[BasicDimension]*CounterAggregate
}

// NewBuffer creates a new Buffer with initialized maps.
func NewBuffer(
	startTime time.Time,
	wallclockSlot uint64,
	wallclockSlotStartDateTime time.Time,
	clSyncing bool,
	elOptimistic bool,
	elOffline bool,
) *Buffer {
	return &Buffer{
		StartTime:                  startTime,
		WallclockSlot:              wallclockSlot,
		WallclockSlotStartDateTime: wallclockSlotStartDateTime,
		CLSyncing:                  clSyncing,
		ELOptimistic:               elOptimistic,
		ELOffline:                  elOffline,
		// Syscalls.
		SyscallRead:      make(map[BasicDimension]*LatencyAggregate, 16),
		SyscallWrite:     make(map[BasicDimension]*LatencyAggregate, 16),
		SyscallFutex:     make(map[BasicDimension]*LatencyAggregate, 16),
		SyscallMmap:      make(map[BasicDimension]*LatencyAggregate, 16),
		SyscallEpollWait: make(map[BasicDimension]*LatencyAggregate, 16),
		SyscallFsync:     make(map[BasicDimension]*LatencyAggregate, 16),
		SyscallFdatasync: make(map[BasicDimension]*LatencyAggregate, 16),
		SyscallPwrite:    make(map[BasicDimension]*LatencyAggregate, 16),
		// Network.
		NetIO:         make(map[NetworkDimension]*CounterAggregate, 64),
		TcpRetransmit: make(map[NetworkDimension]*CounterAggregate, 32),
		// TCP metrics.
		TcpRTT:  make(map[TCPMetricsDimension]*GaugeAggregate, 32),
		TcpCwnd: make(map[TCPMetricsDimension]*GaugeAggregate, 32),
		// Disk.
		DiskLatency:    make(map[DiskDimension]*LatencyAggregate, 16),
		DiskBytes:      make(map[DiskDimension]*CounterAggregate, 16),
		DiskQueueDepth: make(map[DiskDimension]*GaugeAggregate, 16),
		BlockMerge:     make(map[DiskDimension]*CounterAggregate, 16),
		// Scheduler.
		SchedSwitch:   make(map[BasicDimension]*LatencyAggregate, 16),
		SchedRunqueue: make(map[BasicDimension]*LatencyAggregate, 16),
		SchedOffCpu:   make(map[BasicDimension]*LatencyAggregate, 16),
		// Page faults.
		PageFaultMajor: make(map[BasicDimension]*CounterAggregate, 16),
		PageFaultMinor: make(map[BasicDimension]*CounterAggregate, 16),
		// FD operations.
		FDOpen:  make(map[BasicDimension]*CounterAggregate, 16),
		FDClose: make(map[BasicDimension]*CounterAggregate, 16),
		// Memory pressure.
		MemReclaim:     make(map[BasicDimension]*LatencyAggregate, 8),
		MemCompaction:  make(map[BasicDimension]*LatencyAggregate, 8),
		SwapIn:         make(map[BasicDimension]*CounterAggregate, 8),
		SwapOut:        make(map[BasicDimension]*CounterAggregate, 8),
		OOMKill:        make(map[BasicDimension]*CounterAggregate, 8),
		ProcessExit:    make(map[BasicDimension]*CounterAggregate, 8),
		TcpStateChange: make(map[BasicDimension]*CounterAggregate, 8),
	}
}

// getOrCreateLatency returns the LatencyAggregate for the given key,
// creating it if it doesn't exist. Uses double-checked locking.
func getOrCreateLatency[K comparable](
	mu *sync.RWMutex,
	m map[K]*LatencyAggregate,
	key K,
) *LatencyAggregate {
	mu.RLock()
	agg, ok := m[key]
	mu.RUnlock()

	if ok {
		return agg
	}

	mu.Lock()
	defer mu.Unlock()

	// Double-check after acquiring write lock.
	if agg, ok = m[key]; ok {
		return agg
	}

	agg = NewLatencyAggregate()
	m[key] = agg

	return agg
}

// getOrCreateCounter returns the CounterAggregate for the given key,
// creating it if it doesn't exist. Uses double-checked locking.
func getOrCreateCounter[K comparable](
	mu *sync.RWMutex,
	m map[K]*CounterAggregate,
	key K,
) *CounterAggregate {
	mu.RLock()
	agg, ok := m[key]
	mu.RUnlock()

	if ok {
		return agg
	}

	mu.Lock()
	defer mu.Unlock()

	// Double-check after acquiring write lock.
	if agg, ok = m[key]; ok {
		return agg
	}

	agg = NewCounterAggregate()
	m[key] = agg

	return agg
}

// getOrCreateGauge returns the GaugeAggregate for the given key,
// creating it if it doesn't exist. Uses double-checked locking.
func getOrCreateGauge[K comparable](
	mu *sync.RWMutex,
	m map[K]*GaugeAggregate,
	key K,
) *GaugeAggregate {
	mu.RLock()
	agg, ok := m[key]
	mu.RUnlock()

	if ok {
		return agg
	}

	mu.Lock()
	defer mu.Unlock()

	// Double-check after acquiring write lock.
	if agg, ok = m[key]; ok {
		return agg
	}

	agg = NewGaugeAggregate()
	m[key] = agg

	return agg
}

// AddSyscall adds a syscall latency event to the appropriate map.
// Uses EventType integer dispatch instead of string matching.
func (b *Buffer) AddSyscall(eventType tracer.EventType, dim BasicDimension, latencyNs uint64) {
	var m map[BasicDimension]*LatencyAggregate

	switch eventType {
	case tracer.EventTypeSyscallRead:
		m = b.SyscallRead
	case tracer.EventTypeSyscallWrite:
		m = b.SyscallWrite
	case tracer.EventTypeSyscallFutex:
		m = b.SyscallFutex
	case tracer.EventTypeSyscallMmap:
		m = b.SyscallMmap
	case tracer.EventTypeSyscallEpollWait:
		m = b.SyscallEpollWait
	case tracer.EventTypeSyscallFsync:
		m = b.SyscallFsync
	case tracer.EventTypeSyscallFdatasync:
		m = b.SyscallFdatasync
	case tracer.EventTypeSyscallPwrite:
		m = b.SyscallPwrite
	default:
		return
	}

	agg := getOrCreateLatency(&b.mu, m, dim)
	agg.Add(latencyNs)
}

// AddNetIO adds a network I/O event.
func (b *Buffer) AddNetIO(dim NetworkDimension, bytes int64) {
	agg := getOrCreateCounter(&b.mu, b.NetIO, dim)
	agg.Add(bytes)
}

// AddTcpRetransmit adds a TCP retransmit event.
func (b *Buffer) AddTcpRetransmit(dim NetworkDimension, bytes int64) {
	agg := getOrCreateCounter(&b.mu, b.TcpRetransmit, dim)
	agg.Add(bytes)
}

// AddTcpMetrics adds TCP metrics (RTT and CWND).
func (b *Buffer) AddTcpMetrics(dim TCPMetricsDimension, rttUs, cwnd uint32) {
	rttAgg := getOrCreateGauge(&b.mu, b.TcpRTT, dim)
	rttAgg.Add(int64(rttUs))

	cwndAgg := getOrCreateGauge(&b.mu, b.TcpCwnd, dim)
	cwndAgg.Add(int64(cwnd))
}

// AddDiskIO adds a disk I/O event with latency and bytes.
func (b *Buffer) AddDiskIO(dim DiskDimension, latencyNs uint64, bytes uint32, queueDepth uint32) {
	latAgg := getOrCreateLatency(&b.mu, b.DiskLatency, dim)
	latAgg.Add(latencyNs)

	bytesAgg := getOrCreateCounter(&b.mu, b.DiskBytes, dim)
	bytesAgg.Add(int64(bytes))

	queueAgg := getOrCreateGauge(&b.mu, b.DiskQueueDepth, dim)
	queueAgg.Add(int64(queueDepth))
}

// AddBlockMerge adds a block merge event.
func (b *Buffer) AddBlockMerge(dim DiskDimension, bytes uint32) {
	agg := getOrCreateCounter(&b.mu, b.BlockMerge, dim)
	agg.Add(int64(bytes))
}

// AddSchedSwitch adds a scheduler switch event.
func (b *Buffer) AddSchedSwitch(dim BasicDimension, onCpuNs uint64) {
	agg := getOrCreateLatency(&b.mu, b.SchedSwitch, dim)
	agg.Add(onCpuNs)
}

// AddSchedRunqueue adds scheduler runqueue/off-CPU latency.
func (b *Buffer) AddSchedRunqueue(dim BasicDimension, runqueueNs, offCpuNs uint64) {
	if runqueueNs > 0 {
		rqAgg := getOrCreateLatency(&b.mu, b.SchedRunqueue, dim)
		rqAgg.Add(runqueueNs)
	}

	if offCpuNs > 0 {
		offAgg := getOrCreateLatency(&b.mu, b.SchedOffCpu, dim)
		offAgg.Add(offCpuNs)
	}
}

// AddPageFault adds a page fault event.
func (b *Buffer) AddPageFault(dim BasicDimension, major bool) {
	if major {
		agg := getOrCreateCounter(&b.mu, b.PageFaultMajor, dim)
		agg.AddCount(1)
	} else {
		agg := getOrCreateCounter(&b.mu, b.PageFaultMinor, dim)
		agg.AddCount(1)
	}
}

// AddFDOpen adds an FD open event.
func (b *Buffer) AddFDOpen(dim BasicDimension) {
	agg := getOrCreateCounter(&b.mu, b.FDOpen, dim)
	agg.AddCount(1)
}

// AddFDClose adds an FD close event.
func (b *Buffer) AddFDClose(dim BasicDimension) {
	agg := getOrCreateCounter(&b.mu, b.FDClose, dim)
	agg.AddCount(1)
}

// AddMemReclaim adds a memory reclaim event.
func (b *Buffer) AddMemReclaim(dim BasicDimension, durationNs uint64) {
	agg := getOrCreateLatency(&b.mu, b.MemReclaim, dim)
	agg.Add(durationNs)
}

// AddMemCompaction adds a memory compaction event.
func (b *Buffer) AddMemCompaction(dim BasicDimension, durationNs uint64) {
	agg := getOrCreateLatency(&b.mu, b.MemCompaction, dim)
	agg.Add(durationNs)
}

// AddSwapIn adds a swap-in event.
func (b *Buffer) AddSwapIn(dim BasicDimension, pages uint64) {
	agg := getOrCreateCounter(&b.mu, b.SwapIn, dim)
	agg.Add(int64(pages))
}

// AddSwapOut adds a swap-out event.
func (b *Buffer) AddSwapOut(dim BasicDimension, pages uint64) {
	agg := getOrCreateCounter(&b.mu, b.SwapOut, dim)
	agg.Add(int64(pages))
}

// AddOOMKill adds an OOM kill event.
func (b *Buffer) AddOOMKill(dim BasicDimension) {
	agg := getOrCreateCounter(&b.mu, b.OOMKill, dim)
	agg.AddCount(1)
}

// AddProcessExit adds a process exit event.
func (b *Buffer) AddProcessExit(dim BasicDimension) {
	agg := getOrCreateCounter(&b.mu, b.ProcessExit, dim)
	agg.AddCount(1)
}

// AddTcpStateChange adds a TCP state change event.
func (b *Buffer) AddTcpStateChange(dim BasicDimension) {
	agg := getOrCreateCounter(&b.mu, b.TcpStateChange, dim)
	agg.AddCount(1)
}
