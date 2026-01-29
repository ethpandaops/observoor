package sink

import (
	"sync/atomic"
	"time"

	"github.com/ethpandaops/observoor/internal/tracer"
)

// Bucket aggregates events over a time period (slot or window).
type Bucket struct {
	StartTime time.Time
	Slot      uint64

	// Syscall metrics
	SyscallReadCount      atomic.Int64
	SyscallReadBytes      atomic.Int64
	SyscallReadLatNs      atomic.Int64
	SyscallWriteCount     atomic.Int64
	SyscallWriteBytes     atomic.Int64
	SyscallWriteLatNs     atomic.Int64
	SyscallFutexCount     atomic.Int64
	SyscallFutexLatNs     atomic.Int64
	SyscallMmapCount      atomic.Int64
	SyscallEpollCount     atomic.Int64
	SyscallEpollLatNs     atomic.Int64
	SyscallFsyncCount     atomic.Int64
	SyscallFsyncLatNs     atomic.Int64
	SyscallFdatasyncCount atomic.Int64
	SyscallFdatasyncLatNs atomic.Int64
	SyscallPwriteCount    atomic.Int64
	SyscallPwriteBytes    atomic.Int64
	SyscallPwriteLatNs    atomic.Int64

	// Disk I/O metrics
	DiskReadCount     atomic.Int64
	DiskReadBytes     atomic.Int64
	DiskReadLatNs     atomic.Int64
	DiskWriteCount    atomic.Int64
	DiskWriteBytes    atomic.Int64
	DiskWriteLatNs    atomic.Int64
	DiskQueueDepthSum atomic.Int64
	BlockMergeCount   atomic.Int64
	BlockMergeBytes   atomic.Int64

	// Network I/O metrics
	NetTXCount atomic.Int64
	NetTXBytes atomic.Int64
	NetRXCount atomic.Int64
	NetRXBytes atomic.Int64

	// Scheduler metrics
	SchedSwitchTotal     atomic.Int64
	SchedSwitchVoluntary atomic.Int64
	SchedOnCpuNs         atomic.Int64
	SchedRunqueueCount   atomic.Int64
	SchedRunqueueLatNs   atomic.Int64
	SchedOffCpuNs        atomic.Int64

	// Memory metrics
	PageFaultTotal atomic.Int64
	PageFaultMajor atomic.Int64

	MemReclaimCount    atomic.Int64
	MemReclaimNs       atomic.Int64
	MemCompactionCount atomic.Int64
	MemCompactionNs    atomic.Int64
	SwapInCount        atomic.Int64
	SwapOutCount       atomic.Int64
	SwapInPages        atomic.Int64
	SwapOutPages       atomic.Int64
	OOMKillCount       atomic.Int64

	// FD metrics
	FDOpenCount  atomic.Int64
	FDCloseCount atomic.Int64

	// TCP metrics
	TcpRetransmitCount  atomic.Int64
	TcpRetransmitBytes  atomic.Int64
	TcpStateChangeCount atomic.Int64
	TcpMetricsCount     atomic.Int64
	TcpSrttUsSum        atomic.Int64
	TcpCwndSum          atomic.Int64

	// Process lifecycle
	ProcessExitCount        atomic.Int64
	ProcessExitNonZeroCount atomic.Int64

	// Total event count
	EventCount atomic.Int64
}

// NewBucket creates a new aggregation bucket for the given slot.
func NewBucket(slot uint64, startTime time.Time) *Bucket {
	return &Bucket{
		StartTime: startTime,
		Slot:      slot,
	}
}

// Add incorporates a parsed event into the bucket's counters.
func (b *Bucket) Add(event tracer.ParsedEvent) {
	b.EventCount.Add(1)

	switch e := event.Typed.(type) {
	case tracer.SyscallEvent:
		b.addSyscall(event.Raw.Type, e)
	case tracer.DiskIOEvent:
		b.addDiskIO(e)
	case tracer.NetIOEvent:
		b.addNetIO(e)
	case tracer.SchedEvent:
		b.addSched(e)
	case tracer.SchedRunqueueEvent:
		b.addSchedRunqueue(e)
	case tracer.PageFaultEvent:
		b.addPageFault(e)
	case tracer.FDEvent:
		b.addFD(event.Raw.Type)
	case tracer.BlockMergeEvent:
		b.addBlockMerge(e)
	case tracer.TcpRetransmitEvent:
		b.addTcpRetransmit(e)
	case tracer.TcpStateEvent:
		b.addTcpState(e)
	case tracer.TcpMetricsEvent:
		b.addTcpMetrics(e)
	case tracer.MemLatencyEvent:
		b.addMemLatency(event.Raw.Type, e)
	case tracer.SwapEvent:
		b.addSwap(event.Raw.Type, e)
	case tracer.OOMKillEvent:
		b.addOOMKill()
	case tracer.ProcessExitEvent:
		b.addProcessExit(e)
	}
}

func (b *Bucket) addSyscall(
	eventType tracer.EventType,
	e tracer.SyscallEvent,
) {
	switch eventType {
	case tracer.EventTypeSyscallRead:
		b.SyscallReadCount.Add(1)
		b.SyscallReadLatNs.Add(int64(e.LatencyNs))

		if e.Return > 0 {
			b.SyscallReadBytes.Add(e.Return)
		}
	case tracer.EventTypeSyscallWrite:
		b.SyscallWriteCount.Add(1)
		b.SyscallWriteLatNs.Add(int64(e.LatencyNs))

		if e.Return > 0 {
			b.SyscallWriteBytes.Add(e.Return)
		}
	case tracer.EventTypeSyscallFutex:
		b.SyscallFutexCount.Add(1)
		b.SyscallFutexLatNs.Add(int64(e.LatencyNs))
	case tracer.EventTypeSyscallMmap:
		b.SyscallMmapCount.Add(1)
	case tracer.EventTypeSyscallEpollWait:
		b.SyscallEpollCount.Add(1)
		b.SyscallEpollLatNs.Add(int64(e.LatencyNs))
	case tracer.EventTypeSyscallFsync:
		b.SyscallFsyncCount.Add(1)
		b.SyscallFsyncLatNs.Add(int64(e.LatencyNs))
	case tracer.EventTypeSyscallFdatasync:
		b.SyscallFdatasyncCount.Add(1)
		b.SyscallFdatasyncLatNs.Add(int64(e.LatencyNs))
	case tracer.EventTypeSyscallPwrite:
		b.SyscallPwriteCount.Add(1)
		b.SyscallPwriteLatNs.Add(int64(e.LatencyNs))
		if e.Return > 0 {
			b.SyscallPwriteBytes.Add(e.Return)
		}
	}
}

func (b *Bucket) addDiskIO(e tracer.DiskIOEvent) {
	if e.ReadWrite == 0 {
		b.DiskReadCount.Add(1)
		b.DiskReadBytes.Add(int64(e.Bytes))
		b.DiskReadLatNs.Add(int64(e.LatencyNs))
	} else {
		b.DiskWriteCount.Add(1)
		b.DiskWriteBytes.Add(int64(e.Bytes))
		b.DiskWriteLatNs.Add(int64(e.LatencyNs))
	}

	b.DiskQueueDepthSum.Add(int64(e.QueueDepth))
}

func (b *Bucket) addNetIO(e tracer.NetIOEvent) {
	if e.Dir == tracer.DirectionTX {
		b.NetTXCount.Add(1)
		b.NetTXBytes.Add(int64(e.Bytes))
	} else {
		b.NetRXCount.Add(1)
		b.NetRXBytes.Add(int64(e.Bytes))
	}
}

func (b *Bucket) addSched(e tracer.SchedEvent) {
	b.SchedSwitchTotal.Add(1)

	if e.Voluntary {
		b.SchedSwitchVoluntary.Add(1)
	}

	b.SchedOnCpuNs.Add(int64(e.OnCpuNs))
}

func (b *Bucket) addSchedRunqueue(e tracer.SchedRunqueueEvent) {
	b.SchedRunqueueCount.Add(1)
	b.SchedRunqueueLatNs.Add(int64(e.RunqueueNs))
	b.SchedOffCpuNs.Add(int64(e.OffCpuNs))
}

func (b *Bucket) addPageFault(e tracer.PageFaultEvent) {
	b.PageFaultTotal.Add(1)

	if e.Major {
		b.PageFaultMajor.Add(1)
	}
}

func (b *Bucket) addFD(eventType tracer.EventType) {
	if eventType == tracer.EventTypeFDOpen {
		b.FDOpenCount.Add(1)
	} else {
		b.FDCloseCount.Add(1)
	}
}

func (b *Bucket) addBlockMerge(e tracer.BlockMergeEvent) {
	b.BlockMergeCount.Add(1)
	b.BlockMergeBytes.Add(int64(e.Bytes))
}

func (b *Bucket) addTcpRetransmit(e tracer.TcpRetransmitEvent) {
	b.TcpRetransmitCount.Add(1)
	b.TcpRetransmitBytes.Add(int64(e.Bytes))
}

func (b *Bucket) addTcpState(_ tracer.TcpStateEvent) {
	b.TcpStateChangeCount.Add(1)
}

func (b *Bucket) addTcpMetrics(e tracer.TcpMetricsEvent) {
	b.TcpMetricsCount.Add(1)
	b.TcpSrttUsSum.Add(int64(e.SrttUs))
	b.TcpCwndSum.Add(int64(e.Cwnd))
}

func (b *Bucket) addMemLatency(
	eventType tracer.EventType,
	e tracer.MemLatencyEvent,
) {
	switch eventType {
	case tracer.EventTypeMemReclaim:
		b.MemReclaimCount.Add(1)
		b.MemReclaimNs.Add(int64(e.DurationNs))
	case tracer.EventTypeMemCompaction:
		b.MemCompactionCount.Add(1)
		b.MemCompactionNs.Add(int64(e.DurationNs))
	}
}

func (b *Bucket) addSwap(
	eventType tracer.EventType,
	e tracer.SwapEvent,
) {
	switch eventType {
	case tracer.EventTypeSwapIn:
		b.SwapInCount.Add(1)
		b.SwapInPages.Add(int64(e.Pages))
	case tracer.EventTypeSwapOut:
		b.SwapOutCount.Add(1)
		b.SwapOutPages.Add(int64(e.Pages))
	}
}

func (b *Bucket) addOOMKill() {
	b.OOMKillCount.Add(1)
}

func (b *Bucket) addProcessExit(e tracer.ProcessExitEvent) {
	b.ProcessExitCount.Add(1)
	if e.ExitCode != 0 {
		b.ProcessExitNonZeroCount.Add(1)
	}
}

// Snapshot returns a point-in-time copy of the bucket's counters.
type BucketSnapshot struct {
	StartTime time.Time
	Slot      uint64

	SyscallReadCount      int64
	SyscallReadBytes      int64
	SyscallReadLatNs      int64
	SyscallWriteCount     int64
	SyscallWriteBytes     int64
	SyscallWriteLatNs     int64
	SyscallFutexCount     int64
	SyscallFutexLatNs     int64
	SyscallMmapCount      int64
	SyscallEpollCount     int64
	SyscallEpollLatNs     int64
	SyscallFsyncCount     int64
	SyscallFsyncLatNs     int64
	SyscallFdatasyncCount int64
	SyscallFdatasyncLatNs int64
	SyscallPwriteCount    int64
	SyscallPwriteBytes    int64
	SyscallPwriteLatNs    int64

	DiskReadCount     int64
	DiskReadBytes     int64
	DiskReadLatNs     int64
	DiskWriteCount    int64
	DiskWriteBytes    int64
	DiskWriteLatNs    int64
	DiskQueueDepthSum int64
	BlockMergeCount   int64
	BlockMergeBytes   int64

	NetTXCount int64
	NetTXBytes int64
	NetRXCount int64
	NetRXBytes int64

	SchedSwitchTotal     int64
	SchedSwitchVoluntary int64
	SchedOnCpuNs         int64
	SchedRunqueueCount   int64
	SchedRunqueueLatNs   int64
	SchedOffCpuNs        int64

	PageFaultTotal     int64
	PageFaultMajor     int64
	MemReclaimCount    int64
	MemReclaimNs       int64
	MemCompactionCount int64
	MemCompactionNs    int64
	SwapInCount        int64
	SwapOutCount       int64
	SwapInPages        int64
	SwapOutPages       int64
	OOMKillCount       int64

	FDOpenCount  int64
	FDCloseCount int64

	TcpRetransmitCount  int64
	TcpRetransmitBytes  int64
	TcpStateChangeCount int64
	TcpMetricsCount     int64
	TcpSrttUsSum        int64
	TcpCwndSum          int64

	ProcessExitCount        int64
	ProcessExitNonZeroCount int64

	EventCount int64
}

// Snapshot returns a point-in-time snapshot of the bucket.
func (b *Bucket) Snapshot() BucketSnapshot {
	return BucketSnapshot{
		StartTime: b.StartTime,
		Slot:      b.Slot,

		SyscallReadCount:      b.SyscallReadCount.Load(),
		SyscallReadBytes:      b.SyscallReadBytes.Load(),
		SyscallReadLatNs:      b.SyscallReadLatNs.Load(),
		SyscallWriteCount:     b.SyscallWriteCount.Load(),
		SyscallWriteBytes:     b.SyscallWriteBytes.Load(),
		SyscallWriteLatNs:     b.SyscallWriteLatNs.Load(),
		SyscallFutexCount:     b.SyscallFutexCount.Load(),
		SyscallFutexLatNs:     b.SyscallFutexLatNs.Load(),
		SyscallMmapCount:      b.SyscallMmapCount.Load(),
		SyscallEpollCount:     b.SyscallEpollCount.Load(),
		SyscallEpollLatNs:     b.SyscallEpollLatNs.Load(),
		SyscallFsyncCount:     b.SyscallFsyncCount.Load(),
		SyscallFsyncLatNs:     b.SyscallFsyncLatNs.Load(),
		SyscallFdatasyncCount: b.SyscallFdatasyncCount.Load(),
		SyscallFdatasyncLatNs: b.SyscallFdatasyncLatNs.Load(),
		SyscallPwriteCount:    b.SyscallPwriteCount.Load(),
		SyscallPwriteBytes:    b.SyscallPwriteBytes.Load(),
		SyscallPwriteLatNs:    b.SyscallPwriteLatNs.Load(),

		DiskReadCount:     b.DiskReadCount.Load(),
		DiskReadBytes:     b.DiskReadBytes.Load(),
		DiskReadLatNs:     b.DiskReadLatNs.Load(),
		DiskWriteCount:    b.DiskWriteCount.Load(),
		DiskWriteBytes:    b.DiskWriteBytes.Load(),
		DiskWriteLatNs:    b.DiskWriteLatNs.Load(),
		DiskQueueDepthSum: b.DiskQueueDepthSum.Load(),
		BlockMergeCount:   b.BlockMergeCount.Load(),
		BlockMergeBytes:   b.BlockMergeBytes.Load(),

		NetTXCount: b.NetTXCount.Load(),
		NetTXBytes: b.NetTXBytes.Load(),
		NetRXCount: b.NetRXCount.Load(),
		NetRXBytes: b.NetRXBytes.Load(),

		SchedSwitchTotal:     b.SchedSwitchTotal.Load(),
		SchedSwitchVoluntary: b.SchedSwitchVoluntary.Load(),
		SchedOnCpuNs:         b.SchedOnCpuNs.Load(),
		SchedRunqueueCount:   b.SchedRunqueueCount.Load(),
		SchedRunqueueLatNs:   b.SchedRunqueueLatNs.Load(),
		SchedOffCpuNs:        b.SchedOffCpuNs.Load(),

		PageFaultTotal:     b.PageFaultTotal.Load(),
		PageFaultMajor:     b.PageFaultMajor.Load(),
		MemReclaimCount:    b.MemReclaimCount.Load(),
		MemReclaimNs:       b.MemReclaimNs.Load(),
		MemCompactionCount: b.MemCompactionCount.Load(),
		MemCompactionNs:    b.MemCompactionNs.Load(),
		SwapInCount:        b.SwapInCount.Load(),
		SwapOutCount:       b.SwapOutCount.Load(),
		SwapInPages:        b.SwapInPages.Load(),
		SwapOutPages:       b.SwapOutPages.Load(),
		OOMKillCount:       b.OOMKillCount.Load(),

		FDOpenCount:  b.FDOpenCount.Load(),
		FDCloseCount: b.FDCloseCount.Load(),

		TcpRetransmitCount:  b.TcpRetransmitCount.Load(),
		TcpRetransmitBytes:  b.TcpRetransmitBytes.Load(),
		TcpStateChangeCount: b.TcpStateChangeCount.Load(),
		TcpMetricsCount:     b.TcpMetricsCount.Load(),
		TcpSrttUsSum:        b.TcpSrttUsSum.Load(),
		TcpCwndSum:          b.TcpCwndSum.Load(),

		ProcessExitCount:        b.ProcessExitCount.Load(),
		ProcessExitNonZeroCount: b.ProcessExitNonZeroCount.Load(),

		EventCount: b.EventCount.Load(),
	}
}
