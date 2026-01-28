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
	SyscallReadCount  atomic.Int64
	SyscallReadBytes  atomic.Int64
	SyscallReadLatNs  atomic.Int64
	SyscallWriteCount atomic.Int64
	SyscallWriteBytes atomic.Int64
	SyscallWriteLatNs atomic.Int64
	SyscallFutexCount atomic.Int64
	SyscallFutexLatNs atomic.Int64
	SyscallMmapCount  atomic.Int64
	SyscallEpollCount atomic.Int64
	SyscallEpollLatNs atomic.Int64

	// Disk I/O metrics
	DiskReadCount  atomic.Int64
	DiskReadBytes  atomic.Int64
	DiskReadLatNs  atomic.Int64
	DiskWriteCount atomic.Int64
	DiskWriteBytes atomic.Int64
	DiskWriteLatNs atomic.Int64

	// Network I/O metrics
	NetTXCount atomic.Int64
	NetTXBytes atomic.Int64
	NetRXCount atomic.Int64
	NetRXBytes atomic.Int64

	// Scheduler metrics
	SchedSwitchTotal     atomic.Int64
	SchedSwitchVoluntary atomic.Int64
	SchedOnCpuNs         atomic.Int64

	// Memory metrics
	PageFaultTotal atomic.Int64
	PageFaultMajor atomic.Int64

	// FD metrics
	FDOpenCount  atomic.Int64
	FDCloseCount atomic.Int64

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
	case tracer.PageFaultEvent:
		b.addPageFault(e)
	case tracer.FDEvent:
		b.addFD(event.Raw.Type)
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

// Snapshot returns a point-in-time copy of the bucket's counters.
type BucketSnapshot struct {
	StartTime time.Time
	Slot      uint64

	SyscallReadCount  int64
	SyscallReadBytes  int64
	SyscallReadLatNs  int64
	SyscallWriteCount int64
	SyscallWriteBytes int64
	SyscallWriteLatNs int64
	SyscallFutexCount int64
	SyscallFutexLatNs int64
	SyscallMmapCount  int64
	SyscallEpollCount int64
	SyscallEpollLatNs int64

	DiskReadCount  int64
	DiskReadBytes  int64
	DiskReadLatNs  int64
	DiskWriteCount int64
	DiskWriteBytes int64
	DiskWriteLatNs int64

	NetTXCount int64
	NetTXBytes int64
	NetRXCount int64
	NetRXBytes int64

	SchedSwitchTotal     int64
	SchedSwitchVoluntary int64
	SchedOnCpuNs         int64

	PageFaultTotal int64
	PageFaultMajor int64

	FDOpenCount  int64
	FDCloseCount int64

	EventCount int64
}

// Snapshot returns a point-in-time snapshot of the bucket.
func (b *Bucket) Snapshot() BucketSnapshot {
	return BucketSnapshot{
		StartTime: b.StartTime,
		Slot:      b.Slot,

		SyscallReadCount:  b.SyscallReadCount.Load(),
		SyscallReadBytes:  b.SyscallReadBytes.Load(),
		SyscallReadLatNs:  b.SyscallReadLatNs.Load(),
		SyscallWriteCount: b.SyscallWriteCount.Load(),
		SyscallWriteBytes: b.SyscallWriteBytes.Load(),
		SyscallWriteLatNs: b.SyscallWriteLatNs.Load(),
		SyscallFutexCount: b.SyscallFutexCount.Load(),
		SyscallFutexLatNs: b.SyscallFutexLatNs.Load(),
		SyscallMmapCount:  b.SyscallMmapCount.Load(),
		SyscallEpollCount: b.SyscallEpollCount.Load(),
		SyscallEpollLatNs: b.SyscallEpollLatNs.Load(),

		DiskReadCount:  b.DiskReadCount.Load(),
		DiskReadBytes:  b.DiskReadBytes.Load(),
		DiskReadLatNs:  b.DiskReadLatNs.Load(),
		DiskWriteCount: b.DiskWriteCount.Load(),
		DiskWriteBytes: b.DiskWriteBytes.Load(),
		DiskWriteLatNs: b.DiskWriteLatNs.Load(),

		NetTXCount: b.NetTXCount.Load(),
		NetTXBytes: b.NetTXBytes.Load(),
		NetRXCount: b.NetRXCount.Load(),
		NetRXBytes: b.NetRXBytes.Load(),

		SchedSwitchTotal:     b.SchedSwitchTotal.Load(),
		SchedSwitchVoluntary: b.SchedSwitchVoluntary.Load(),
		SchedOnCpuNs:         b.SchedOnCpuNs.Load(),

		PageFaultTotal: b.PageFaultTotal.Load(),
		PageFaultMajor: b.PageFaultMajor.Load(),

		FDOpenCount:  b.FDOpenCount.Load(),
		FDCloseCount: b.FDCloseCount.Load(),

		EventCount: b.EventCount.Load(),
	}
}
