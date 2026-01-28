package sink

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/ethpandaops/observoor/internal/tracer"
)

func TestNewBucket(t *testing.T) {
	now := time.Now()
	b := NewBucket(42, now)

	assert.Equal(t, uint64(42), b.Slot)
	assert.Equal(t, now, b.StartTime)
	assert.Equal(t, int64(0), b.EventCount.Load())
}

func TestBucket_AddSyscallRead(t *testing.T) {
	b := NewBucket(1, time.Now())

	b.Add(tracer.ParsedEvent{
		Raw: tracer.Event{Type: tracer.EventTypeSyscallRead},
		Typed: tracer.SyscallEvent{
			LatencyNs: 5000,
			Return:    1024,
		},
	})

	snap := b.Snapshot()
	assert.Equal(t, int64(1), snap.EventCount)
	assert.Equal(t, int64(1), snap.SyscallReadCount)
	assert.Equal(t, int64(1024), snap.SyscallReadBytes)
	assert.Equal(t, int64(5000), snap.SyscallReadLatNs)
}

func TestBucket_AddSyscallWrite(t *testing.T) {
	b := NewBucket(1, time.Now())

	b.Add(tracer.ParsedEvent{
		Raw: tracer.Event{Type: tracer.EventTypeSyscallWrite},
		Typed: tracer.SyscallEvent{
			LatencyNs: 3000,
			Return:    512,
		},
	})

	snap := b.Snapshot()
	assert.Equal(t, int64(1), snap.SyscallWriteCount)
	assert.Equal(t, int64(512), snap.SyscallWriteBytes)
	assert.Equal(t, int64(3000), snap.SyscallWriteLatNs)
}

func TestBucket_AddSyscallFutex(t *testing.T) {
	b := NewBucket(1, time.Now())

	b.Add(tracer.ParsedEvent{
		Raw: tracer.Event{Type: tracer.EventTypeSyscallFutex},
		Typed: tracer.SyscallEvent{
			LatencyNs: 100000,
		},
	})

	snap := b.Snapshot()
	assert.Equal(t, int64(1), snap.SyscallFutexCount)
	assert.Equal(t, int64(100000), snap.SyscallFutexLatNs)
}

func TestBucket_AddDiskIO(t *testing.T) {
	b := NewBucket(1, time.Now())

	// Read
	b.Add(tracer.ParsedEvent{
		Raw: tracer.Event{Type: tracer.EventTypeDiskIO},
		Typed: tracer.DiskIOEvent{
			LatencyNs: 10000,
			Bytes:     4096,
			ReadWrite: 0, // read
		},
	})

	// Write
	b.Add(tracer.ParsedEvent{
		Raw: tracer.Event{Type: tracer.EventTypeDiskIO},
		Typed: tracer.DiskIOEvent{
			LatencyNs: 20000,
			Bytes:     8192,
			ReadWrite: 1, // write
		},
	})

	snap := b.Snapshot()
	assert.Equal(t, int64(2), snap.EventCount)
	assert.Equal(t, int64(1), snap.DiskReadCount)
	assert.Equal(t, int64(4096), snap.DiskReadBytes)
	assert.Equal(t, int64(10000), snap.DiskReadLatNs)
	assert.Equal(t, int64(1), snap.DiskWriteCount)
	assert.Equal(t, int64(8192), snap.DiskWriteBytes)
	assert.Equal(t, int64(20000), snap.DiskWriteLatNs)
}

func TestBucket_AddNetIO(t *testing.T) {
	b := NewBucket(1, time.Now())

	b.Add(tracer.ParsedEvent{
		Raw: tracer.Event{Type: tracer.EventTypeNetTX},
		Typed: tracer.NetIOEvent{
			Bytes: 1500,
			Dir:   tracer.DirectionTX,
		},
	})

	b.Add(tracer.ParsedEvent{
		Raw: tracer.Event{Type: tracer.EventTypeNetRX},
		Typed: tracer.NetIOEvent{
			Bytes: 2000,
			Dir:   tracer.DirectionRX,
		},
	})

	snap := b.Snapshot()
	assert.Equal(t, int64(1), snap.NetTXCount)
	assert.Equal(t, int64(1500), snap.NetTXBytes)
	assert.Equal(t, int64(1), snap.NetRXCount)
	assert.Equal(t, int64(2000), snap.NetRXBytes)
}

func TestBucket_AddSchedSwitch(t *testing.T) {
	b := NewBucket(1, time.Now())

	b.Add(tracer.ParsedEvent{
		Raw:   tracer.Event{Type: tracer.EventTypeSchedSwitch},
		Typed: tracer.SchedEvent{Voluntary: true},
	})
	b.Add(tracer.ParsedEvent{
		Raw:   tracer.Event{Type: tracer.EventTypeSchedSwitch},
		Typed: tracer.SchedEvent{Voluntary: false},
	})

	snap := b.Snapshot()
	assert.Equal(t, int64(2), snap.SchedSwitchTotal)
	assert.Equal(t, int64(1), snap.SchedSwitchVoluntary)
}

func TestBucket_AddPageFault(t *testing.T) {
	b := NewBucket(1, time.Now())

	b.Add(tracer.ParsedEvent{
		Raw:   tracer.Event{Type: tracer.EventTypePageFault},
		Typed: tracer.PageFaultEvent{Major: true, Address: 0xdeadbeef},
	})
	b.Add(tracer.ParsedEvent{
		Raw:   tracer.Event{Type: tracer.EventTypePageFault},
		Typed: tracer.PageFaultEvent{Major: false, Address: 0xcafebabe},
	})

	snap := b.Snapshot()
	assert.Equal(t, int64(2), snap.PageFaultTotal)
	assert.Equal(t, int64(1), snap.PageFaultMajor)
}

func TestBucket_AddFD(t *testing.T) {
	b := NewBucket(1, time.Now())

	b.Add(tracer.ParsedEvent{
		Raw: tracer.Event{Type: tracer.EventTypeFDOpen},
		Typed: tracer.FDEvent{
			FD:       42,
			Filename: "/tmp/test",
		},
	})
	b.Add(tracer.ParsedEvent{
		Raw:   tracer.Event{Type: tracer.EventTypeFDClose},
		Typed: tracer.FDEvent{FD: 42},
	})

	snap := b.Snapshot()
	assert.Equal(t, int64(1), snap.FDOpenCount)
	assert.Equal(t, int64(1), snap.FDCloseCount)
}

func TestBucket_NegativeReturn(t *testing.T) {
	b := NewBucket(1, time.Now())

	// Negative return (error) should not add bytes.
	b.Add(tracer.ParsedEvent{
		Raw: tracer.Event{Type: tracer.EventTypeSyscallRead},
		Typed: tracer.SyscallEvent{
			LatencyNs: 100,
			Return:    -1,
		},
	})

	snap := b.Snapshot()
	assert.Equal(t, int64(1), snap.SyscallReadCount)
	assert.Equal(t, int64(0), snap.SyscallReadBytes)
}

func TestBucket_ConcurrentAdds(t *testing.T) {
	b := NewBucket(1, time.Now())

	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(1)

		go func() {
			defer wg.Done()

			b.Add(tracer.ParsedEvent{
				Raw: tracer.Event{Type: tracer.EventTypeSyscallRead},
				Typed: tracer.SyscallEvent{
					LatencyNs: 100,
					Return:    10,
				},
			})
		}()
	}

	wg.Wait()

	snap := b.Snapshot()
	assert.Equal(t, int64(100), snap.EventCount)
	assert.Equal(t, int64(100), snap.SyscallReadCount)
	assert.Equal(t, int64(1000), snap.SyscallReadBytes)
}

func TestBucket_Snapshot_IsPointInTime(t *testing.T) {
	b := NewBucket(42, time.Now())

	b.Add(tracer.ParsedEvent{
		Raw: tracer.Event{Type: tracer.EventTypeSyscallRead},
		Typed: tracer.SyscallEvent{
			LatencyNs: 100,
			Return:    10,
		},
	})

	snap1 := b.Snapshot()

	b.Add(tracer.ParsedEvent{
		Raw: tracer.Event{Type: tracer.EventTypeSyscallRead},
		Typed: tracer.SyscallEvent{
			LatencyNs: 200,
			Return:    20,
		},
	})

	snap2 := b.Snapshot()

	// snap1 should not change after more adds.
	assert.Equal(t, int64(1), snap1.SyscallReadCount)
	assert.Equal(t, int64(2), snap2.SyscallReadCount)
}
