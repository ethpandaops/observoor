package tracer

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEventStats_Record(t *testing.T) {
	s := NewEventStats()

	s.Record(EventTypeSyscallRead)
	s.Record(EventTypeSyscallRead)
	s.Record(EventTypeNetTX)

	snap := s.Snapshot()
	assert.Equal(t, uint64(2), snap[EventTypeSyscallRead])
	assert.Equal(t, uint64(1), snap[EventTypeNetTX])
	assert.Len(t, snap, 2)
}

func TestEventStats_RecordN(t *testing.T) {
	s := NewEventStats()

	s.RecordN(EventTypeDiskIO, 100)
	s.RecordN(EventTypeDiskIO, 50)

	snap := s.Snapshot()
	assert.Equal(t, uint64(150), snap[EventTypeDiskIO])
}

func TestEventStats_SnapshotResetsCounters(t *testing.T) {
	s := NewEventStats()

	s.Record(EventTypeSyscallRead)
	s.Record(EventTypeNetTX)

	snap1 := s.Snapshot()
	require.Len(t, snap1, 2)

	// Second snapshot should be empty since counters were reset.
	snap2 := s.Snapshot()
	assert.Len(t, snap2, 0)
}

func TestEventStats_SnapshotEmptyReturnsEmpty(t *testing.T) {
	s := NewEventStats()

	snap := s.Snapshot()
	assert.Len(t, snap, 0)
}

func TestEventStats_BoundsCheck(t *testing.T) {
	s := NewEventStats()

	// Out-of-bounds event type should be silently ignored.
	s.Record(EventType(255))
	s.RecordN(EventType(100), 50)

	snap := s.Snapshot()
	assert.Len(t, snap, 0)
}

func TestEventStats_AllEventTypes(t *testing.T) {
	s := NewEventStats()

	// Record one of each known event type.
	for i := EventType(1); i <= MaxEventType; i++ {
		s.Record(i)
	}

	snap := s.Snapshot()
	assert.Len(t, snap, int(MaxEventType))

	for i := EventType(1); i <= MaxEventType; i++ {
		assert.Equal(t, uint64(1), snap[i], "event type %d", i)
	}
}

func TestEventStats_ConcurrentAccess(t *testing.T) {
	s := NewEventStats()

	const goroutines = 100
	const iterations = 1000

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for range goroutines {
		go func() {
			defer wg.Done()

			for range iterations {
				s.Record(EventTypeSyscallRead)
				s.Record(EventTypeNetTX)
			}
		}()
	}

	wg.Wait()

	snap := s.Snapshot()
	assert.Equal(t, uint64(goroutines*iterations), snap[EventTypeSyscallRead])
	assert.Equal(t, uint64(goroutines*iterations), snap[EventTypeNetTX])
}
