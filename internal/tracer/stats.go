package tracer

import "sync/atomic"

// EventStats provides lock-free per-EventType counters.
// Snapshot atomically reads and resets all counters, making it
// suitable for periodic reporting without contention.
type EventStats struct {
	counts [maxEventType + 1]atomic.Uint64
}

// NewEventStats creates a new EventStats instance.
func NewEventStats() *EventStats {
	return &EventStats{}
}

// Record increments the counter for the given event type by one.
func (s *EventStats) Record(t EventType) {
	if t > maxEventType {
		return
	}

	s.counts[t].Add(1)
}

// RecordN increments the counter for the given event type by n.
func (s *EventStats) RecordN(t EventType, n uint64) {
	if t > maxEventType {
		return
	}

	s.counts[t].Add(n)
}

// Snapshot atomically reads and resets all counters, returning
// a map of only non-zero entries.
func (s *EventStats) Snapshot() map[EventType]uint64 {
	result := make(map[EventType]uint64, maxEventType)

	for i := range s.counts {
		v := s.counts[i].Swap(0)
		if v > 0 {
			result[EventType(i)] = v
		}
	}

	return result
}
