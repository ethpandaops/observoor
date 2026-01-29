package tracer

import "context"

// EventHandler is called for each parsed event from the ring buffer.
type EventHandler func(event ParsedEvent)
type ErrorHandler func(err error)

type RingbufStats struct {
	UsedBytes int
	SizeBytes int
}

type RingbufStatsHandler func(stats RingbufStats)

// Tracer manages BPF program loading, attachment, and event reading.
type Tracer interface {
	// Start loads BPF programs, attaches hooks, and begins reading
	// events from the ring buffer.
	Start(ctx context.Context) error
	// Stop detaches BPF programs and closes the ring buffer reader.
	Stop() error
	// UpdatePIDs updates the tracked PIDs in the BPF map.
	UpdatePIDs(pids []uint32, clientTypes map[uint32]ClientType) error
	// UpdateTIDs updates the tracked TIDs in the BPF map for
	// on-CPU time tracking. Clears and repopulates tracked_tids
	// and clears sched_on_ts.
	UpdateTIDs(tids []uint32, clientTypes map[uint32]ClientType) error
	// OnEvent registers a handler for parsed events.
	OnEvent(handler EventHandler)
	// OnError registers a handler for read or parse errors.
	OnError(handler ErrorHandler)
	// OnRingbufStats registers a handler for ring buffer usage stats.
	OnRingbufStats(handler RingbufStatsHandler)
}
