package aggregated

import (
	"math"
	"sync/atomic"
)

// LatencyAggregate tracks latency statistics with histogram.
// Used for syscalls, disk I/O latency, memory latency, etc.
// All operations are atomic and safe for concurrent use.
type LatencyAggregate struct {
	sum       atomic.Int64
	count     atomic.Uint64
	min       atomic.Int64
	max       atomic.Int64
	histogram Histogram
}

// NewLatencyAggregate creates a new LatencyAggregate with initial min/max values.
func NewLatencyAggregate() *LatencyAggregate {
	a := &LatencyAggregate{}
	a.min.Store(math.MaxInt64)
	a.max.Store(math.MinInt64)

	return a
}

// Add records a latency value in nanoseconds.
func (a *LatencyAggregate) Add(valueNs uint64) {
	val := int64(valueNs)
	a.sum.Add(val)
	a.count.Add(1)
	a.histogram.Add(valueNs)

	// CAS loop for min.
	for {
		oldMin := a.min.Load()
		if val >= oldMin {
			break
		}

		if a.min.CompareAndSwap(oldMin, val) {
			break
		}
	}

	// CAS loop for max.
	for {
		oldMax := a.max.Load()
		if val <= oldMax {
			break
		}

		if a.max.CompareAndSwap(oldMax, val) {
			break
		}
	}
}

// LatencySnapshot represents a point-in-time view of latency statistics.
type LatencySnapshot struct {
	Sum       int64
	Count     uint64
	Min       int64
	Max       int64
	Histogram [numBuckets]uint64
}

// Snapshot returns the current statistics.
func (a *LatencyAggregate) Snapshot() LatencySnapshot {
	count := a.count.Load()
	minVal := a.min.Load()
	maxVal := a.max.Load()

	// Handle case where no values were added.
	if count == 0 {
		minVal = 0
		maxVal = 0
	}

	return LatencySnapshot{
		Sum:       a.sum.Load(),
		Count:     count,
		Min:       minVal,
		Max:       maxVal,
		Histogram: a.histogram.Snapshot(),
	}
}

// CounterAggregate tracks count and sum for counter-type metrics.
// Used for network bytes, FD operations, etc.
// All operations are atomic and safe for concurrent use.
type CounterAggregate struct {
	count atomic.Uint64
	sum   atomic.Int64
}

// NewCounterAggregate creates a new CounterAggregate.
func NewCounterAggregate() *CounterAggregate {
	return &CounterAggregate{}
}

// Add records a value (typically bytes).
func (a *CounterAggregate) Add(value int64) {
	a.count.Add(1)
	a.sum.Add(value)
}

// AddCount increments only the count.
func (a *CounterAggregate) AddCount(n uint64) {
	a.count.Add(n)
}

// CounterSnapshot represents a point-in-time view of counter statistics.
type CounterSnapshot struct {
	Count uint64
	Sum   int64
}

// Snapshot returns the current statistics.
func (a *CounterAggregate) Snapshot() CounterSnapshot {
	return CounterSnapshot{
		Count: a.count.Load(),
		Sum:   a.sum.Load(),
	}
}

// GaugeAggregate tracks statistics for gauge-type metrics.
// Used for TCP RTT, CWND, queue depth, etc.
// All operations are atomic and safe for concurrent use.
type GaugeAggregate struct {
	sum   atomic.Int64
	count atomic.Uint64
	min   atomic.Int64
	max   atomic.Int64
}

// NewGaugeAggregate creates a new GaugeAggregate with initial min/max values.
func NewGaugeAggregate() *GaugeAggregate {
	a := &GaugeAggregate{}
	a.min.Store(math.MaxInt64)
	a.max.Store(math.MinInt64)

	return a
}

// Add records a gauge value.
func (a *GaugeAggregate) Add(value int64) {
	a.sum.Add(value)
	a.count.Add(1)

	// CAS loop for min.
	for {
		oldMin := a.min.Load()
		if value >= oldMin {
			break
		}

		if a.min.CompareAndSwap(oldMin, value) {
			break
		}
	}

	// CAS loop for max.
	for {
		oldMax := a.max.Load()
		if value <= oldMax {
			break
		}

		if a.max.CompareAndSwap(oldMax, value) {
			break
		}
	}
}

// GaugeSnapshot represents a point-in-time view of gauge statistics.
type GaugeSnapshot struct {
	Sum   int64
	Count uint64
	Min   int64
	Max   int64
}

// Snapshot returns the current statistics.
func (a *GaugeAggregate) Snapshot() GaugeSnapshot {
	count := a.count.Load()
	minVal := a.min.Load()
	maxVal := a.max.Load()

	// Handle case where no values were added.
	if count == 0 {
		minVal = 0
		maxVal = 0
	}

	return GaugeSnapshot{
		Sum:   a.sum.Load(),
		Count: count,
		Min:   minVal,
		Max:   maxVal,
	}
}
