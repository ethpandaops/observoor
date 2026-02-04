package aggregated

import "time"

// WindowInfo contains time window metadata for aggregated metrics.
type WindowInfo struct {
	Start      time.Time
	IntervalMs uint16
}

// SlotInfo contains Ethereum slot metadata.
type SlotInfo struct {
	Number    uint32
	StartTime time.Time
}

// BatchMetadata contains export-time metadata.
type BatchMetadata struct {
	ClientName  string
	NetworkName string
	UpdatedTime time.Time
}

// LatencyMetric is the exporter-agnostic latency data.
type LatencyMetric struct {
	MetricType string
	Window     WindowInfo
	Slot       SlotInfo
	PID        uint32
	ClientType string
	// Optional dimensions (nil = not applicable).
	DeviceID *uint32
	RW       *string
	// Values.
	Sum       int64
	Count     uint32
	Min       int64
	Max       int64
	Histogram []uint32
}

// CounterMetric is the exporter-agnostic counter data.
type CounterMetric struct {
	MetricType string
	Window     WindowInfo
	Slot       SlotInfo
	PID        uint32
	ClientType string
	// Optional dimensions.
	DeviceID  *uint32
	RW        *string
	LocalPort *uint16
	Direction *string
	// Values.
	Sum   int64
	Count uint32
}

// GaugeMetric is the exporter-agnostic gauge data.
type GaugeMetric struct {
	MetricType string
	Window     WindowInfo
	Slot       SlotInfo
	PID        uint32
	ClientType string
	// Optional dimensions.
	DeviceID  *uint32
	RW        *string
	LocalPort *uint16
	// Values.
	Sum   int64
	Count uint32
	Min   int64
	Max   int64
}

// MetricBatch contains all metrics collected in one flush cycle.
type MetricBatch struct {
	Metadata BatchMetadata
	Latency  []LatencyMetric
	Counter  []CounterMetric
	Gauge    []GaugeMetric
}

// TotalMetrics returns the total number of metrics in the batch.
func (b *MetricBatch) TotalMetrics() int {
	return len(b.Latency) + len(b.Counter) + len(b.Gauge)
}
