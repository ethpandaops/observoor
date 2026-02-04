package aggregated

import (
	"context"
	"time"

	processor "github.com/ethpandaops/go-batch-processor"
	"github.com/sirupsen/logrus"

	httpexport "github.com/ethpandaops/observoor/internal/export/http"
)

// AggregatedMetricJSON is the JSON schema for HTTP export of aggregated metrics.
type AggregatedMetricJSON struct {
	MetricType                 string   `json:"metric_type"`
	UpdatedDateTime            string   `json:"updated_date_time"`
	WindowStart                string   `json:"window_start"`
	IntervalMs                 uint16   `json:"interval_ms"`
	WallclockSlot              uint32   `json:"wallclock_slot"`
	WallclockSlotStartDateTime string   `json:"wallclock_slot_start_date_time"`
	PID                        uint32   `json:"pid"`
	ClientType                 string   `json:"client_type"`
	Sum                        int64    `json:"sum"`
	Count                      uint32   `json:"count"`
	Min                        int64    `json:"min,omitempty"`
	Max                        int64    `json:"max,omitempty"`
	Histogram                  []uint32 `json:"histogram,omitempty"`
	// Dimension fields (optional, depending on metric type).
	LocalPort uint16 `json:"local_port,omitempty"`
	Direction string `json:"direction,omitempty"`
	DeviceID  uint32 `json:"device_id,omitempty"`
	RW        string `json:"rw,omitempty"`
	// Metadata.
	MetaClientName  string `json:"meta_client_name,omitempty"`
	MetaNetworkName string `json:"meta_network_name,omitempty"`
}

// HTTPExporter exports metrics via HTTP (e.g., to Vector).
type HTTPExporter struct {
	log  logrus.FieldLogger
	proc *processor.BatchItemProcessor[AggregatedMetricJSON]
	cfg  httpexport.Config
}

// Ensure HTTPExporter implements MetricExporter.
var _ MetricExporter = (*HTTPExporter)(nil)

// NewHTTPExporter creates a new HTTP exporter.
func NewHTTPExporter(
	log logrus.FieldLogger,
	proc *processor.BatchItemProcessor[AggregatedMetricJSON],
	cfg httpexport.Config,
) *HTTPExporter {
	return &HTTPExporter{
		log:  log.WithField("exporter", "http"),
		proc: proc,
		cfg:  cfg,
	}
}

// Name returns the exporter identifier.
func (e *HTTPExporter) Name() string {
	return "http"
}

// Start initializes the exporter (no-op, processor is started separately).
func (e *HTTPExporter) Start(_ context.Context) error {
	return nil
}

// Stop shuts down the exporter (no-op, processor is stopped separately).
func (e *HTTPExporter) Stop() error {
	return nil
}

// Export writes the metric batch to the HTTP processor.
func (e *HTTPExporter) Export(ctx context.Context, batch MetricBatch) error {
	events := make([]*AggregatedMetricJSON, 0, batch.TotalMetrics())

	// Convert latency metrics.
	for _, m := range batch.Latency {
		events = append(events, e.latencyToJSON(m, batch.Metadata))
	}

	// Convert counter metrics.
	for _, m := range batch.Counter {
		events = append(events, e.counterToJSON(m, batch.Metadata))
	}

	// Convert gauge metrics.
	for _, m := range batch.Gauge {
		events = append(events, e.gaugeToJSON(m, batch.Metadata))
	}

	if len(events) > 0 {
		_ = e.proc.Write(ctx, events)
	}

	return nil
}

// latencyToJSON converts a LatencyMetric to JSON format.
func (e *HTTPExporter) latencyToJSON(m LatencyMetric, meta BatchMetadata) *AggregatedMetricJSON {
	json := &AggregatedMetricJSON{
		MetricType:                 m.MetricType,
		UpdatedDateTime:            meta.UpdatedTime.Format(time.RFC3339Nano),
		WindowStart:                m.Window.Start.Format(time.RFC3339Nano),
		IntervalMs:                 m.Window.IntervalMs,
		WallclockSlot:              m.Slot.Number,
		WallclockSlotStartDateTime: m.Slot.StartTime.Format(time.RFC3339Nano),
		PID:                        m.PID,
		ClientType:                 m.ClientType,
		Sum:                        m.Sum,
		Count:                      m.Count,
		Min:                        m.Min,
		Max:                        m.Max,
		Histogram:                  m.Histogram,
		MetaClientName:             meta.ClientName,
		MetaNetworkName:            meta.NetworkName,
	}

	// Add optional dimensions.
	if m.DeviceID != nil {
		json.DeviceID = *m.DeviceID
	}

	if m.RW != nil {
		json.RW = *m.RW
	}

	return json
}

// counterToJSON converts a CounterMetric to JSON format.
func (e *HTTPExporter) counterToJSON(m CounterMetric, meta BatchMetadata) *AggregatedMetricJSON {
	json := &AggregatedMetricJSON{
		MetricType:                 m.MetricType,
		UpdatedDateTime:            meta.UpdatedTime.Format(time.RFC3339Nano),
		WindowStart:                m.Window.Start.Format(time.RFC3339Nano),
		IntervalMs:                 m.Window.IntervalMs,
		WallclockSlot:              m.Slot.Number,
		WallclockSlotStartDateTime: m.Slot.StartTime.Format(time.RFC3339Nano),
		PID:                        m.PID,
		ClientType:                 m.ClientType,
		Sum:                        m.Sum,
		Count:                      m.Count,
		MetaClientName:             meta.ClientName,
		MetaNetworkName:            meta.NetworkName,
	}

	// Add optional dimensions.
	if m.DeviceID != nil {
		json.DeviceID = *m.DeviceID
	}

	if m.RW != nil {
		json.RW = *m.RW
	}

	if m.LocalPort != nil {
		json.LocalPort = *m.LocalPort
	}

	if m.Direction != nil {
		json.Direction = *m.Direction
	}

	return json
}

// gaugeToJSON converts a GaugeMetric to JSON format.
func (e *HTTPExporter) gaugeToJSON(m GaugeMetric, meta BatchMetadata) *AggregatedMetricJSON {
	json := &AggregatedMetricJSON{
		MetricType:                 m.MetricType,
		UpdatedDateTime:            meta.UpdatedTime.Format(time.RFC3339Nano),
		WindowStart:                m.Window.Start.Format(time.RFC3339Nano),
		IntervalMs:                 m.Window.IntervalMs,
		WallclockSlot:              m.Slot.Number,
		WallclockSlotStartDateTime: m.Slot.StartTime.Format(time.RFC3339Nano),
		PID:                        m.PID,
		ClientType:                 m.ClientType,
		Sum:                        m.Sum,
		Count:                      m.Count,
		Min:                        m.Min,
		Max:                        m.Max,
		MetaClientName:             meta.ClientName,
		MetaNetworkName:            meta.NetworkName,
	}

	// Add optional dimensions.
	if m.DeviceID != nil {
		json.DeviceID = *m.DeviceID
	}

	if m.RW != nil {
		json.RW = *m.RW
	}

	if m.LocalPort != nil {
		json.LocalPort = *m.LocalPort
	}

	return json
}
