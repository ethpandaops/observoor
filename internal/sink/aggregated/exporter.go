package aggregated

import "context"

// MetricExporter exports collected metrics to a destination.
type MetricExporter interface {
	// Name returns the exporter's identifier for logging.
	Name() string
	// Start initializes the exporter.
	Start(ctx context.Context) error
	// Export writes a batch of metrics to the destination.
	Export(ctx context.Context, batch MetricBatch) error
	// Stop shuts down the exporter gracefully.
	Stop() error
}
