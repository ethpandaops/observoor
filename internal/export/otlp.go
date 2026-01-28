package export

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
)

// OTLPConfig configures the OTLP metric exporter.
type OTLPConfig struct {
	// Endpoint is the gRPC OTLP endpoint (e.g. "otel-collector:4317").
	Endpoint string `yaml:"endpoint"`

	// Insecure disables TLS for the gRPC connection.
	Insecure bool `yaml:"insecure"`
}

// OTLPExporter manages the OTLP metric export pipeline.
type OTLPExporter struct {
	log      logrus.FieldLogger
	cfg      OTLPConfig
	provider *metric.MeterProvider
	exporter metric.Exporter
}

// NewOTLPExporter creates a new OTLP metric exporter.
func NewOTLPExporter(
	log logrus.FieldLogger,
	cfg OTLPConfig,
) *OTLPExporter {
	return &OTLPExporter{
		log: log.WithField("component", "otlp"),
		cfg: cfg,
	}
}

// Start initializes the OTLP exporter and meter provider.
func (e *OTLPExporter) Start(ctx context.Context) error {
	opts := []otlpmetricgrpc.Option{
		otlpmetricgrpc.WithEndpoint(e.cfg.Endpoint),
	}

	if e.cfg.Insecure {
		opts = append(opts, otlpmetricgrpc.WithInsecure())
	}

	exporter, err := otlpmetricgrpc.New(ctx, opts...)
	if err != nil {
		return fmt.Errorf("creating OTLP exporter: %w", err)
	}

	e.exporter = exporter

	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName("observoor"),
		),
	)
	if err != nil {
		return fmt.Errorf("creating OTLP resource: %w", err)
	}

	e.provider = metric.NewMeterProvider(
		metric.WithResource(res),
		metric.WithReader(metric.NewPeriodicReader(exporter)),
	)

	e.log.WithField("endpoint", e.cfg.Endpoint).
		Info("OTLP exporter started")

	return nil
}

// MeterProvider returns the configured meter provider for
// creating metrics.
func (e *OTLPExporter) MeterProvider() *metric.MeterProvider {
	return e.provider
}

// Stop shuts down the OTLP exporter.
func (e *OTLPExporter) Stop(ctx context.Context) error {
	if e.provider != nil {
		if err := e.provider.Shutdown(ctx); err != nil {
			return fmt.Errorf("shutting down OTLP provider: %w", err)
		}
	}

	if e.exporter != nil {
		if err := e.exporter.Shutdown(ctx); err != nil {
			return fmt.Errorf("shutting down OTLP exporter: %w", err)
		}
	}

	return nil
}
