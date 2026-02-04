// Package http provides an HTTP exporter for streaming events to Vector or other HTTP sinks.
package http

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	processor "github.com/ethpandaops/go-batch-processor"
	"github.com/sirupsen/logrus"
)

// Exporter implements processor.ItemExporter for HTTP NDJSON export.
type Exporter[T any] struct {
	cfg        Config
	client     *http.Client
	compressor *Compressor
	log        logrus.FieldLogger
}

// compile-time check that Exporter implements ItemExporter.
var _ processor.ItemExporter[any] = (*Exporter[any])(nil)

// NewExporter creates a new HTTP exporter.
func NewExporter[T any](log logrus.FieldLogger, cfg Config) (*Exporter[T], error) {
	cfg.ApplyDefaults()

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	compressor, err := NewCompressor(cfg.Compression)
	if err != nil {
		return nil, fmt.Errorf("creating compressor: %w", err)
	}

	transport := &http.Transport{
		MaxIdleConns:        cfg.Workers * 2,
		MaxIdleConnsPerHost: cfg.Workers * 2,
		IdleConnTimeout:     90 * time.Second,
		DisableKeepAlives:   !cfg.IsKeepAlive(),
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   cfg.ExportTimeout,
	}

	return &Exporter[T]{
		cfg:        cfg,
		client:     client,
		compressor: compressor,
		log:        log.WithField("component", "http_exporter"),
	}, nil
}

// ExportItems exports a batch of items to the HTTP endpoint as NDJSON.
func (e *Exporter[T]) ExportItems(ctx context.Context, items []*T) error {
	if len(items) == 0 {
		return nil
	}

	// Marshal items to NDJSON (newline-delimited JSON).
	var buf bytes.Buffer
	buf.Grow(len(items) * 256) // Pre-allocate based on estimated size.

	encoder := json.NewEncoder(&buf)

	for _, item := range items {
		if item == nil {
			continue
		}

		if err := encoder.Encode(item); err != nil {
			return fmt.Errorf("encoding item: %w", err)
		}
	}

	data := buf.Bytes()

	// Compress if configured.
	compressed, err := e.compressor.Compress(data)
	if err != nil {
		return fmt.Errorf("compressing data: %w", err)
	}

	// Create request.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.cfg.Address, bytes.NewReader(compressed))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-ndjson")

	if encoding := e.compressor.ContentEncoding(); encoding != "" {
		req.Header.Set("Content-Encoding", encoding)
	}

	// Add custom headers.
	for k, v := range e.cfg.Headers {
		req.Header.Set(k, v)
	}

	// Send request.
	resp, err := e.client.Do(req)
	if err != nil {
		return fmt.Errorf("sending request: %w", err)
	}

	defer resp.Body.Close()

	// Drain response body to enable connection reuse.
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	e.log.WithFields(logrus.Fields{
		"items":      len(items),
		"bytes":      len(data),
		"compressed": len(compressed),
	}).Debug("Exported batch via HTTP")

	return nil
}

// Shutdown shuts down the exporter.
func (e *Exporter[T]) Shutdown(_ context.Context) error {
	if e.compressor != nil {
		return e.compressor.Close()
	}

	return nil
}

// NewProcessor creates a BatchItemProcessor with this exporter.
func NewProcessor[T any](
	log logrus.FieldLogger,
	cfg Config,
	name string,
) (*processor.BatchItemProcessor[T], error) {
	exporter, err := NewExporter[T](log, cfg)
	if err != nil {
		return nil, fmt.Errorf("creating exporter: %w", err)
	}

	proc, err := processor.NewBatchItemProcessor[T](
		exporter,
		name,
		log,
		processor.WithMaxQueueSize(cfg.MaxQueueSize),
		processor.WithBatchTimeout(cfg.BatchTimeout),
		processor.WithExportTimeout(cfg.ExportTimeout),
		processor.WithMaxExportBatchSize(cfg.BatchSize),
		processor.WithWorkers(cfg.Workers),
	)
	if err != nil {
		return nil, fmt.Errorf("creating processor: %w", err)
	}

	return proc, nil
}
