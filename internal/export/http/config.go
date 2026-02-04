package http

import (
	"errors"
	"time"
)

// Config configures the HTTP exporter.
type Config struct {
	// Enabled enables the HTTP exporter.
	Enabled bool `yaml:"enabled"`

	// Address is the HTTP endpoint to send data to.
	Address string `yaml:"address"`

	// Headers are additional HTTP headers to include in requests.
	Headers map[string]string `yaml:"headers"`

	// Compression specifies the compression algorithm.
	// Valid values: none, gzip, zstd, zlib, snappy.
	// Defaults to gzip.
	Compression string `yaml:"compression"`

	// BatchSize is the maximum number of items per batch.
	// Defaults to 512.
	BatchSize int `yaml:"batch_size"`

	// BatchTimeout is the maximum duration to wait before sending a batch.
	// Defaults to 5s.
	BatchTimeout time.Duration `yaml:"batch_timeout"`

	// ExportTimeout is the maximum duration for an export operation.
	// Defaults to 30s.
	ExportTimeout time.Duration `yaml:"export_timeout"`

	// MaxQueueSize is the maximum number of items to queue.
	// Items are dropped if the queue is full.
	// Defaults to 51200.
	MaxQueueSize int `yaml:"max_queue_size"`

	// Workers is the number of concurrent workers.
	// Defaults to 1.
	Workers int `yaml:"workers"`

	// KeepAlive enables HTTP keep-alive connections.
	// Defaults to true.
	KeepAlive *bool `yaml:"keep_alive"`

	// MetaClientName is added to exported events.
	MetaClientName string `yaml:"meta_client_name"`

	// MetaNetworkName is added to exported events.
	MetaNetworkName string `yaml:"meta_network_name"`
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	keepAlive := true

	return Config{
		Compression:   CompressionGzip,
		BatchSize:     512,
		BatchTimeout:  5 * time.Second,
		ExportTimeout: 30 * time.Second,
		MaxQueueSize:  51200,
		Workers:       1,
		KeepAlive:     &keepAlive,
	}
}

// Validate validates the configuration.
func (c *Config) Validate() error {
	if !c.Enabled {
		return nil
	}

	if c.Address == "" {
		return errors.New("http address is required when enabled")
	}

	if c.BatchSize <= 0 {
		return errors.New("batch_size must be greater than 0")
	}

	if c.MaxQueueSize <= 0 {
		return errors.New("max_queue_size must be greater than 0")
	}

	if c.BatchSize > c.MaxQueueSize {
		return errors.New("batch_size cannot be greater than max_queue_size")
	}

	if c.Workers <= 0 {
		return errors.New("workers must be greater than 0")
	}

	if c.Compression != "" {
		switch c.Compression {
		case CompressionNone, CompressionGzip, CompressionZstd,
			CompressionZlib, CompressionSnappy:
			// Valid.
		default:
			return errors.New("invalid compression type: " + c.Compression)
		}
	}

	return nil
}

// ApplyDefaults applies default values to unset fields.
func (c *Config) ApplyDefaults() {
	defaults := DefaultConfig()

	if c.Compression == "" {
		c.Compression = defaults.Compression
	}

	if c.BatchSize <= 0 {
		c.BatchSize = defaults.BatchSize
	}

	if c.BatchTimeout <= 0 {
		c.BatchTimeout = defaults.BatchTimeout
	}

	if c.ExportTimeout <= 0 {
		c.ExportTimeout = defaults.ExportTimeout
	}

	if c.MaxQueueSize <= 0 {
		c.MaxQueueSize = defaults.MaxQueueSize
	}

	if c.Workers <= 0 {
		c.Workers = defaults.Workers
	}

	if c.KeepAlive == nil {
		c.KeepAlive = defaults.KeepAlive
	}
}

// IsKeepAlive returns whether HTTP keep-alive is enabled.
func (c *Config) IsKeepAlive() bool {
	if c.KeepAlive == nil {
		return true
	}

	return *c.KeepAlive
}
