package agent

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/ethpandaops/observoor/internal/beacon"
	"github.com/ethpandaops/observoor/internal/export"
	"github.com/ethpandaops/observoor/internal/pid"
	"github.com/ethpandaops/observoor/internal/sink"
)

// Config is the top-level configuration for the observoor agent.
type Config struct {
	// LogLevel sets the logging verbosity (debug, info, warn, error).
	LogLevel string `yaml:"log_level"`

	// Beacon configures the CL beacon node connection.
	Beacon beacon.Config `yaml:"beacon"`

	// PID configures process discovery.
	PID pid.Config `yaml:"pid"`

	// Sinks configures data export sinks.
	Sinks sink.Config `yaml:"sinks"`

	// Health configures the Prometheus health metrics server.
	Health export.HealthConfig `yaml:"health"`

	// SyncPollInterval is how often to poll the beacon node
	// for sync state. Defaults to 30s.
	SyncPollInterval time.Duration `yaml:"sync_poll_interval"`

	// RingBufferSize is the BPF ring buffer size in bytes.
	// Defaults to 4MB.
	RingBufferSize int `yaml:"ring_buffer_size"`
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		LogLevel:         "info",
		SyncPollInterval: 30 * time.Second,
		RingBufferSize:   4 * 1024 * 1024, // 4MB
		Health: export.HealthConfig{
			Addr: ":9090",
		},
	}
}

// LoadConfig reads and parses a YAML configuration file.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file %s: %w", path, err)
	}

	cfg := DefaultConfig()

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config file %s: %w", path, err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}

	return cfg, nil
}

// Validate checks the configuration for required fields and consistency.
func (c *Config) Validate() error {
	if c.Beacon.Endpoint == "" {
		return fmt.Errorf("beacon.endpoint is required")
	}

	if c.PID.ProcessNames == nil && c.PID.CgroupPath == "" {
		return fmt.Errorf(
			"at least one of pid.process_names or pid.cgroup_path is required",
		)
	}

	if c.RingBufferSize <= 0 {
		return fmt.Errorf("ring_buffer_size must be positive")
	}

	return nil
}
