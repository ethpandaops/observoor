package aggregated

import (
	"time"

	"github.com/ethpandaops/observoor/internal/export"
)

// Config configures the aggregated metrics sink.
type Config struct {
	// Enabled enables the aggregated metrics sink.
	Enabled bool `yaml:"enabled"`

	// Resolution configures the aggregation time window.
	Resolution ResolutionConfig `yaml:"resolution"`

	// Dimensions configures which dimensions to include.
	Dimensions DimensionsConfig `yaml:"dimensions"`

	// ClickHouse configures the ClickHouse connection.
	ClickHouse export.ClickHouseConfig `yaml:"clickhouse"`
}

// ResolutionConfig configures aggregation time windows.
type ResolutionConfig struct {
	// Interval is the aggregation window duration.
	// Common values: 50ms, 100ms, 500ms, 1s, 5s, 1m.
	// Defaults to 1s.
	Interval time.Duration `yaml:"interval"`

	// SlotAligned resets aggregation windows at slot boundaries.
	// When true, the first interval after a slot change may be shorter.
	// Defaults to true.
	SlotAligned bool `yaml:"slot_aligned"`

	// SyncStatePollInterval is the interval for writing sync state.
	// Defaults to 12s (1 Ethereum slot).
	SyncStatePollInterval time.Duration `yaml:"sync_state_poll_interval"`
}

// DimensionsConfig configures which dimensions to include in aggregations.
type DimensionsConfig struct {
	// Network configures network metric dimensions.
	Network NetworkDimensionsConfig `yaml:"network"`

	// Disk configures disk metric dimensions.
	Disk DiskDimensionsConfig `yaml:"disk"`
}

// NetworkDimensionsConfig configures network metric dimensions.
type NetworkDimensionsConfig struct {
	// Port includes local port in network metrics.
	// When true, ports are filtered to well-known ports discovered from
	// process command lines (or defaults per client type).
	// Defaults to true.
	Port *bool `yaml:"include_port"`

	// Direction includes TX/RX direction in network metrics.
	// Defaults to true.
	Direction *bool `yaml:"include_direction"`

	// portWhitelist is set at runtime with discovered ports.
	// Not configurable via YAML - auto-discovered from processes.
	portWhitelist map[uint16]struct{}
}

// DiskDimensionsConfig configures disk metric dimensions.
type DiskDimensionsConfig struct {
	// Device includes block device ID in disk metrics.
	// Defaults to true.
	Device *bool `yaml:"include_device"`

	// RW includes read/write breakdown in disk metrics.
	// Defaults to true.
	RW *bool `yaml:"include_rw"`
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Resolution: ResolutionConfig{
			Interval:              time.Second,
			SlotAligned:           true,
			SyncStatePollInterval: 12 * time.Second,
		},
		Dimensions: DimensionsConfig{
			Network: NetworkDimensionsConfig{},
			Disk:    DiskDimensionsConfig{},
		},
		ClickHouse: export.ClickHouseConfig{
			Database:      "default",
			Table:         "aggregated_metrics",
			BatchSize:     10000,
			FlushInterval: time.Second,
		},
	}
}

// IncludePort returns whether to include port in network dimensions.
func (c *NetworkDimensionsConfig) IncludePort() bool {
	if c.Port == nil {
		return true
	}

	return *c.Port
}

// SetPortWhitelist sets the runtime port whitelist.
// Only ports in this set will be tracked; others will be recorded as port 0.
func (c *NetworkDimensionsConfig) SetPortWhitelist(ports map[uint16]struct{}) {
	c.portWhitelist = ports
}

// FilterPort returns the port if it's in the whitelist, or 0 otherwise.
// If no whitelist is set, returns the port unchanged.
func (c *NetworkDimensionsConfig) FilterPort(port uint16) uint16 {
	if c.portWhitelist == nil || len(c.portWhitelist) == 0 {
		return port
	}

	if _, ok := c.portWhitelist[port]; ok {
		return port
	}

	return 0
}

// IncludeDirection returns whether to include direction in network dimensions.
func (c *NetworkDimensionsConfig) IncludeDirection() bool {
	if c.Direction == nil {
		return true
	}

	return *c.Direction
}

// IncludeDevice returns whether to include device ID in disk dimensions.
func (c *DiskDimensionsConfig) IncludeDevice() bool {
	if c.Device == nil {
		return true
	}

	return *c.Device
}

// IncludeRW returns whether to include read/write in disk dimensions.
func (c *DiskDimensionsConfig) IncludeRW() bool {
	if c.RW == nil {
		return true
	}

	return *c.RW
}
