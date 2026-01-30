package agent

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ethpandaops/observoor/internal/pid"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	assert.Equal(t, "info", cfg.LogLevel)
	assert.Equal(t, ":9090", cfg.Health.Addr)
	assert.Equal(t, 4*1024*1024, cfg.RingBufferSize)
}

func TestLoadConfig(t *testing.T) {
	yaml := `
log_level: debug
beacon:
  endpoint: "http://localhost:3500"
  timeout: 5s
pid:
  process_names:
    - geth
    - prysm
  cgroup_path: "/sys/fs/cgroup/ethereum.slice"
sinks:
  raw:
    enabled: false
  slot:
    enabled: true
  window:
    enabled: false
    interval: 500ms
health:
  addr: ":9091"
sync_poll_interval: 15s
ring_buffer_size: 8388608
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(yaml), 0o644))

	cfg, err := LoadConfig(path)
	require.NoError(t, err)

	assert.Equal(t, "debug", cfg.LogLevel)
	assert.Equal(t, "http://localhost:3500", cfg.Beacon.Endpoint)
	assert.Equal(t, []string{"geth", "prysm"}, cfg.PID.ProcessNames)
	assert.Equal(t,
		"/sys/fs/cgroup/ethereum.slice",
		cfg.PID.CgroupPath,
	)
	assert.True(t, cfg.Sinks.Slot.Enabled)
	assert.False(t, cfg.Sinks.Raw.Enabled)
	assert.Equal(t, ":9091", cfg.Health.Addr)
	assert.Equal(t, 8388608, cfg.RingBufferSize)
}

func TestLoadConfig_MissingFile(t *testing.T) {
	_, err := LoadConfig("/nonexistent/path.yaml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reading config file")
}

func TestLoadConfig_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	// Use a tab character at the start which is invalid YAML indentation.
	require.NoError(t, os.WriteFile(path, []byte("\t- bad"), 0o644))

	_, err := LoadConfig(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parsing config file")
}

func TestValidate_MissingBeaconEndpoint(t *testing.T) {
	cfg := DefaultConfig()
	cfg.PID.ProcessNames = []string{"geth"}

	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "beacon.endpoint is required")
}

func TestValidate_DefaultsPIDConfig(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Beacon.Endpoint = "http://localhost:3500"

	// When no PID config is specified, Validate should apply defaults.
	err := cfg.Validate()
	require.NoError(t, err)
	assert.Equal(t, pid.DefaultProcessNames, cfg.PID.ProcessNames)
}

func TestValidate_InvalidRingBufferSize(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Beacon.Endpoint = "http://localhost:3500"
	cfg.PID.ProcessNames = []string{"geth"}
	cfg.RingBufferSize = 0

	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ring_buffer_size must be positive")
}

func TestValidate_ValidConfig(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Beacon.Endpoint = "http://localhost:3500"
	cfg.PID.ProcessNames = []string{"geth"}

	err := cfg.Validate()
	require.NoError(t, err)
}

func TestValidate_CgroupPathOnly(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Beacon.Endpoint = "http://localhost:3500"
	cfg.PID.CgroupPath = "/sys/fs/cgroup/test"

	err := cfg.Validate()
	require.NoError(t, err)
}
