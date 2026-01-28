package export

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testLog() logrus.FieldLogger {
	log := logrus.New()
	log.SetLevel(logrus.DebugLevel)

	return log
}

func startHealth(t *testing.T) *HealthMetrics {
	t.Helper()

	h := NewHealthMetrics(testLog(), HealthConfig{
		Addr: "127.0.0.1:0",
	})

	ctx := context.Background()
	require.NoError(t, h.Start(ctx))

	t.Cleanup(func() {
		h.Stop()
	})

	// Give server a moment to start serving.
	time.Sleep(50 * time.Millisecond)

	return h
}

func TestHealthMetrics_StartStop(t *testing.T) {
	h := startHealth(t)
	assert.True(t, h.running.Load())
	assert.NotEmpty(t, h.Addr())
}

func TestHealthMetrics_CounterIncrement(t *testing.T) {
	h := startHealth(t)

	h.EventsReceived.Inc()
	h.EventsReceived.Inc()
	h.EventsReceived.Inc()
	h.EventsDropped.Inc()
	h.PIDsTracked.Set(5)
	h.CurrentSlot.Set(12345)
	h.IsSyncing.Set(0)

	url := fmt.Sprintf("http://%s/metrics", h.Addr())

	resp, err := http.Get(url)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	bodyStr := string(body)
	assert.Contains(t, bodyStr, "observoor_events_received_total 3")
	assert.Contains(t, bodyStr, "observoor_events_dropped_total 1")
	assert.Contains(t, bodyStr, "observoor_pids_tracked 5")
	assert.Contains(t, bodyStr, "observoor_current_slot 12345")
	assert.Contains(t, bodyStr, "observoor_is_syncing 0")
}

func TestHealthMetrics_HealthzResponse(t *testing.T) {
	h := startHealth(t)

	url := fmt.Sprintf("http://%s/healthz", h.Addr())

	resp, err := http.Get(url)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "ok", string(body))
}

func TestHealthMetrics_StopIdempotent(t *testing.T) {
	h := NewHealthMetrics(testLog(), HealthConfig{})

	assert.NoError(t, h.Stop())
	assert.NoError(t, h.Stop())
}

func TestHealthMetrics_AddrBeforeStart(t *testing.T) {
	h := NewHealthMetrics(testLog(), HealthConfig{
		Addr: ":9999",
	})

	// Before Start, Addr returns the configured address.
	assert.Equal(t, ":9999", h.Addr())
}
