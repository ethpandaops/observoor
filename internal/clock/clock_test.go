package clock

import (
	"context"
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

func TestNew_ValidParams(t *testing.T) {
	genesis := time.Date(2023, 9, 28, 12, 0, 0, 0, time.UTC)

	clk, err := New(testLog(), genesis, 12, 32)
	require.NoError(t, err)
	assert.NotNil(t, clk)
}

func TestNew_ZeroSecondsPerSlot(t *testing.T) {
	genesis := time.Date(2023, 9, 28, 12, 0, 0, 0, time.UTC)

	_, err := New(testLog(), genesis, 0, 32)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "secondsPerSlot must be > 0")
}

func TestNew_ZeroSlotsPerEpoch(t *testing.T) {
	genesis := time.Date(2023, 9, 28, 12, 0, 0, 0, time.UTC)

	_, err := New(testLog(), genesis, 12, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "slotsPerEpoch must be > 0")
}

func TestSlotStartTime(t *testing.T) {
	genesis := time.Date(2023, 9, 28, 12, 0, 0, 0, time.UTC)

	clk, err := New(testLog(), genesis, 12, 32)
	require.NoError(t, err)

	tests := []struct {
		slot uint64
		want time.Time
	}{
		{slot: 0, want: genesis},
		{slot: 1, want: genesis.Add(12 * time.Second)},
		{slot: 10, want: genesis.Add(120 * time.Second)},
		{slot: 100, want: genesis.Add(1200 * time.Second)},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.want, clk.SlotStartTime(tt.slot),
			"slot %d", tt.slot)
	}
}

func TestCurrentSlot(t *testing.T) {
	// Set genesis to a known time in the past.
	now := time.Now()
	genesis := now.Add(-120 * time.Second) // 120s ago

	clk, err := New(testLog(), genesis, 12, 32)
	require.NoError(t, err)

	slot := clk.CurrentSlot()
	// 120s / 12s = slot 10 (approximately).
	assert.InDelta(t, 10, slot, 1)
}

func TestOnSlotChanged(t *testing.T) {
	genesis := time.Now().Add(-1 * time.Second)

	clk, err := New(testLog(), genesis, 1, 32) // 1s slots for fast test
	require.NoError(t, err)

	slotCh := make(chan uint64, 1)
	clk.OnSlotChanged(func(slot uint64) {
		select {
		case slotCh <- slot:
		default:
		}
	})

	ctx, cancel := context.WithTimeout(
		context.Background(), 5*time.Second,
	)
	defer cancel()

	require.NoError(t, clk.Start(ctx))
	defer clk.Stop()

	select {
	case slot := <-slotCh:
		assert.Greater(t, slot, uint64(0))
	case <-ctx.Done():
		t.Fatal("timed out waiting for slot change")
	}
}

func TestMillisIntoSlot(t *testing.T) {
	genesis := time.Now().Add(-6 * time.Second)

	clk, err := New(testLog(), genesis, 12, 32)
	require.NoError(t, err)

	millis := clk.MillisIntoSlot()
	// We're about 6 seconds into a 12-second slot.
	assert.InDelta(t, 6000, millis, 500)
}

func TestStopIdempotent(t *testing.T) {
	genesis := time.Now()

	clk, err := New(testLog(), genesis, 12, 32)
	require.NoError(t, err)

	// Stop without Start should not panic.
	assert.NoError(t, clk.Stop())
	assert.NoError(t, clk.Stop())
}
