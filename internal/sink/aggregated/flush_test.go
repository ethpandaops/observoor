package aggregated

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMakeLatencyRow_HistogramConversion(t *testing.T) {
	f := &flusher{
		updatedDateTime:            time.Now(),
		intervalMs:                 1000,
		wallclockSlot:              12345,
		wallclockSlotStartDateTime: time.Now(),
		buf: &Buffer{
			StartTime: time.Now(),
		},
	}

	dim := BasicDimension{
		PID:        1234,
		ClientType: "geth",
	}

	// Create a snapshot with known histogram values.
	snap := LatencySnapshot{
		Sum:   1000000,
		Count: 100,
		Min:   100,
		Max:   50000,
		Histogram: [10]uint64{
			10, 20, 30, 15, 10,
			5, 3, 2, 1, 4,
		},
	}

	row := f.makeLatencyRow(dim, snap)

	// Verify basic fields.
	assert.Equal(t, uint32(1234), row.PID)
	assert.Equal(t, "geth", row.ClientType)
	assert.Equal(t, int64(1000000), row.Sum)
	assert.Equal(t, uint32(100), row.Count)
	assert.Equal(t, int64(100), row.Min)
	assert.Equal(t, int64(50000), row.Max)

	// Verify histogram conversion from uint64 to uint32.
	expected := []uint32{10, 20, 30, 15, 10, 5, 3, 2, 1, 4}
	assert.Equal(t, expected, row.Histogram)
}

func TestMakeLatencyRow_HistogramZeroValues(t *testing.T) {
	f := &flusher{
		updatedDateTime:            time.Now(),
		intervalMs:                 1000,
		wallclockSlot:              12345,
		wallclockSlotStartDateTime: time.Now(),
		buf: &Buffer{
			StartTime: time.Now(),
		},
	}

	dim := BasicDimension{
		PID:        1234,
		ClientType: "reth",
	}

	// Snapshot with all zero histogram buckets.
	snap := LatencySnapshot{
		Sum:       0,
		Count:     0,
		Min:       0,
		Max:       0,
		Histogram: [10]uint64{0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	}

	row := f.makeLatencyRow(dim, snap)

	expected := []uint32{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	assert.Equal(t, expected, row.Histogram)
}

func TestMakeLatencyRow_HistogramLargeValues(t *testing.T) {
	f := &flusher{
		updatedDateTime:            time.Now(),
		intervalMs:                 1000,
		wallclockSlot:              12345,
		wallclockSlotStartDateTime: time.Now(),
		buf: &Buffer{
			StartTime: time.Now(),
		},
	}

	dim := BasicDimension{
		PID:        5678,
		ClientType: "lighthouse",
	}

	// Snapshot with large histogram values (but within uint32 range).
	snap := LatencySnapshot{
		Sum:   9999999999,
		Count: 4294967295, // max uint32
		Min:   1,
		Max:   9999999999,
		Histogram: [10]uint64{
			1000000, 2000000, 3000000, 4000000, 5000000,
			1000000, 500000, 100000, 10000, 1000,
		},
	}

	row := f.makeLatencyRow(dim, snap)

	expected := []uint32{
		1000000, 2000000, 3000000, 4000000, 5000000,
		1000000, 500000, 100000, 10000, 1000,
	}
	assert.Equal(t, expected, row.Histogram)
}

func TestMakeDiskLatencyRow_HistogramConversion(t *testing.T) {
	f := &flusher{
		updatedDateTime:            time.Now(),
		intervalMs:                 1000,
		wallclockSlot:              12345,
		wallclockSlotStartDateTime: time.Now(),
		buf: &Buffer{
			StartTime: time.Now(),
		},
	}

	dim := DiskDimension{
		PID:        1234,
		ClientType: "geth",
		DeviceID:   259,
		ReadWrite:  0, // Read
	}

	snap := LatencySnapshot{
		Sum:   5000000,
		Count: 50,
		Min:   1000,
		Max:   100000,
		Histogram: [10]uint64{
			5, 10, 15, 10, 5,
			3, 1, 1, 0, 0,
		},
	}

	row := f.makeDiskLatencyRow(dim, snap)

	// Verify basic fields.
	assert.Equal(t, uint32(1234), row.PID)
	assert.Equal(t, "geth", row.ClientType)
	assert.Equal(t, uint32(259), row.DeviceID)
	assert.Equal(t, "read", row.RW)

	// Verify embedded latencyRow fields.
	assert.Equal(t, int64(5000000), row.Sum)
	assert.Equal(t, uint32(50), row.Count)
	assert.Equal(t, int64(1000), row.Min)
	assert.Equal(t, int64(100000), row.Max)

	// Verify histogram.
	expected := []uint32{5, 10, 15, 10, 5, 3, 1, 1, 0, 0}
	assert.Equal(t, expected, row.Histogram)
}

func TestMakeDiskLatencyRow_WriteDirection(t *testing.T) {
	f := &flusher{
		updatedDateTime:            time.Now(),
		intervalMs:                 1000,
		wallclockSlot:              12345,
		wallclockSlotStartDateTime: time.Now(),
		buf: &Buffer{
			StartTime: time.Now(),
		},
	}

	dim := DiskDimension{
		PID:        1234,
		ClientType: "reth",
		DeviceID:   259,
		ReadWrite:  1, // Write
	}

	snap := LatencySnapshot{
		Sum:       1000,
		Count:     1,
		Min:       1000,
		Max:       1000,
		Histogram: [10]uint64{0, 0, 0, 1, 0, 0, 0, 0, 0, 0},
	}

	row := f.makeDiskLatencyRow(dim, snap)

	assert.Equal(t, "write", row.RW)
}

func TestLatencyRow_HistogramIndexMapping(t *testing.T) {
	// Test that histogram indices map to expected bucket names:
	// [0]=le_1us, [1]=le_10us, [2]=le_100us, [3]=le_1ms, [4]=le_10ms,
	// [5]=le_100ms, [6]=le_1s, [7]=le_10s, [8]=le_100s, [9]=inf
	f := &flusher{
		updatedDateTime:            time.Now(),
		intervalMs:                 1000,
		wallclockSlot:              12345,
		wallclockSlotStartDateTime: time.Now(),
		buf: &Buffer{
			StartTime: time.Now(),
		},
	}

	dim := BasicDimension{PID: 1, ClientType: "test"}

	// Set each bucket to a unique value to verify ordering.
	snap := LatencySnapshot{
		Sum:   100,
		Count: 10,
		Min:   1,
		Max:   100,
		Histogram: [10]uint64{
			1,  // le_1us (index 0)
			2,  // le_10us (index 1)
			3,  // le_100us (index 2)
			4,  // le_1ms (index 3)
			5,  // le_10ms (index 4)
			6,  // le_100ms (index 5)
			7,  // le_1s (index 6)
			8,  // le_10s (index 7)
			9,  // le_100s (index 8)
			10, // inf (index 9)
		},
	}

	row := f.makeLatencyRow(dim, snap)

	// Verify each bucket is at the expected position.
	require.Len(t, row.Histogram, 10)
	assert.Equal(t, uint32(1), row.Histogram[0], "le_1us bucket")
	assert.Equal(t, uint32(2), row.Histogram[1], "le_10us bucket")
	assert.Equal(t, uint32(3), row.Histogram[2], "le_100us bucket")
	assert.Equal(t, uint32(4), row.Histogram[3], "le_1ms bucket")
	assert.Equal(t, uint32(5), row.Histogram[4], "le_10ms bucket")
	assert.Equal(t, uint32(6), row.Histogram[5], "le_100ms bucket")
	assert.Equal(t, uint32(7), row.Histogram[6], "le_1s bucket")
	assert.Equal(t, uint32(8), row.Histogram[7], "le_10s bucket")
	assert.Equal(t, uint32(9), row.Histogram[8], "le_100s bucket")
	assert.Equal(t, uint32(10), row.Histogram[9], "inf bucket")
}

func TestLatencyRowStruct_HasCorrectHistogramField(t *testing.T) {
	// Verify the struct has a []uint32 Histogram field, not individual fields.
	row := latencyRow{
		Histogram: []uint32{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
	}

	assert.Equal(t, []uint32{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, row.Histogram)
}

func TestDiskLatencyRowStruct_InheritsHistogramField(t *testing.T) {
	// Verify diskLatencyRow inherits Histogram from embedded latencyRow.
	row := diskLatencyRow{
		latencyRow: latencyRow{
			Histogram: []uint32{10, 20, 30, 40, 50, 60, 70, 80, 90, 100},
		},
		DeviceID: 123,
		RW:       "read",
	}

	assert.Equal(t, []uint32{10, 20, 30, 40, 50, 60, 70, 80, 90, 100}, row.Histogram)
	assert.Equal(t, uint32(123), row.DeviceID)
	assert.Equal(t, "read", row.RW)
}
