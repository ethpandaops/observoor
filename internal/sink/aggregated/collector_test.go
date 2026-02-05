package aggregated

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCollector_HistogramConversion(t *testing.T) {
	c := NewCollector(time.Second)

	buf := NewBuffer(
		time.Now(),
		12345,
		time.Now(),
		false,
		false,
		false,
	)

	// Add a syscall event to populate the buffer.
	dim := BasicDimension{
		PID:        1234,
		ClientType: "geth",
	}
	agg := NewLatencyAggregate()
	// Add values to create known histogram.
	agg.Add(500)      // < 1us
	agg.Add(5000)     // 1us-10us
	agg.Add(50000)    // 10us-100us
	agg.Add(500000)   // 100us-1ms
	agg.Add(5000000)  // 1ms-10ms
	agg.Add(50000000) // 10ms-100ms
	buf.SyscallRead[dim] = agg

	meta := BatchMetadata{
		ClientName:  "test-client",
		NetworkName: "test-network",
		UpdatedTime: time.Now(),
	}

	batch := c.Collect(buf, meta)

	require.Len(t, batch.Latency, 1)
	m := batch.Latency[0]

	// Verify basic fields.
	assert.Equal(t, "syscall_read", m.MetricType)
	assert.Equal(t, uint32(1234), m.PID)
	assert.Equal(t, "geth", m.ClientType)
	assert.Equal(t, uint32(6), m.Count)

	// Verify histogram has 10 buckets.
	require.Len(t, m.Histogram, 10)
	// First 6 buckets should have 1 each.
	assert.Equal(t, uint32(1), m.Histogram[0], "le_1us bucket")
	assert.Equal(t, uint32(1), m.Histogram[1], "le_10us bucket")
	assert.Equal(t, uint32(1), m.Histogram[2], "le_100us bucket")
	assert.Equal(t, uint32(1), m.Histogram[3], "le_1ms bucket")
	assert.Equal(t, uint32(1), m.Histogram[4], "le_10ms bucket")
	assert.Equal(t, uint32(1), m.Histogram[5], "le_100ms bucket")
	// Remaining buckets should be 0.
	assert.Equal(t, uint32(0), m.Histogram[6], "le_1s bucket")
	assert.Equal(t, uint32(0), m.Histogram[7], "le_10s bucket")
	assert.Equal(t, uint32(0), m.Histogram[8], "le_100s bucket")
	assert.Equal(t, uint32(0), m.Histogram[9], "inf bucket")
}

func TestCollector_ZeroCountMetricsSkipped(t *testing.T) {
	c := NewCollector(time.Second)

	buf := NewBuffer(
		time.Now(),
		12345,
		time.Now(),
		false,
		false,
		false,
	)

	// Create an aggregate but don't add any values.
	dim := BasicDimension{
		PID:        1234,
		ClientType: "reth",
	}
	buf.SyscallWrite[dim] = NewLatencyAggregate()

	meta := BatchMetadata{
		ClientName:  "test-client",
		NetworkName: "test-network",
		UpdatedTime: time.Now(),
	}

	batch := c.Collect(buf, meta)

	// Zero-count metrics should be skipped.
	assert.Empty(t, batch.Latency)
}

func TestCollector_DiskLatencyWithDimensions(t *testing.T) {
	c := NewCollector(time.Second)

	buf := NewBuffer(
		time.Now(),
		12345,
		time.Now(),
		false,
		false,
		false,
	)

	dim := DiskDimension{
		PID:        1234,
		ClientType: "geth",
		DeviceID:   259,
		ReadWrite:  0, // Read
	}
	agg := NewLatencyAggregate()
	agg.Add(1000000) // 1ms
	buf.DiskLatency[dim] = agg

	meta := BatchMetadata{
		ClientName:  "test-client",
		NetworkName: "test-network",
		UpdatedTime: time.Now(),
	}

	batch := c.Collect(buf, meta)

	require.Len(t, batch.Latency, 1)
	m := batch.Latency[0]

	assert.Equal(t, "disk_latency", m.MetricType)
	assert.Equal(t, uint32(1234), m.PID)
	assert.Equal(t, "geth", m.ClientType)
	require.NotNil(t, m.DeviceID)
	assert.Equal(t, uint32(259), *m.DeviceID)
	require.NotNil(t, m.RW)
	assert.Equal(t, "read", *m.RW)
}

func TestCollector_DiskLatencyWriteDirection(t *testing.T) {
	c := NewCollector(time.Second)

	buf := NewBuffer(
		time.Now(),
		12345,
		time.Now(),
		false,
		false,
		false,
	)

	dim := DiskDimension{
		PID:        1234,
		ClientType: "reth",
		DeviceID:   259,
		ReadWrite:  1, // Write
	}
	agg := NewLatencyAggregate()
	agg.Add(1000000)
	buf.DiskLatency[dim] = agg

	meta := BatchMetadata{
		ClientName:  "test-client",
		NetworkName: "test-network",
		UpdatedTime: time.Now(),
	}

	batch := c.Collect(buf, meta)

	require.Len(t, batch.Latency, 1)
	m := batch.Latency[0]

	require.NotNil(t, m.RW)
	assert.Equal(t, "write", *m.RW)
}

func TestCollector_NetworkCounterWithDimensions(t *testing.T) {
	c := NewCollector(time.Second)

	buf := NewBuffer(
		time.Now(),
		12345,
		time.Now(),
		false,
		false,
		false,
	)

	dim := NetworkDimension{
		PID:        1234,
		ClientType: "lighthouse",
		LocalPort:  9000,
		Direction:  0, // TX
	}
	agg := NewCounterAggregate()
	agg.Add(1024)
	buf.NetIO[dim] = agg

	meta := BatchMetadata{
		ClientName:  "test-client",
		NetworkName: "test-network",
		UpdatedTime: time.Now(),
	}

	batch := c.Collect(buf, meta)

	require.Len(t, batch.Counter, 1)
	m := batch.Counter[0]

	assert.Equal(t, "net_io", m.MetricType)
	assert.Equal(t, uint32(1234), m.PID)
	assert.Equal(t, "lighthouse", m.ClientType)
	require.NotNil(t, m.LocalPort)
	assert.Equal(t, uint16(9000), *m.LocalPort)
	require.NotNil(t, m.Direction)
	assert.Equal(t, "tx", *m.Direction)
	assert.Equal(t, int64(1024), m.Sum)
	assert.Equal(t, uint32(1), m.Count)
}

func TestCollector_TCPGaugeWithDimensions(t *testing.T) {
	c := NewCollector(time.Second)

	buf := NewBuffer(
		time.Now(),
		12345,
		time.Now(),
		false,
		false,
		false,
	)

	dim := TCPMetricsDimension{
		PID:        1234,
		ClientType: "prysm",
		LocalPort:  13000,
	}
	agg := NewGaugeAggregate()
	agg.Add(5000) // 5ms RTT
	agg.Add(10000)
	buf.TcpRTT[dim] = agg

	meta := BatchMetadata{
		ClientName:  "test-client",
		NetworkName: "test-network",
		UpdatedTime: time.Now(),
	}

	batch := c.Collect(buf, meta)

	require.Len(t, batch.Gauge, 1)
	m := batch.Gauge[0]

	assert.Equal(t, "tcp_rtt", m.MetricType)
	assert.Equal(t, uint32(1234), m.PID)
	assert.Equal(t, "prysm", m.ClientType)
	require.NotNil(t, m.LocalPort)
	assert.Equal(t, uint16(13000), *m.LocalPort)
	assert.Equal(t, int64(15000), m.Sum)
	assert.Equal(t, uint32(2), m.Count)
	assert.Equal(t, int64(5000), m.Min)
	assert.Equal(t, int64(10000), m.Max)
}

func TestCollector_AllMetricTypesCollected(t *testing.T) {
	c := NewCollector(time.Second)

	buf := NewBuffer(
		time.Now(),
		12345,
		time.Now(),
		false,
		false,
		false,
	)

	// Add one of each category.
	basicDim := BasicDimension{PID: 1, ClientType: "test"}
	diskDim := DiskDimension{PID: 1, ClientType: "test", DeviceID: 1}
	netDim := NetworkDimension{PID: 1, ClientType: "test", LocalPort: 9000}
	tcpDim := TCPMetricsDimension{PID: 1, ClientType: "test", LocalPort: 9000}

	// Basic latency.
	latAgg := NewLatencyAggregate()
	latAgg.Add(1000)
	buf.SyscallRead[basicDim] = latAgg

	// Disk latency.
	diskLatAgg := NewLatencyAggregate()
	diskLatAgg.Add(1000)
	buf.DiskLatency[diskDim] = diskLatAgg

	// Basic counter.
	counterAgg := NewCounterAggregate()
	counterAgg.AddCount(1)
	buf.FDOpen[basicDim] = counterAgg

	// Network counter.
	netCounterAgg := NewCounterAggregate()
	netCounterAgg.Add(100)
	buf.NetIO[netDim] = netCounterAgg

	// Disk counter.
	diskCounterAgg := NewCounterAggregate()
	diskCounterAgg.Add(512)
	buf.DiskBytes[diskDim] = diskCounterAgg

	// TCP gauge.
	tcpGaugeAgg := NewGaugeAggregate()
	tcpGaugeAgg.Add(1000)
	buf.TcpRTT[tcpDim] = tcpGaugeAgg

	// Disk gauge.
	diskGaugeAgg := NewGaugeAggregate()
	diskGaugeAgg.Add(4)
	buf.DiskQueueDepth[diskDim] = diskGaugeAgg

	meta := BatchMetadata{
		ClientName:  "test-client",
		NetworkName: "test-network",
		UpdatedTime: time.Now(),
	}

	batch := c.Collect(buf, meta)

	// Should have 2 latency (basic + disk).
	assert.Equal(t, 2, len(batch.Latency))

	// Should have 3 counters (basic + network + disk).
	assert.Equal(t, 3, len(batch.Counter))

	// Should have 2 gauges (tcp + disk).
	assert.Equal(t, 2, len(batch.Gauge))

	// Total should be 7.
	assert.Equal(t, 7, batch.TotalMetrics())
}

func TestCollector_WindowAndSlotInfo(t *testing.T) {
	c := NewCollector(500 * time.Millisecond)

	startTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	slotStart := time.Date(2024, 1, 1, 11, 59, 48, 0, time.UTC)

	buf := NewBuffer(
		startTime,
		12345,
		slotStart,
		false,
		false,
		false,
	)

	dim := BasicDimension{PID: 1, ClientType: "test"}
	agg := NewLatencyAggregate()
	agg.Add(1000)
	buf.SyscallRead[dim] = agg

	meta := BatchMetadata{
		ClientName:  "test-client",
		NetworkName: "test-network",
		UpdatedTime: time.Now(),
	}

	batch := c.Collect(buf, meta)

	require.Len(t, batch.Latency, 1)
	m := batch.Latency[0]

	// Verify window info.
	assert.Equal(t, startTime, m.Window.Start)
	assert.Equal(t, uint16(500), m.Window.IntervalMs)

	// Verify slot info.
	assert.Equal(t, uint32(12345), m.Slot.Number)
	assert.Equal(t, slotStart, m.Slot.StartTime)
}

func TestCollector_MetadataPassedThrough(t *testing.T) {
	c := NewCollector(time.Second)

	buf := NewBuffer(
		time.Now(),
		12345,
		time.Now(),
		false,
		false,
		false,
	)

	dim := BasicDimension{PID: 1, ClientType: "test"}
	agg := NewLatencyAggregate()
	agg.Add(1000)
	buf.SyscallRead[dim] = agg

	updatedTime := time.Date(2024, 6, 15, 10, 30, 0, 0, time.UTC)
	meta := BatchMetadata{
		ClientName:  "my-client",
		NetworkName: "mainnet",
		UpdatedTime: updatedTime,
	}

	batch := c.Collect(buf, meta)

	assert.Equal(t, "my-client", batch.Metadata.ClientName)
	assert.Equal(t, "mainnet", batch.Metadata.NetworkName)
	assert.Equal(t, updatedTime, batch.Metadata.UpdatedTime)
}

func TestSnapshotToHistogram(t *testing.T) {
	input := [numBuckets]uint64{
		1, 2, 3, 4, 5,
		6, 7, 8, 9, 10,
	}

	result := snapshotToHistogram(input)

	require.Len(t, result, 10)
	expected := []uint32{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	assert.Equal(t, expected, result)
}
