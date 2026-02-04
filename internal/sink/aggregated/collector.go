package aggregated

import "time"

// Collector performs single-pass collection from a Buffer into a MetricBatch.
type Collector struct {
	intervalMs uint16
}

// NewCollector creates a new Collector with the given interval.
func NewCollector(interval time.Duration) *Collector {
	return &Collector{
		intervalMs: uint16(interval.Milliseconds()),
	}
}

// Collect iterates the buffer once and returns all metrics.
func (c *Collector) Collect(buf *Buffer, meta BatchMetadata) MetricBatch {
	window := WindowInfo{
		Start:      buf.StartTime,
		IntervalMs: c.intervalMs,
	}

	slot := SlotInfo{
		Number:    uint32(buf.WallclockSlot),
		StartTime: buf.WallclockSlotStartDateTime,
	}

	batch := MetricBatch{
		Metadata: meta,
		Latency:  make([]LatencyMetric, 0, 256),
		Counter:  make([]CounterMetric, 0, 128),
		Gauge:    make([]GaugeMetric, 0, 64),
	}

	c.collectBasicLatency(&batch, buf, window, slot)
	c.collectDiskLatency(&batch, buf, window, slot)
	c.collectBasicCounters(&batch, buf, window, slot)
	c.collectNetworkCounters(&batch, buf, window, slot)
	c.collectDiskCounters(&batch, buf, window, slot)
	c.collectTCPGauges(&batch, buf, window, slot)
	c.collectDiskGauges(&batch, buf, window, slot)

	return batch
}

// collectBasicLatency collects all basic-dimension latency metrics.
func (c *Collector) collectBasicLatency(
	batch *MetricBatch,
	buf *Buffer,
	window WindowInfo,
	slot SlotInfo,
) {
	// Table of all basic latency maps.
	basicLatencyMaps := []struct {
		name string
		data map[BasicDimension]*LatencyAggregate
	}{
		{"syscall_read", buf.SyscallRead},
		{"syscall_write", buf.SyscallWrite},
		{"syscall_futex", buf.SyscallFutex},
		{"syscall_mmap", buf.SyscallMmap},
		{"syscall_epoll_wait", buf.SyscallEpollWait},
		{"syscall_fsync", buf.SyscallFsync},
		{"syscall_fdatasync", buf.SyscallFdatasync},
		{"syscall_pwrite", buf.SyscallPwrite},
		{"sched_on_cpu", buf.SchedSwitch},
		{"sched_off_cpu", buf.SchedOffCpu},
		{"sched_runqueue", buf.SchedRunqueue},
		{"mem_reclaim", buf.MemReclaim},
		{"mem_compaction", buf.MemCompaction},
	}

	for _, m := range basicLatencyMaps {
		for dim, agg := range m.data {
			snap := agg.Snapshot()
			if snap.Count == 0 {
				continue
			}

			batch.Latency = append(batch.Latency, LatencyMetric{
				MetricType: m.name,
				Window:     window,
				Slot:       slot,
				PID:        dim.PID,
				ClientType: dim.ClientType,
				Sum:        snap.Sum,
				Count:      uint32(snap.Count),
				Min:        snap.Min,
				Max:        snap.Max,
				Histogram:  snapshotToHistogram(snap.Histogram),
			})
		}
	}
}

// collectDiskLatency collects disk latency metrics with device/rw dimensions.
func (c *Collector) collectDiskLatency(
	batch *MetricBatch,
	buf *Buffer,
	window WindowInfo,
	slot SlotInfo,
) {
	for dim, agg := range buf.DiskLatency {
		snap := agg.Snapshot()
		if snap.Count == 0 {
			continue
		}

		deviceID := dim.DeviceID
		rw := RWString(dim.ReadWrite)

		batch.Latency = append(batch.Latency, LatencyMetric{
			MetricType: "disk_latency",
			Window:     window,
			Slot:       slot,
			PID:        dim.PID,
			ClientType: dim.ClientType,
			DeviceID:   &deviceID,
			RW:         &rw,
			Sum:        snap.Sum,
			Count:      uint32(snap.Count),
			Min:        snap.Min,
			Max:        snap.Max,
			Histogram:  snapshotToHistogram(snap.Histogram),
		})
	}
}

// collectBasicCounters collects all basic-dimension counter metrics.
func (c *Collector) collectBasicCounters(
	batch *MetricBatch,
	buf *Buffer,
	window WindowInfo,
	slot SlotInfo,
) {
	basicCounterMaps := []struct {
		name string
		data map[BasicDimension]*CounterAggregate
	}{
		{"page_fault_major", buf.PageFaultMajor},
		{"page_fault_minor", buf.PageFaultMinor},
		{"swap_in", buf.SwapIn},
		{"swap_out", buf.SwapOut},
		{"oom_kill", buf.OOMKill},
		{"fd_open", buf.FDOpen},
		{"fd_close", buf.FDClose},
		{"process_exit", buf.ProcessExit},
		{"tcp_state_change", buf.TcpStateChange},
	}

	for _, m := range basicCounterMaps {
		for dim, agg := range m.data {
			snap := agg.Snapshot()
			if snap.Count == 0 {
				continue
			}

			batch.Counter = append(batch.Counter, CounterMetric{
				MetricType: m.name,
				Window:     window,
				Slot:       slot,
				PID:        dim.PID,
				ClientType: dim.ClientType,
				Sum:        snap.Sum,
				Count:      uint32(snap.Count),
			})
		}
	}
}

// collectNetworkCounters collects network counter metrics with port/direction.
func (c *Collector) collectNetworkCounters(
	batch *MetricBatch,
	buf *Buffer,
	window WindowInfo,
	slot SlotInfo,
) {
	networkCounterMaps := []struct {
		name string
		data map[NetworkDimension]*CounterAggregate
	}{
		{"net_io", buf.NetIO},
		{"tcp_retransmit", buf.TcpRetransmit},
	}

	for _, m := range networkCounterMaps {
		for dim, agg := range m.data {
			snap := agg.Snapshot()
			if snap.Count == 0 {
				continue
			}

			localPort := dim.LocalPort
			direction := DirectionString(dim.Direction)

			batch.Counter = append(batch.Counter, CounterMetric{
				MetricType: m.name,
				Window:     window,
				Slot:       slot,
				PID:        dim.PID,
				ClientType: dim.ClientType,
				LocalPort:  &localPort,
				Direction:  &direction,
				Sum:        snap.Sum,
				Count:      uint32(snap.Count),
			})
		}
	}
}

// collectDiskCounters collects disk counter metrics with device/rw dimensions.
func (c *Collector) collectDiskCounters(
	batch *MetricBatch,
	buf *Buffer,
	window WindowInfo,
	slot SlotInfo,
) {
	diskCounterMaps := []struct {
		name string
		data map[DiskDimension]*CounterAggregate
	}{
		{"disk_bytes", buf.DiskBytes},
		{"block_merge", buf.BlockMerge},
	}

	for _, m := range diskCounterMaps {
		for dim, agg := range m.data {
			snap := agg.Snapshot()
			if snap.Count == 0 {
				continue
			}

			deviceID := dim.DeviceID
			rw := RWString(dim.ReadWrite)

			batch.Counter = append(batch.Counter, CounterMetric{
				MetricType: m.name,
				Window:     window,
				Slot:       slot,
				PID:        dim.PID,
				ClientType: dim.ClientType,
				DeviceID:   &deviceID,
				RW:         &rw,
				Sum:        snap.Sum,
				Count:      uint32(snap.Count),
			})
		}
	}
}

// collectTCPGauges collects TCP gauge metrics with local port dimension.
func (c *Collector) collectTCPGauges(
	batch *MetricBatch,
	buf *Buffer,
	window WindowInfo,
	slot SlotInfo,
) {
	tcpGaugeMaps := []struct {
		name string
		data map[TCPMetricsDimension]*GaugeAggregate
	}{
		{"tcp_rtt", buf.TcpRTT},
		{"tcp_cwnd", buf.TcpCwnd},
	}

	for _, m := range tcpGaugeMaps {
		for dim, agg := range m.data {
			snap := agg.Snapshot()
			if snap.Count == 0 {
				continue
			}

			localPort := dim.LocalPort

			batch.Gauge = append(batch.Gauge, GaugeMetric{
				MetricType: m.name,
				Window:     window,
				Slot:       slot,
				PID:        dim.PID,
				ClientType: dim.ClientType,
				LocalPort:  &localPort,
				Sum:        snap.Sum,
				Count:      uint32(snap.Count),
				Min:        snap.Min,
				Max:        snap.Max,
			})
		}
	}
}

// collectDiskGauges collects disk gauge metrics with device/rw dimensions.
func (c *Collector) collectDiskGauges(
	batch *MetricBatch,
	buf *Buffer,
	window WindowInfo,
	slot SlotInfo,
) {
	for dim, agg := range buf.DiskQueueDepth {
		snap := agg.Snapshot()
		if snap.Count == 0 {
			continue
		}

		deviceID := dim.DeviceID
		rw := RWString(dim.ReadWrite)

		batch.Gauge = append(batch.Gauge, GaugeMetric{
			MetricType: "disk_queue_depth",
			Window:     window,
			Slot:       slot,
			PID:        dim.PID,
			ClientType: dim.ClientType,
			DeviceID:   &deviceID,
			RW:         &rw,
			Sum:        snap.Sum,
			Count:      uint32(snap.Count),
			Min:        snap.Min,
			Max:        snap.Max,
		})
	}
}

// snapshotToHistogram converts a fixed-size histogram array to a slice.
func snapshotToHistogram(hist [numBuckets]uint64) []uint32 {
	result := make([]uint32, numBuckets)
	for i := range numBuckets {
		result[i] = uint32(hist[i])
	}

	return result
}
