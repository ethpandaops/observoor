package aggregated

import (
	"context"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/ethpandaops/observoor/internal/export"
)

// aggregatedRow represents a single row to be written to ClickHouse.
type aggregatedRow struct {
	WindowStart time.Time
	WindowEnd   time.Time
	IntervalMs  uint16
	Slot        uint32
	MetricName  string
	PID         uint32
	ClientType  string
	LocalPort   uint16
	Direction   string
	DeviceID    uint32
	RW          string
	Sum         int64
	Count       uint32
	Min         int64
	Max         int64
	Hist1us     uint16
	Hist10us    uint16
	Hist100us   uint16
	Hist1ms     uint16
	Hist10ms    uint16
	Hist100ms   uint16
	Hist1s      uint16
	Hist10s     uint16
	Hist100s    uint16
	HistInf     uint16
}

// flusher handles writing aggregated data to ClickHouse.
type flusher struct {
	log        logrus.FieldLogger
	writer     *export.ClickHouseWriter
	cfg        Config
	health     *export.HealthMetrics
	rows       []aggregatedRow
	intervalMs uint16
	slot       uint32
	buf        *Buffer
}

// newFlusher creates a new flusher.
func newFlusher(
	log logrus.FieldLogger,
	writer *export.ClickHouseWriter,
	cfg Config,
	health *export.HealthMetrics,
) *flusher {
	return &flusher{
		log:    log,
		writer: writer,
		cfg:    cfg,
		health: health,
		rows:   make([]aggregatedRow, 0, 1024),
	}
}

// Flush writes all aggregated data from the buffer to ClickHouse.
func (f *flusher) Flush(ctx context.Context, buf *Buffer) error {
	f.intervalMs = uint16(f.cfg.Resolution.Interval.Milliseconds())
	f.slot = uint32(buf.Slot)
	f.buf = buf

	// Collect all rows from the buffer.
	f.collectSyscalls()
	f.collectNetwork()
	f.collectTcpMetrics()
	f.collectDisk()
	f.collectScheduler()
	f.collectPageFaults()
	f.collectFDOps()
	f.collectMemory()
	f.collectMisc()

	if len(f.rows) == 0 {
		return nil
	}

	// Write to ClickHouse.
	conn := f.writer.Conn()
	cfg := f.writer.Config()
	table := fmt.Sprintf("%s.%s", cfg.Database, cfg.Table)

	batch, err := conn.PrepareBatch(
		ctx,
		fmt.Sprintf(`INSERT INTO %s (
			window_start, window_end, interval_ms, slot,
			metric_name, pid, client_type, local_port, direction, device_id, rw,
			sum, count, min, max,
			hist_1us, hist_10us, hist_100us, hist_1ms, hist_10ms, hist_100ms, hist_1s, hist_10s, hist_100s, hist_inf
		)`, table),
	)
	if err != nil {
		return fmt.Errorf("preparing batch: %w", err)
	}

	for _, row := range f.rows {
		if err := batch.Append(
			row.WindowStart, row.WindowEnd, row.IntervalMs, row.Slot,
			row.MetricName, row.PID, row.ClientType, row.LocalPort, row.Direction, row.DeviceID, row.RW,
			row.Sum, row.Count, row.Min, row.Max,
			row.Hist1us, row.Hist10us, row.Hist100us, row.Hist1ms, row.Hist10ms, row.Hist100ms,
			row.Hist1s, row.Hist10s, row.Hist100s, row.HistInf,
		); err != nil {
			return fmt.Errorf("appending row: %w", err)
		}
	}

	if err := batch.Send(); err != nil {
		if f.health != nil {
			f.health.ExportBatchErrors.WithLabelValues("aggregated", "send").Inc()
		}

		return fmt.Errorf("sending batch of %d rows: %w", len(f.rows), err)
	}

	// Record batch size metric.
	if f.health != nil {
		f.health.SinkBatchSize.WithLabelValues("aggregated").Observe(float64(len(f.rows)))
	}

	f.log.WithField("rows", len(f.rows)).Debug("Flushed aggregated metrics")

	return nil
}

// addLatencyRow adds a row with histogram data.
func (f *flusher) addLatencyRow(metricName string, dim BasicDimension, snap LatencySnapshot) {
	if snap.Count == 0 {
		return
	}

	f.rows = append(f.rows, aggregatedRow{
		WindowStart: f.buf.StartTime,
		WindowEnd:   f.buf.EndTime,
		IntervalMs:  f.intervalMs,
		Slot:        f.slot,
		MetricName:  metricName,
		PID:         dim.PID,
		ClientType:  dim.ClientType,
		Sum:         snap.Sum,
		Count:       uint32(snap.Count),
		Min:         snap.Min,
		Max:         snap.Max,
		Hist1us:     uint16(snap.Histogram[0]),
		Hist10us:    uint16(snap.Histogram[1]),
		Hist100us:   uint16(snap.Histogram[2]),
		Hist1ms:     uint16(snap.Histogram[3]),
		Hist10ms:    uint16(snap.Histogram[4]),
		Hist100ms:   uint16(snap.Histogram[5]),
		Hist1s:      uint16(snap.Histogram[6]),
		Hist10s:     uint16(snap.Histogram[7]),
		Hist100s:    uint16(snap.Histogram[8]),
		HistInf:     uint16(snap.Histogram[9]),
	})
}

// addCounterRow adds a row with count/sum only.
func (f *flusher) addCounterRow(metricName string, dim BasicDimension, snap CounterSnapshot) {
	if snap.Count == 0 {
		return
	}

	f.rows = append(f.rows, aggregatedRow{
		WindowStart: f.buf.StartTime,
		WindowEnd:   f.buf.EndTime,
		IntervalMs:  f.intervalMs,
		Slot:        f.slot,
		MetricName:  metricName,
		PID:         dim.PID,
		ClientType:  dim.ClientType,
		Sum:         snap.Sum,
		Count:       uint32(snap.Count),
	})
}

// addGaugeRow adds a row with min/max/sum/count.
func (f *flusher) addGaugeRow(metricName string, dim BasicDimension, snap GaugeSnapshot) {
	if snap.Count == 0 {
		return
	}

	f.rows = append(f.rows, aggregatedRow{
		WindowStart: f.buf.StartTime,
		WindowEnd:   f.buf.EndTime,
		IntervalMs:  f.intervalMs,
		Slot:        f.slot,
		MetricName:  metricName,
		PID:         dim.PID,
		ClientType:  dim.ClientType,
		Sum:         snap.Sum,
		Count:       uint32(snap.Count),
		Min:         snap.Min,
		Max:         snap.Max,
	})
}

// collectSyscalls collects syscall latency aggregates.
func (f *flusher) collectSyscalls() {
	syscallMaps := map[string]map[BasicDimension]*LatencyAggregate{
		"syscall_read":       f.buf.SyscallRead,
		"syscall_write":      f.buf.SyscallWrite,
		"syscall_futex":      f.buf.SyscallFutex,
		"syscall_mmap":       f.buf.SyscallMmap,
		"syscall_epoll_wait": f.buf.SyscallEpollWait,
		"syscall_fsync":      f.buf.SyscallFsync,
		"syscall_fdatasync":  f.buf.SyscallFdatasync,
		"syscall_pwrite":     f.buf.SyscallPwrite,
	}

	for metricName, m := range syscallMaps {
		for dim, agg := range m {
			f.addLatencyRow(metricName, dim, agg.Snapshot())
		}
	}
}

// collectNetwork collects network I/O aggregates.
func (f *flusher) collectNetwork() {
	// Net I/O.
	for dim, agg := range f.buf.NetIO {
		snap := agg.Snapshot()
		if snap.Count == 0 {
			continue
		}

		f.rows = append(f.rows, aggregatedRow{
			WindowStart: f.buf.StartTime,
			WindowEnd:   f.buf.EndTime,
			IntervalMs:  f.intervalMs,
			Slot:        f.slot,
			MetricName:  "net_io",
			PID:         dim.PID,
			ClientType:  dim.ClientType,
			LocalPort:   dim.LocalPort,
			Direction:   DirectionString(dim.Direction),
			Sum:         snap.Sum,
			Count:       uint32(snap.Count),
		})
	}

	// TCP retransmits.
	for dim, agg := range f.buf.TcpRetransmit {
		snap := agg.Snapshot()
		if snap.Count == 0 {
			continue
		}

		f.rows = append(f.rows, aggregatedRow{
			WindowStart: f.buf.StartTime,
			WindowEnd:   f.buf.EndTime,
			IntervalMs:  f.intervalMs,
			Slot:        f.slot,
			MetricName:  "tcp_retransmit",
			PID:         dim.PID,
			ClientType:  dim.ClientType,
			LocalPort:   dim.LocalPort,
			Direction:   DirectionString(dim.Direction),
			Sum:         snap.Sum,
			Count:       uint32(snap.Count),
		})
	}
}

// collectTcpMetrics collects TCP RTT and CWND aggregates.
func (f *flusher) collectTcpMetrics() {
	// TCP RTT.
	for dim, agg := range f.buf.TcpRTT {
		snap := agg.Snapshot()
		if snap.Count == 0 {
			continue
		}

		f.rows = append(f.rows, aggregatedRow{
			WindowStart: f.buf.StartTime,
			WindowEnd:   f.buf.EndTime,
			IntervalMs:  f.intervalMs,
			Slot:        f.slot,
			MetricName:  "tcp_rtt_us",
			PID:         dim.PID,
			ClientType:  dim.ClientType,
			LocalPort:   dim.LocalPort,
			Sum:         snap.Sum,
			Count:       uint32(snap.Count),
			Min:         snap.Min,
			Max:         snap.Max,
		})
	}

	// TCP CWND.
	for dim, agg := range f.buf.TcpCwnd {
		snap := agg.Snapshot()
		if snap.Count == 0 {
			continue
		}

		f.rows = append(f.rows, aggregatedRow{
			WindowStart: f.buf.StartTime,
			WindowEnd:   f.buf.EndTime,
			IntervalMs:  f.intervalMs,
			Slot:        f.slot,
			MetricName:  "tcp_cwnd",
			PID:         dim.PID,
			ClientType:  dim.ClientType,
			LocalPort:   dim.LocalPort,
			Sum:         snap.Sum,
			Count:       uint32(snap.Count),
			Min:         snap.Min,
			Max:         snap.Max,
		})
	}

	// TCP state changes.
	for dim, agg := range f.buf.TcpStateChange {
		snap := agg.Snapshot()
		if snap.Count == 0 {
			continue
		}

		f.rows = append(f.rows, aggregatedRow{
			WindowStart: f.buf.StartTime,
			WindowEnd:   f.buf.EndTime,
			IntervalMs:  f.intervalMs,
			Slot:        f.slot,
			MetricName:  "tcp_state_change",
			PID:         dim.PID,
			ClientType:  dim.ClientType,
			Sum:         snap.Sum,
			Count:       uint32(snap.Count),
		})
	}
}

// collectDisk collects disk I/O aggregates.
func (f *flusher) collectDisk() {
	// Disk latency.
	for dim, agg := range f.buf.DiskLatency {
		snap := agg.Snapshot()
		if snap.Count == 0 {
			continue
		}

		f.rows = append(f.rows, aggregatedRow{
			WindowStart: f.buf.StartTime,
			WindowEnd:   f.buf.EndTime,
			IntervalMs:  f.intervalMs,
			Slot:        f.slot,
			MetricName:  "disk_latency",
			PID:         dim.PID,
			ClientType:  dim.ClientType,
			DeviceID:    dim.DeviceID,
			RW:          RWString(dim.ReadWrite),
			Sum:         snap.Sum,
			Count:       uint32(snap.Count),
			Min:         snap.Min,
			Max:         snap.Max,
			Hist1us:     uint16(snap.Histogram[0]),
			Hist10us:    uint16(snap.Histogram[1]),
			Hist100us:   uint16(snap.Histogram[2]),
			Hist1ms:     uint16(snap.Histogram[3]),
			Hist10ms:    uint16(snap.Histogram[4]),
			Hist100ms:   uint16(snap.Histogram[5]),
			Hist1s:      uint16(snap.Histogram[6]),
			Hist10s:     uint16(snap.Histogram[7]),
			Hist100s:    uint16(snap.Histogram[8]),
			HistInf:     uint16(snap.Histogram[9]),
		})
	}

	// Disk bytes.
	for dim, agg := range f.buf.DiskBytes {
		snap := agg.Snapshot()
		if snap.Count == 0 {
			continue
		}

		f.rows = append(f.rows, aggregatedRow{
			WindowStart: f.buf.StartTime,
			WindowEnd:   f.buf.EndTime,
			IntervalMs:  f.intervalMs,
			Slot:        f.slot,
			MetricName:  "disk_bytes",
			PID:         dim.PID,
			ClientType:  dim.ClientType,
			DeviceID:    dim.DeviceID,
			RW:          RWString(dim.ReadWrite),
			Sum:         snap.Sum,
			Count:       uint32(snap.Count),
		})
	}

	// Disk queue depth.
	for dim, agg := range f.buf.DiskQueueDepth {
		snap := agg.Snapshot()
		if snap.Count == 0 {
			continue
		}

		f.rows = append(f.rows, aggregatedRow{
			WindowStart: f.buf.StartTime,
			WindowEnd:   f.buf.EndTime,
			IntervalMs:  f.intervalMs,
			Slot:        f.slot,
			MetricName:  "disk_queue_depth",
			PID:         dim.PID,
			ClientType:  dim.ClientType,
			DeviceID:    dim.DeviceID,
			RW:          RWString(dim.ReadWrite),
			Sum:         snap.Sum,
			Count:       uint32(snap.Count),
			Min:         snap.Min,
			Max:         snap.Max,
		})
	}

	// Block merge.
	for dim, agg := range f.buf.BlockMerge {
		snap := agg.Snapshot()
		if snap.Count == 0 {
			continue
		}

		f.rows = append(f.rows, aggregatedRow{
			WindowStart: f.buf.StartTime,
			WindowEnd:   f.buf.EndTime,
			IntervalMs:  f.intervalMs,
			Slot:        f.slot,
			MetricName:  "block_merge",
			PID:         dim.PID,
			ClientType:  dim.ClientType,
			DeviceID:    dim.DeviceID,
			RW:          RWString(dim.ReadWrite),
			Sum:         snap.Sum,
			Count:       uint32(snap.Count),
		})
	}
}

// collectScheduler collects scheduler aggregates.
func (f *flusher) collectScheduler() {
	// Sched switch (on-CPU time).
	for dim, agg := range f.buf.SchedSwitch {
		f.addLatencyRow("sched_on_cpu", dim, agg.Snapshot())
	}

	// Runqueue latency.
	for dim, agg := range f.buf.SchedRunqueue {
		f.addLatencyRow("sched_runqueue", dim, agg.Snapshot())
	}

	// Off-CPU time.
	for dim, agg := range f.buf.SchedOffCpu {
		f.addLatencyRow("sched_off_cpu", dim, agg.Snapshot())
	}
}

// collectPageFaults collects page fault aggregates.
func (f *flusher) collectPageFaults() {
	for dim, agg := range f.buf.PageFaultMajor {
		f.addCounterRow("page_fault_major", dim, agg.Snapshot())
	}

	for dim, agg := range f.buf.PageFaultMinor {
		f.addCounterRow("page_fault_minor", dim, agg.Snapshot())
	}
}

// collectFDOps collects file descriptor operation aggregates.
func (f *flusher) collectFDOps() {
	for dim, agg := range f.buf.FDOpen {
		f.addCounterRow("fd_open", dim, agg.Snapshot())
	}

	for dim, agg := range f.buf.FDClose {
		f.addCounterRow("fd_close", dim, agg.Snapshot())
	}
}

// collectMemory collects memory-related aggregates.
func (f *flusher) collectMemory() {
	// Memory reclaim.
	for dim, agg := range f.buf.MemReclaim {
		f.addLatencyRow("mem_reclaim", dim, agg.Snapshot())
	}

	// Memory compaction.
	for dim, agg := range f.buf.MemCompaction {
		f.addLatencyRow("mem_compaction", dim, agg.Snapshot())
	}

	// Swap in.
	for dim, agg := range f.buf.SwapIn {
		f.addCounterRow("swap_in", dim, agg.Snapshot())
	}

	// Swap out.
	for dim, agg := range f.buf.SwapOut {
		f.addCounterRow("swap_out", dim, agg.Snapshot())
	}
}

// collectMisc collects miscellaneous aggregates.
func (f *flusher) collectMisc() {
	// OOM kills.
	for dim, agg := range f.buf.OOMKill {
		f.addCounterRow("oom_kill", dim, agg.Snapshot())
	}

	// Process exits.
	for dim, agg := range f.buf.ProcessExit {
		f.addCounterRow("process_exit", dim, agg.Snapshot())
	}
}
