package aggregated

import (
	"context"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/ethpandaops/observoor/internal/export"
)

// Row types for each subsystem table.

// cpuRow is for cpu_metrics table (scheduler events with histograms).
type cpuRow struct {
	WindowStart   time.Time
	IntervalMs    uint16
	WallclockSlot uint32
	CLSyncing     bool
	ELOptimistic  bool
	ELOffline     bool
	MetricName    string
	PID           uint32
	ClientType    string
	Sum           int64
	Count         uint32
	Min           int64
	Max           int64
	Hist1us       uint16
	Hist10us      uint16
	Hist100us     uint16
	Hist1ms       uint16
	Hist10ms      uint16
	Hist100ms     uint16
	Hist1s        uint16
	Hist10s       uint16
	Hist100s      uint16
	HistInf       uint16
}

// memoryRow is for memory_metrics table (page faults, swap, oom, mem pressure).
type memoryRow struct {
	WindowStart   time.Time
	IntervalMs    uint16
	WallclockSlot uint32
	CLSyncing     bool
	ELOptimistic  bool
	ELOffline     bool
	MetricName    string
	PID           uint32
	ClientType    string
	Sum           int64
	Count         uint32
	Min           int64
	Max           int64
	Hist1us       uint16
	Hist10us      uint16
	Hist100us     uint16
	Hist1ms       uint16
	Hist10ms      uint16
	Hist100ms     uint16
	Hist1s        uint16
	Hist10s       uint16
	Hist100s      uint16
	HistInf       uint16
}

// diskRow is for disk_metrics table (disk I/O with device_id, rw, histograms).
type diskRow struct {
	WindowStart   time.Time
	IntervalMs    uint16
	WallclockSlot uint32
	CLSyncing     bool
	ELOptimistic  bool
	ELOffline     bool
	MetricName    string
	PID           uint32
	ClientType    string
	DeviceID      uint32
	RW            string
	Sum           int64
	Count         uint32
	Min           int64
	Max           int64
	Hist1us       uint16
	Hist10us      uint16
	Hist100us     uint16
	Hist1ms       uint16
	Hist10ms      uint16
	Hist100ms     uint16
	Hist1s        uint16
	Hist10s       uint16
	Hist100s      uint16
	HistInf       uint16
}

// networkRow is for network_metrics table (net I/O, TCP with port/direction).
type networkRow struct {
	WindowStart   time.Time
	IntervalMs    uint16
	WallclockSlot uint32
	CLSyncing     bool
	ELOptimistic  bool
	ELOffline     bool
	MetricName    string
	PID           uint32
	ClientType    string
	LocalPort     uint16
	Direction     string
	Sum           int64
	Count         uint32
	Min           int64
	Max           int64
}

// syscallRow is for syscall_metrics table (syscall latencies with histograms).
type syscallRow struct {
	WindowStart   time.Time
	IntervalMs    uint16
	WallclockSlot uint32
	CLSyncing     bool
	ELOptimistic  bool
	ELOffline     bool
	MetricName    string
	PID           uint32
	ClientType    string
	Sum           int64
	Count         uint32
	Min           int64
	Max           int64
	Hist1us       uint16
	Hist10us      uint16
	Hist100us     uint16
	Hist1ms       uint16
	Hist10ms      uint16
	Hist100ms     uint16
	Hist1s        uint16
	Hist10s       uint16
	Hist100s      uint16
	HistInf       uint16
}

// processRow is for process_metrics table (fd ops, process exit - counters only).
type processRow struct {
	WindowStart   time.Time
	IntervalMs    uint16
	WallclockSlot uint32
	CLSyncing     bool
	ELOptimistic  bool
	ELOffline     bool
	MetricName    string
	PID           uint32
	ClientType    string
	Sum           int64
	Count         uint32
}

// flusher handles writing aggregated data to ClickHouse.
type flusher struct {
	log           logrus.FieldLogger
	writer        *export.ClickHouseWriter
	cfg           Config
	health        *export.HealthMetrics
	intervalMs    uint16
	wallclockSlot uint32
	clSyncing     bool
	elOptimistic  bool
	elOffline     bool
	buf           *Buffer

	// Per-table row buffers.
	cpuRows     []cpuRow
	memoryRows  []memoryRow
	diskRows    []diskRow
	networkRows []networkRow
	syscallRows []syscallRow
	processRows []processRow
}

// newFlusher creates a new flusher.
func newFlusher(
	log logrus.FieldLogger,
	writer *export.ClickHouseWriter,
	cfg Config,
	health *export.HealthMetrics,
) *flusher {
	return &flusher{
		log:         log,
		writer:      writer,
		cfg:         cfg,
		health:      health,
		cpuRows:     make([]cpuRow, 0, 64),
		memoryRows:  make([]memoryRow, 0, 64),
		diskRows:    make([]diskRow, 0, 64),
		networkRows: make([]networkRow, 0, 128),
		syscallRows: make([]syscallRow, 0, 256),
		processRows: make([]processRow, 0, 32),
	}
}

// Flush writes all aggregated data from the buffer to ClickHouse.
func (f *flusher) Flush(ctx context.Context, buf *Buffer) error {
	f.intervalMs = uint16(f.cfg.Resolution.Interval.Milliseconds())
	f.wallclockSlot = uint32(buf.WallclockSlot)
	f.clSyncing = buf.CLSyncing
	f.elOptimistic = buf.ELOptimistic
	f.elOffline = buf.ELOffline
	f.buf = buf

	// Collect rows into per-table buffers.
	f.collectCPU()
	f.collectMemory()
	f.collectDisk()
	f.collectNetwork()
	f.collectSyscalls()
	f.collectProcess()

	// Flush each table.
	var totalRows int

	if err := f.flushCPU(ctx); err != nil {
		return err
	}

	totalRows += len(f.cpuRows)

	if err := f.flushMemory(ctx); err != nil {
		return err
	}

	totalRows += len(f.memoryRows)

	if err := f.flushDisk(ctx); err != nil {
		return err
	}

	totalRows += len(f.diskRows)

	if err := f.flushNetwork(ctx); err != nil {
		return err
	}

	totalRows += len(f.networkRows)

	if err := f.flushSyscalls(ctx); err != nil {
		return err
	}

	totalRows += len(f.syscallRows)

	if err := f.flushProcess(ctx); err != nil {
		return err
	}

	totalRows += len(f.processRows)

	if totalRows > 0 {
		if f.health != nil {
			f.health.SinkBatchSize.WithLabelValues("aggregated").Observe(float64(totalRows))
		}

		f.log.WithField("rows", totalRows).Debug("Flushed aggregated metrics")
	}

	return nil
}

// collectCPU collects scheduler metrics into cpuRows.
func (f *flusher) collectCPU() {
	// Sched switch (on-CPU time).
	for dim, agg := range f.buf.SchedSwitch {
		snap := agg.Snapshot()
		if snap.Count == 0 {
			continue
		}

		f.cpuRows = append(f.cpuRows, f.makeCPURow("sched_on_cpu", dim, snap))
	}

	// Runqueue latency.
	for dim, agg := range f.buf.SchedRunqueue {
		snap := agg.Snapshot()
		if snap.Count == 0 {
			continue
		}

		f.cpuRows = append(f.cpuRows, f.makeCPURow("sched_runqueue", dim, snap))
	}

	// Off-CPU time.
	for dim, agg := range f.buf.SchedOffCpu {
		snap := agg.Snapshot()
		if snap.Count == 0 {
			continue
		}

		f.cpuRows = append(f.cpuRows, f.makeCPURow("sched_off_cpu", dim, snap))
	}
}

func (f *flusher) makeCPURow(metricName string, dim BasicDimension, snap LatencySnapshot) cpuRow {
	return cpuRow{
		WindowStart:   f.buf.StartTime,
		IntervalMs:    f.intervalMs,
		WallclockSlot: f.wallclockSlot,
		CLSyncing:     f.clSyncing,
		ELOptimistic:  f.elOptimistic,
		ELOffline:     f.elOffline,
		MetricName:    metricName,
		PID:           dim.PID,
		ClientType:    dim.ClientType,
		Sum:           snap.Sum,
		Count:         uint32(snap.Count),
		Min:           snap.Min,
		Max:           snap.Max,
		Hist1us:       uint16(snap.Histogram[0]),
		Hist10us:      uint16(snap.Histogram[1]),
		Hist100us:     uint16(snap.Histogram[2]),
		Hist1ms:       uint16(snap.Histogram[3]),
		Hist10ms:      uint16(snap.Histogram[4]),
		Hist100ms:     uint16(snap.Histogram[5]),
		Hist1s:        uint16(snap.Histogram[6]),
		Hist10s:       uint16(snap.Histogram[7]),
		Hist100s:      uint16(snap.Histogram[8]),
		HistInf:       uint16(snap.Histogram[9]),
	}
}

// collectMemory collects memory metrics into memoryRows.
func (f *flusher) collectMemory() {
	// Page faults (counters - histogram will be zero).
	for dim, agg := range f.buf.PageFaultMajor {
		snap := agg.Snapshot()
		if snap.Count == 0 {
			continue
		}

		f.memoryRows = append(f.memoryRows, f.makeMemoryCounterRow("page_fault_major", dim, snap))
	}

	for dim, agg := range f.buf.PageFaultMinor {
		snap := agg.Snapshot()
		if snap.Count == 0 {
			continue
		}

		f.memoryRows = append(f.memoryRows, f.makeMemoryCounterRow("page_fault_minor", dim, snap))
	}

	// Memory reclaim (latency with histogram).
	for dim, agg := range f.buf.MemReclaim {
		snap := agg.Snapshot()
		if snap.Count == 0 {
			continue
		}

		f.memoryRows = append(f.memoryRows, f.makeMemoryLatencyRow("mem_reclaim", dim, snap))
	}

	// Memory compaction (latency with histogram).
	for dim, agg := range f.buf.MemCompaction {
		snap := agg.Snapshot()
		if snap.Count == 0 {
			continue
		}

		f.memoryRows = append(f.memoryRows, f.makeMemoryLatencyRow("mem_compaction", dim, snap))
	}

	// Swap (counters).
	for dim, agg := range f.buf.SwapIn {
		snap := agg.Snapshot()
		if snap.Count == 0 {
			continue
		}

		f.memoryRows = append(f.memoryRows, f.makeMemoryCounterRow("swap_in", dim, snap))
	}

	for dim, agg := range f.buf.SwapOut {
		snap := agg.Snapshot()
		if snap.Count == 0 {
			continue
		}

		f.memoryRows = append(f.memoryRows, f.makeMemoryCounterRow("swap_out", dim, snap))
	}

	// OOM kills (counter).
	for dim, agg := range f.buf.OOMKill {
		snap := agg.Snapshot()
		if snap.Count == 0 {
			continue
		}

		f.memoryRows = append(f.memoryRows, f.makeMemoryCounterRow("oom_kill", dim, snap))
	}
}

func (f *flusher) makeMemoryLatencyRow(metricName string, dim BasicDimension, snap LatencySnapshot) memoryRow {
	return memoryRow{
		WindowStart:   f.buf.StartTime,
		IntervalMs:    f.intervalMs,
		WallclockSlot: f.wallclockSlot,
		CLSyncing:     f.clSyncing,
		ELOptimistic:  f.elOptimistic,
		ELOffline:     f.elOffline,
		MetricName:    metricName,
		PID:           dim.PID,
		ClientType:    dim.ClientType,
		Sum:           snap.Sum,
		Count:         uint32(snap.Count),
		Min:           snap.Min,
		Max:           snap.Max,
		Hist1us:       uint16(snap.Histogram[0]),
		Hist10us:      uint16(snap.Histogram[1]),
		Hist100us:     uint16(snap.Histogram[2]),
		Hist1ms:       uint16(snap.Histogram[3]),
		Hist10ms:      uint16(snap.Histogram[4]),
		Hist100ms:     uint16(snap.Histogram[5]),
		Hist1s:        uint16(snap.Histogram[6]),
		Hist10s:       uint16(snap.Histogram[7]),
		Hist100s:      uint16(snap.Histogram[8]),
		HistInf:       uint16(snap.Histogram[9]),
	}
}

func (f *flusher) makeMemoryCounterRow(metricName string, dim BasicDimension, snap CounterSnapshot) memoryRow {
	return memoryRow{
		WindowStart:   f.buf.StartTime,
		IntervalMs:    f.intervalMs,
		WallclockSlot: f.wallclockSlot,
		CLSyncing:     f.clSyncing,
		ELOptimistic:  f.elOptimistic,
		ELOffline:     f.elOffline,
		MetricName:    metricName,
		PID:           dim.PID,
		ClientType:    dim.ClientType,
		Sum:           snap.Sum,
		Count:         uint32(snap.Count),
	}
}

// collectDisk collects disk metrics into diskRows.
func (f *flusher) collectDisk() {
	// Disk latency (with histogram).
	for dim, agg := range f.buf.DiskLatency {
		snap := agg.Snapshot()
		if snap.Count == 0 {
			continue
		}

		f.diskRows = append(f.diskRows, f.makeDiskLatencyRow("disk_latency", dim, snap))
	}

	// Disk bytes (counter).
	for dim, agg := range f.buf.DiskBytes {
		snap := agg.Snapshot()
		if snap.Count == 0 {
			continue
		}

		f.diskRows = append(f.diskRows, f.makeDiskCounterRow("disk_bytes", dim, snap))
	}

	// Disk queue depth (gauge).
	for dim, agg := range f.buf.DiskQueueDepth {
		snap := agg.Snapshot()
		if snap.Count == 0 {
			continue
		}

		f.diskRows = append(f.diskRows, f.makeDiskGaugeRow("disk_queue_depth", dim, snap))
	}

	// Block merge (counter).
	for dim, agg := range f.buf.BlockMerge {
		snap := agg.Snapshot()
		if snap.Count == 0 {
			continue
		}

		f.diskRows = append(f.diskRows, f.makeDiskCounterRow("block_merge", dim, snap))
	}
}

func (f *flusher) makeDiskLatencyRow(metricName string, dim DiskDimension, snap LatencySnapshot) diskRow {
	return diskRow{
		WindowStart:   f.buf.StartTime,
		IntervalMs:    f.intervalMs,
		WallclockSlot: f.wallclockSlot,
		CLSyncing:     f.clSyncing,
		ELOptimistic:  f.elOptimistic,
		ELOffline:     f.elOffline,
		MetricName:    metricName,
		PID:           dim.PID,
		ClientType:    dim.ClientType,
		DeviceID:      dim.DeviceID,
		RW:            RWString(dim.ReadWrite),
		Sum:           snap.Sum,
		Count:         uint32(snap.Count),
		Min:           snap.Min,
		Max:           snap.Max,
		Hist1us:       uint16(snap.Histogram[0]),
		Hist10us:      uint16(snap.Histogram[1]),
		Hist100us:     uint16(snap.Histogram[2]),
		Hist1ms:       uint16(snap.Histogram[3]),
		Hist10ms:      uint16(snap.Histogram[4]),
		Hist100ms:     uint16(snap.Histogram[5]),
		Hist1s:        uint16(snap.Histogram[6]),
		Hist10s:       uint16(snap.Histogram[7]),
		Hist100s:      uint16(snap.Histogram[8]),
		HistInf:       uint16(snap.Histogram[9]),
	}
}

func (f *flusher) makeDiskCounterRow(metricName string, dim DiskDimension, snap CounterSnapshot) diskRow {
	return diskRow{
		WindowStart:   f.buf.StartTime,
		IntervalMs:    f.intervalMs,
		WallclockSlot: f.wallclockSlot,
		CLSyncing:     f.clSyncing,
		ELOptimistic:  f.elOptimistic,
		ELOffline:     f.elOffline,
		MetricName:    metricName,
		PID:           dim.PID,
		ClientType:    dim.ClientType,
		DeviceID:      dim.DeviceID,
		RW:            RWString(dim.ReadWrite),
		Sum:           snap.Sum,
		Count:         uint32(snap.Count),
	}
}

func (f *flusher) makeDiskGaugeRow(metricName string, dim DiskDimension, snap GaugeSnapshot) diskRow {
	return diskRow{
		WindowStart:   f.buf.StartTime,
		IntervalMs:    f.intervalMs,
		WallclockSlot: f.wallclockSlot,
		CLSyncing:     f.clSyncing,
		ELOptimistic:  f.elOptimistic,
		ELOffline:     f.elOffline,
		MetricName:    metricName,
		PID:           dim.PID,
		ClientType:    dim.ClientType,
		DeviceID:      dim.DeviceID,
		RW:            RWString(dim.ReadWrite),
		Sum:           snap.Sum,
		Count:         uint32(snap.Count),
		Min:           snap.Min,
		Max:           snap.Max,
	}
}

// collectNetwork collects network metrics into networkRows.
func (f *flusher) collectNetwork() {
	// Net I/O (counter).
	for dim, agg := range f.buf.NetIO {
		snap := agg.Snapshot()
		if snap.Count == 0 {
			continue
		}

		f.networkRows = append(f.networkRows, f.makeNetworkCounterRow("net_io", dim, snap))
	}

	// TCP retransmits (counter).
	for dim, agg := range f.buf.TcpRetransmit {
		snap := agg.Snapshot()
		if snap.Count == 0 {
			continue
		}

		f.networkRows = append(f.networkRows, f.makeNetworkCounterRow("tcp_retransmit", dim, snap))
	}

	// TCP RTT (gauge).
	for dim, agg := range f.buf.TcpRTT {
		snap := agg.Snapshot()
		if snap.Count == 0 {
			continue
		}

		f.networkRows = append(f.networkRows, f.makeNetworkGaugeRow("tcp_rtt_us", dim, snap))
	}

	// TCP CWND (gauge).
	for dim, agg := range f.buf.TcpCwnd {
		snap := agg.Snapshot()
		if snap.Count == 0 {
			continue
		}

		f.networkRows = append(f.networkRows, f.makeNetworkGaugeRow("tcp_cwnd", dim, snap))
	}

	// TCP state changes (counter - uses BasicDimension).
	for dim, agg := range f.buf.TcpStateChange {
		snap := agg.Snapshot()
		if snap.Count == 0 {
			continue
		}

		f.networkRows = append(f.networkRows, networkRow{
			WindowStart:   f.buf.StartTime,
			IntervalMs:    f.intervalMs,
			WallclockSlot: f.wallclockSlot,
			CLSyncing:     f.clSyncing,
			ELOptimistic:  f.elOptimistic,
			ELOffline:     f.elOffline,
			MetricName:    "tcp_state_change",
			PID:           dim.PID,
			ClientType:    dim.ClientType,
			Sum:           snap.Sum,
			Count:         uint32(snap.Count),
		})
	}
}

func (f *flusher) makeNetworkCounterRow(metricName string, dim NetworkDimension, snap CounterSnapshot) networkRow {
	return networkRow{
		WindowStart:   f.buf.StartTime,
		IntervalMs:    f.intervalMs,
		WallclockSlot: f.wallclockSlot,
		CLSyncing:     f.clSyncing,
		ELOptimistic:  f.elOptimistic,
		ELOffline:     f.elOffline,
		MetricName:    metricName,
		PID:           dim.PID,
		ClientType:    dim.ClientType,
		LocalPort:     dim.LocalPort,
		Direction:     DirectionString(dim.Direction),
		Sum:           snap.Sum,
		Count:         uint32(snap.Count),
	}
}

func (f *flusher) makeNetworkGaugeRow(metricName string, dim TCPMetricsDimension, snap GaugeSnapshot) networkRow {
	return networkRow{
		WindowStart:   f.buf.StartTime,
		IntervalMs:    f.intervalMs,
		WallclockSlot: f.wallclockSlot,
		CLSyncing:     f.clSyncing,
		ELOptimistic:  f.elOptimistic,
		ELOffline:     f.elOffline,
		MetricName:    metricName,
		PID:           dim.PID,
		ClientType:    dim.ClientType,
		LocalPort:     dim.LocalPort,
		Sum:           snap.Sum,
		Count:         uint32(snap.Count),
		Min:           snap.Min,
		Max:           snap.Max,
	}
}

// collectSyscalls collects syscall metrics into syscallRows.
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
			snap := agg.Snapshot()
			if snap.Count == 0 {
				continue
			}

			f.syscallRows = append(f.syscallRows, f.makeSyscallRow(metricName, dim, snap))
		}
	}
}

func (f *flusher) makeSyscallRow(metricName string, dim BasicDimension, snap LatencySnapshot) syscallRow {
	return syscallRow{
		WindowStart:   f.buf.StartTime,
		IntervalMs:    f.intervalMs,
		WallclockSlot: f.wallclockSlot,
		CLSyncing:     f.clSyncing,
		ELOptimistic:  f.elOptimistic,
		ELOffline:     f.elOffline,
		MetricName:    metricName,
		PID:           dim.PID,
		ClientType:    dim.ClientType,
		Sum:           snap.Sum,
		Count:         uint32(snap.Count),
		Min:           snap.Min,
		Max:           snap.Max,
		Hist1us:       uint16(snap.Histogram[0]),
		Hist10us:      uint16(snap.Histogram[1]),
		Hist100us:     uint16(snap.Histogram[2]),
		Hist1ms:       uint16(snap.Histogram[3]),
		Hist10ms:      uint16(snap.Histogram[4]),
		Hist100ms:     uint16(snap.Histogram[5]),
		Hist1s:        uint16(snap.Histogram[6]),
		Hist10s:       uint16(snap.Histogram[7]),
		Hist100s:      uint16(snap.Histogram[8]),
		HistInf:       uint16(snap.Histogram[9]),
	}
}

// collectProcess collects process metrics into processRows.
func (f *flusher) collectProcess() {
	// FD open.
	for dim, agg := range f.buf.FDOpen {
		snap := agg.Snapshot()
		if snap.Count == 0 {
			continue
		}

		f.processRows = append(f.processRows, f.makeProcessRow("fd_open", dim, snap))
	}

	// FD close.
	for dim, agg := range f.buf.FDClose {
		snap := agg.Snapshot()
		if snap.Count == 0 {
			continue
		}

		f.processRows = append(f.processRows, f.makeProcessRow("fd_close", dim, snap))
	}

	// Process exit.
	for dim, agg := range f.buf.ProcessExit {
		snap := agg.Snapshot()
		if snap.Count == 0 {
			continue
		}

		f.processRows = append(f.processRows, f.makeProcessRow("process_exit", dim, snap))
	}
}

func (f *flusher) makeProcessRow(metricName string, dim BasicDimension, snap CounterSnapshot) processRow {
	return processRow{
		WindowStart:   f.buf.StartTime,
		IntervalMs:    f.intervalMs,
		WallclockSlot: f.wallclockSlot,
		CLSyncing:     f.clSyncing,
		ELOptimistic:  f.elOptimistic,
		ELOffline:     f.elOffline,
		MetricName:    metricName,
		PID:           dim.PID,
		ClientType:    dim.ClientType,
		Sum:           snap.Sum,
		Count:         uint32(snap.Count),
	}
}

// Flush methods for each table.

func (f *flusher) flushCPU(ctx context.Context) error {
	if len(f.cpuRows) == 0 {
		return nil
	}

	conn := f.writer.Conn()
	cfg := f.writer.Config()
	table := fmt.Sprintf("%s.cpu_metrics", cfg.Database)

	batch, err := conn.PrepareBatch(ctx, fmt.Sprintf(`INSERT INTO %s (
		window_start, interval_ms, wallclock_slot,
		cl_syncing, el_optimistic, el_offline,
		metric_name, pid, client_type,
		sum, count, min, max,
		hist_1us, hist_10us, hist_100us, hist_1ms, hist_10ms, hist_100ms, hist_1s, hist_10s, hist_100s, hist_inf
	)`, table))
	if err != nil {
		return fmt.Errorf("preparing cpu_metrics batch: %w", err)
	}

	for _, row := range f.cpuRows {
		if err := batch.Append(
			row.WindowStart, row.IntervalMs, row.WallclockSlot,
			row.CLSyncing, row.ELOptimistic, row.ELOffline,
			row.MetricName, row.PID, row.ClientType,
			row.Sum, row.Count, row.Min, row.Max,
			row.Hist1us, row.Hist10us, row.Hist100us, row.Hist1ms, row.Hist10ms, row.Hist100ms,
			row.Hist1s, row.Hist10s, row.Hist100s, row.HistInf,
		); err != nil {
			return fmt.Errorf("appending cpu_metrics row: %w", err)
		}
	}

	if err := batch.Send(); err != nil {
		f.recordBatchError("cpu_metrics")

		return fmt.Errorf("sending cpu_metrics batch: %w", err)
	}

	return nil
}

func (f *flusher) flushMemory(ctx context.Context) error {
	if len(f.memoryRows) == 0 {
		return nil
	}

	conn := f.writer.Conn()
	cfg := f.writer.Config()
	table := fmt.Sprintf("%s.memory_metrics", cfg.Database)

	batch, err := conn.PrepareBatch(ctx, fmt.Sprintf(`INSERT INTO %s (
		window_start, interval_ms, wallclock_slot,
		cl_syncing, el_optimistic, el_offline,
		metric_name, pid, client_type,
		sum, count, min, max,
		hist_1us, hist_10us, hist_100us, hist_1ms, hist_10ms, hist_100ms, hist_1s, hist_10s, hist_100s, hist_inf
	)`, table))
	if err != nil {
		return fmt.Errorf("preparing memory_metrics batch: %w", err)
	}

	for _, row := range f.memoryRows {
		if err := batch.Append(
			row.WindowStart, row.IntervalMs, row.WallclockSlot,
			row.CLSyncing, row.ELOptimistic, row.ELOffline,
			row.MetricName, row.PID, row.ClientType,
			row.Sum, row.Count, row.Min, row.Max,
			row.Hist1us, row.Hist10us, row.Hist100us, row.Hist1ms, row.Hist10ms, row.Hist100ms,
			row.Hist1s, row.Hist10s, row.Hist100s, row.HistInf,
		); err != nil {
			return fmt.Errorf("appending memory_metrics row: %w", err)
		}
	}

	if err := batch.Send(); err != nil {
		f.recordBatchError("memory_metrics")

		return fmt.Errorf("sending memory_metrics batch: %w", err)
	}

	return nil
}

func (f *flusher) flushDisk(ctx context.Context) error {
	if len(f.diskRows) == 0 {
		return nil
	}

	conn := f.writer.Conn()
	cfg := f.writer.Config()
	table := fmt.Sprintf("%s.disk_metrics", cfg.Database)

	batch, err := conn.PrepareBatch(ctx, fmt.Sprintf(`INSERT INTO %s (
		window_start, interval_ms, wallclock_slot,
		cl_syncing, el_optimistic, el_offline,
		metric_name, pid, client_type,
		device_id, rw,
		sum, count, min, max,
		hist_1us, hist_10us, hist_100us, hist_1ms, hist_10ms, hist_100ms, hist_1s, hist_10s, hist_100s, hist_inf
	)`, table))
	if err != nil {
		return fmt.Errorf("preparing disk_metrics batch: %w", err)
	}

	for _, row := range f.diskRows {
		if err := batch.Append(
			row.WindowStart, row.IntervalMs, row.WallclockSlot,
			row.CLSyncing, row.ELOptimistic, row.ELOffline,
			row.MetricName, row.PID, row.ClientType,
			row.DeviceID, row.RW,
			row.Sum, row.Count, row.Min, row.Max,
			row.Hist1us, row.Hist10us, row.Hist100us, row.Hist1ms, row.Hist10ms, row.Hist100ms,
			row.Hist1s, row.Hist10s, row.Hist100s, row.HistInf,
		); err != nil {
			return fmt.Errorf("appending disk_metrics row: %w", err)
		}
	}

	if err := batch.Send(); err != nil {
		f.recordBatchError("disk_metrics")

		return fmt.Errorf("sending disk_metrics batch: %w", err)
	}

	return nil
}

func (f *flusher) flushNetwork(ctx context.Context) error {
	if len(f.networkRows) == 0 {
		return nil
	}

	conn := f.writer.Conn()
	cfg := f.writer.Config()
	table := fmt.Sprintf("%s.network_metrics", cfg.Database)

	batch, err := conn.PrepareBatch(ctx, fmt.Sprintf(`INSERT INTO %s (
		window_start, interval_ms, wallclock_slot,
		cl_syncing, el_optimistic, el_offline,
		metric_name, pid, client_type,
		local_port, direction,
		sum, count, min, max
	)`, table))
	if err != nil {
		return fmt.Errorf("preparing network_metrics batch: %w", err)
	}

	for _, row := range f.networkRows {
		if err := batch.Append(
			row.WindowStart, row.IntervalMs, row.WallclockSlot,
			row.CLSyncing, row.ELOptimistic, row.ELOffline,
			row.MetricName, row.PID, row.ClientType,
			row.LocalPort, row.Direction,
			row.Sum, row.Count, row.Min, row.Max,
		); err != nil {
			return fmt.Errorf("appending network_metrics row: %w", err)
		}
	}

	if err := batch.Send(); err != nil {
		f.recordBatchError("network_metrics")

		return fmt.Errorf("sending network_metrics batch: %w", err)
	}

	return nil
}

func (f *flusher) flushSyscalls(ctx context.Context) error {
	if len(f.syscallRows) == 0 {
		return nil
	}

	conn := f.writer.Conn()
	cfg := f.writer.Config()
	table := fmt.Sprintf("%s.syscall_metrics", cfg.Database)

	batch, err := conn.PrepareBatch(ctx, fmt.Sprintf(`INSERT INTO %s (
		window_start, interval_ms, wallclock_slot,
		cl_syncing, el_optimistic, el_offline,
		metric_name, pid, client_type,
		sum, count, min, max,
		hist_1us, hist_10us, hist_100us, hist_1ms, hist_10ms, hist_100ms, hist_1s, hist_10s, hist_100s, hist_inf
	)`, table))
	if err != nil {
		return fmt.Errorf("preparing syscall_metrics batch: %w", err)
	}

	for _, row := range f.syscallRows {
		if err := batch.Append(
			row.WindowStart, row.IntervalMs, row.WallclockSlot,
			row.CLSyncing, row.ELOptimistic, row.ELOffline,
			row.MetricName, row.PID, row.ClientType,
			row.Sum, row.Count, row.Min, row.Max,
			row.Hist1us, row.Hist10us, row.Hist100us, row.Hist1ms, row.Hist10ms, row.Hist100ms,
			row.Hist1s, row.Hist10s, row.Hist100s, row.HistInf,
		); err != nil {
			return fmt.Errorf("appending syscall_metrics row: %w", err)
		}
	}

	if err := batch.Send(); err != nil {
		f.recordBatchError("syscall_metrics")

		return fmt.Errorf("sending syscall_metrics batch: %w", err)
	}

	return nil
}

func (f *flusher) flushProcess(ctx context.Context) error {
	if len(f.processRows) == 0 {
		return nil
	}

	conn := f.writer.Conn()
	cfg := f.writer.Config()
	table := fmt.Sprintf("%s.process_metrics", cfg.Database)

	batch, err := conn.PrepareBatch(ctx, fmt.Sprintf(`INSERT INTO %s (
		window_start, interval_ms, wallclock_slot,
		cl_syncing, el_optimistic, el_offline,
		metric_name, pid, client_type,
		sum, count
	)`, table))
	if err != nil {
		return fmt.Errorf("preparing process_metrics batch: %w", err)
	}

	for _, row := range f.processRows {
		if err := batch.Append(
			row.WindowStart, row.IntervalMs, row.WallclockSlot,
			row.CLSyncing, row.ELOptimistic, row.ELOffline,
			row.MetricName, row.PID, row.ClientType,
			row.Sum, row.Count,
		); err != nil {
			return fmt.Errorf("appending process_metrics row: %w", err)
		}
	}

	if err := batch.Send(); err != nil {
		f.recordBatchError("process_metrics")

		return fmt.Errorf("sending process_metrics batch: %w", err)
	}

	return nil
}

func (f *flusher) recordBatchError(table string) {
	if f.health != nil {
		f.health.ExportBatchErrors.WithLabelValues("aggregated", table).Inc()
	}
}
