package aggregated

import (
	"context"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/ethpandaops/observoor/internal/export"
)

// Row types for individual metric tables.
// No metric_name column - the table IS the metric.
// No sync state columns - those go to sync_state table.

// latencyRow is for 14 latency tables with histogram.
type latencyRow struct {
	UpdatedDateTime            time.Time
	WindowStart                time.Time
	IntervalMs                 uint16
	WallclockSlot              uint32
	WallclockSlotStartDateTime time.Time
	PID                        uint32
	ClientType                 string
	Sum                        int64
	Count                      uint32
	Min                        int64
	Max                        int64
	Hist1us                    uint32
	Hist10us                   uint32
	Hist100us                  uint32
	Hist1ms                    uint32
	Hist10ms                   uint32
	Hist100ms                  uint32
	Hist1s                     uint32
	Hist10s                    uint32
	Hist100s                   uint32
	HistInf                    uint32
}

// diskLatencyRow is for disk_latency table with device_id and rw dimensions.
type diskLatencyRow struct {
	latencyRow
	DeviceID uint32
	RW       string
}

// counterRow is for 13 counter tables (sum/count only).
type counterRow struct {
	UpdatedDateTime            time.Time
	WindowStart                time.Time
	IntervalMs                 uint16
	WallclockSlot              uint32
	WallclockSlotStartDateTime time.Time
	PID                        uint32
	ClientType                 string
	Sum                        int64
	Count                      uint32
}

// diskCounterRow is for disk counter tables with device_id and rw dimensions.
type diskCounterRow struct {
	counterRow
	DeviceID uint32
	RW       string
}

// networkCounterRow is for network counter tables with local_port and direction.
type networkCounterRow struct {
	counterRow
	LocalPort uint16
	Direction string
}

// gaugeRow is for 3 gauge tables (sum/count/min/max, no histogram).
type gaugeRow struct {
	UpdatedDateTime            time.Time
	WindowStart                time.Time
	IntervalMs                 uint16
	WallclockSlot              uint32
	WallclockSlotStartDateTime time.Time
	PID                        uint32
	ClientType                 string
	Sum                        int64
	Count                      uint32
	Min                        int64
	Max                        int64
}

// tcpGaugeRow is for TCP gauge tables with local_port dimension.
type tcpGaugeRow struct {
	gaugeRow
	LocalPort uint16
}

// diskGaugeRow is for disk gauge tables with device_id and rw dimensions.
type diskGaugeRow struct {
	gaugeRow
	DeviceID uint32
	RW       string
}

// syncStateRow is for the sync_state table.
type syncStateRow struct {
	UpdatedDateTime            time.Time
	EventTime                  time.Time
	WallclockSlot              uint32
	WallclockSlotStartDateTime time.Time
	CLSyncing                  bool
	ELOptimistic               bool
	ELOffline                  bool
}

// flusher handles writing aggregated data to ClickHouse.
type flusher struct {
	log                        logrus.FieldLogger
	writer                     *export.ClickHouseWriter
	cfg                        Config
	health                     *export.HealthMetrics
	intervalMs                 uint16
	wallclockSlot              uint32
	wallclockSlotStartDateTime time.Time
	updatedDateTime            time.Time
	buf                        *Buffer

	// Per-table row buffers - latency tables (14).
	syscallReadRows      []latencyRow
	syscallWriteRows     []latencyRow
	syscallFutexRows     []latencyRow
	syscallMmapRows      []latencyRow
	syscallEpollWaitRows []latencyRow
	syscallFsyncRows     []latencyRow
	syscallFdatasyncRows []latencyRow
	syscallPwriteRows    []latencyRow
	schedOnCpuRows       []latencyRow
	schedOffCpuRows      []latencyRow
	schedRunqueueRows    []latencyRow
	memReclaimRows       []latencyRow
	memCompactionRows    []latencyRow
	diskLatencyRows      []diskLatencyRow

	// Per-table row buffers - counter tables (13).
	pageFaultMajorRows []counterRow
	pageFaultMinorRows []counterRow
	swapInRows         []counterRow
	swapOutRows        []counterRow
	oomKillRows        []counterRow
	fdOpenRows         []counterRow
	fdCloseRows        []counterRow
	processExitRows    []counterRow
	tcpStateChangeRows []counterRow
	netIORows          []networkCounterRow
	tcpRetransmitRows  []networkCounterRow
	diskBytesRows      []diskCounterRow
	blockMergeRows     []diskCounterRow

	// Per-table row buffers - gauge tables (3).
	tcpRTTRows        []tcpGaugeRow
	tcpCwndRows       []tcpGaugeRow
	diskQueueDepthRow []diskGaugeRow
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
		// Initialize slices with capacity hints.
		syscallReadRows:      make([]latencyRow, 0, 64),
		syscallWriteRows:     make([]latencyRow, 0, 64),
		syscallFutexRows:     make([]latencyRow, 0, 64),
		syscallMmapRows:      make([]latencyRow, 0, 32),
		syscallEpollWaitRows: make([]latencyRow, 0, 64),
		syscallFsyncRows:     make([]latencyRow, 0, 32),
		syscallFdatasyncRows: make([]latencyRow, 0, 32),
		syscallPwriteRows:    make([]latencyRow, 0, 32),
		schedOnCpuRows:       make([]latencyRow, 0, 64),
		schedOffCpuRows:      make([]latencyRow, 0, 64),
		schedRunqueueRows:    make([]latencyRow, 0, 64),
		memReclaimRows:       make([]latencyRow, 0, 16),
		memCompactionRows:    make([]latencyRow, 0, 16),
		diskLatencyRows:      make([]diskLatencyRow, 0, 64),
		pageFaultMajorRows:   make([]counterRow, 0, 32),
		pageFaultMinorRows:   make([]counterRow, 0, 32),
		swapInRows:           make([]counterRow, 0, 16),
		swapOutRows:          make([]counterRow, 0, 16),
		oomKillRows:          make([]counterRow, 0, 8),
		fdOpenRows:           make([]counterRow, 0, 32),
		fdCloseRows:          make([]counterRow, 0, 32),
		processExitRows:      make([]counterRow, 0, 8),
		tcpStateChangeRows:   make([]counterRow, 0, 32),
		netIORows:            make([]networkCounterRow, 0, 128),
		tcpRetransmitRows:    make([]networkCounterRow, 0, 32),
		diskBytesRows:        make([]diskCounterRow, 0, 64),
		blockMergeRows:       make([]diskCounterRow, 0, 32),
		tcpRTTRows:           make([]tcpGaugeRow, 0, 64),
		tcpCwndRows:          make([]tcpGaugeRow, 0, 64),
		diskQueueDepthRow:    make([]diskGaugeRow, 0, 64),
	}
}

// Flush writes all aggregated data from the buffer to ClickHouse.
func (f *flusher) Flush(ctx context.Context, buf *Buffer) error {
	f.intervalMs = uint16(f.cfg.Resolution.Interval.Milliseconds())
	f.wallclockSlot = uint32(buf.WallclockSlot)
	f.wallclockSlotStartDateTime = buf.WallclockSlotStartDateTime
	f.updatedDateTime = time.Now()
	f.buf = buf

	// Collect rows into per-table buffers.
	f.collectSyscalls()
	f.collectScheduler()
	f.collectMemory()
	f.collectDisk()
	f.collectNetwork()
	f.collectProcess()

	// Flush each table.
	var totalRows int

	// Syscall tables.
	tables := []struct {
		name string
		rows []latencyRow
	}{
		{"syscall_read", f.syscallReadRows},
		{"syscall_write", f.syscallWriteRows},
		{"syscall_futex", f.syscallFutexRows},
		{"syscall_mmap", f.syscallMmapRows},
		{"syscall_epoll_wait", f.syscallEpollWaitRows},
		{"syscall_fsync", f.syscallFsyncRows},
		{"syscall_fdatasync", f.syscallFdatasyncRows},
		{"syscall_pwrite", f.syscallPwriteRows},
		{"sched_on_cpu", f.schedOnCpuRows},
		{"sched_off_cpu", f.schedOffCpuRows},
		{"sched_runqueue", f.schedRunqueueRows},
		{"mem_reclaim", f.memReclaimRows},
		{"mem_compaction", f.memCompactionRows},
	}

	for _, t := range tables {
		if err := f.flushLatencyTable(ctx, t.name, t.rows); err != nil {
			return err
		}

		totalRows += len(t.rows)
	}

	// Disk latency table.
	if err := f.flushDiskLatencyTable(ctx); err != nil {
		return err
	}

	totalRows += len(f.diskLatencyRows)

	// Counter tables.
	counterTables := []struct {
		name string
		rows []counterRow
	}{
		{"page_fault_major", f.pageFaultMajorRows},
		{"page_fault_minor", f.pageFaultMinorRows},
		{"swap_in", f.swapInRows},
		{"swap_out", f.swapOutRows},
		{"oom_kill", f.oomKillRows},
		{"fd_open", f.fdOpenRows},
		{"fd_close", f.fdCloseRows},
		{"process_exit", f.processExitRows},
		{"tcp_state_change", f.tcpStateChangeRows},
	}

	for _, t := range counterTables {
		if err := f.flushCounterTable(ctx, t.name, t.rows); err != nil {
			return err
		}

		totalRows += len(t.rows)
	}

	// Network counter tables.
	if err := f.flushNetworkCounterTable(ctx, "net_io", f.netIORows); err != nil {
		return err
	}

	totalRows += len(f.netIORows)

	if err := f.flushNetworkCounterTable(ctx, "tcp_retransmit", f.tcpRetransmitRows); err != nil {
		return err
	}

	totalRows += len(f.tcpRetransmitRows)

	// Disk counter tables.
	if err := f.flushDiskCounterTable(ctx, "disk_bytes", f.diskBytesRows); err != nil {
		return err
	}

	totalRows += len(f.diskBytesRows)

	if err := f.flushDiskCounterTable(ctx, "block_merge", f.blockMergeRows); err != nil {
		return err
	}

	totalRows += len(f.blockMergeRows)

	// Gauge tables.
	if err := f.flushTcpGaugeTable(ctx, "tcp_rtt", f.tcpRTTRows); err != nil {
		return err
	}

	totalRows += len(f.tcpRTTRows)

	if err := f.flushTcpGaugeTable(ctx, "tcp_cwnd", f.tcpCwndRows); err != nil {
		return err
	}

	totalRows += len(f.tcpCwndRows)

	if err := f.flushDiskGaugeTable(ctx); err != nil {
		return err
	}

	totalRows += len(f.diskQueueDepthRow)

	if totalRows > 0 {
		if f.health != nil {
			f.health.SinkBatchSize.WithLabelValues("aggregated").Observe(float64(totalRows))
		}

		f.log.WithField("rows", totalRows).Debug("Flushed aggregated metrics")
	}

	return nil
}

// collectSyscalls collects syscall latency metrics.
func (f *flusher) collectSyscalls() {
	syscallMaps := map[string]*[]latencyRow{
		"syscall_read":       &f.syscallReadRows,
		"syscall_write":      &f.syscallWriteRows,
		"syscall_futex":      &f.syscallFutexRows,
		"syscall_mmap":       &f.syscallMmapRows,
		"syscall_epoll_wait": &f.syscallEpollWaitRows,
		"syscall_fsync":      &f.syscallFsyncRows,
		"syscall_fdatasync":  &f.syscallFdatasyncRows,
		"syscall_pwrite":     &f.syscallPwriteRows,
	}

	bufMaps := map[string]map[BasicDimension]*LatencyAggregate{
		"syscall_read":       f.buf.SyscallRead,
		"syscall_write":      f.buf.SyscallWrite,
		"syscall_futex":      f.buf.SyscallFutex,
		"syscall_mmap":       f.buf.SyscallMmap,
		"syscall_epoll_wait": f.buf.SyscallEpollWait,
		"syscall_fsync":      f.buf.SyscallFsync,
		"syscall_fdatasync":  f.buf.SyscallFdatasync,
		"syscall_pwrite":     f.buf.SyscallPwrite,
	}

	for name, rows := range syscallMaps {
		m := bufMaps[name]
		for dim, agg := range m {
			snap := agg.Snapshot()
			if snap.Count == 0 {
				continue
			}

			*rows = append(*rows, f.makeLatencyRow(dim, snap))
		}
	}
}

// collectScheduler collects scheduler latency metrics.
func (f *flusher) collectScheduler() {
	// On-CPU time.
	for dim, agg := range f.buf.SchedSwitch {
		snap := agg.Snapshot()
		if snap.Count == 0 {
			continue
		}

		f.schedOnCpuRows = append(f.schedOnCpuRows, f.makeLatencyRow(dim, snap))
	}

	// Off-CPU time.
	for dim, agg := range f.buf.SchedOffCpu {
		snap := agg.Snapshot()
		if snap.Count == 0 {
			continue
		}

		f.schedOffCpuRows = append(f.schedOffCpuRows, f.makeLatencyRow(dim, snap))
	}

	// Runqueue latency.
	for dim, agg := range f.buf.SchedRunqueue {
		snap := agg.Snapshot()
		if snap.Count == 0 {
			continue
		}

		f.schedRunqueueRows = append(f.schedRunqueueRows, f.makeLatencyRow(dim, snap))
	}
}

// collectMemory collects memory metrics.
func (f *flusher) collectMemory() {
	// Memory reclaim (latency).
	for dim, agg := range f.buf.MemReclaim {
		snap := agg.Snapshot()
		if snap.Count == 0 {
			continue
		}

		f.memReclaimRows = append(f.memReclaimRows, f.makeLatencyRow(dim, snap))
	}

	// Memory compaction (latency).
	for dim, agg := range f.buf.MemCompaction {
		snap := agg.Snapshot()
		if snap.Count == 0 {
			continue
		}

		f.memCompactionRows = append(f.memCompactionRows, f.makeLatencyRow(dim, snap))
	}

	// Page faults (counters).
	for dim, agg := range f.buf.PageFaultMajor {
		snap := agg.Snapshot()
		if snap.Count == 0 {
			continue
		}

		f.pageFaultMajorRows = append(f.pageFaultMajorRows, f.makeCounterRow(dim, snap))
	}

	for dim, agg := range f.buf.PageFaultMinor {
		snap := agg.Snapshot()
		if snap.Count == 0 {
			continue
		}

		f.pageFaultMinorRows = append(f.pageFaultMinorRows, f.makeCounterRow(dim, snap))
	}

	// Swap (counters).
	for dim, agg := range f.buf.SwapIn {
		snap := agg.Snapshot()
		if snap.Count == 0 {
			continue
		}

		f.swapInRows = append(f.swapInRows, f.makeCounterRow(dim, snap))
	}

	for dim, agg := range f.buf.SwapOut {
		snap := agg.Snapshot()
		if snap.Count == 0 {
			continue
		}

		f.swapOutRows = append(f.swapOutRows, f.makeCounterRow(dim, snap))
	}

	// OOM kills (counter).
	for dim, agg := range f.buf.OOMKill {
		snap := agg.Snapshot()
		if snap.Count == 0 {
			continue
		}

		f.oomKillRows = append(f.oomKillRows, f.makeCounterRow(dim, snap))
	}
}

// collectDisk collects disk metrics.
func (f *flusher) collectDisk() {
	// Disk latency (with histogram).
	for dim, agg := range f.buf.DiskLatency {
		snap := agg.Snapshot()
		if snap.Count == 0 {
			continue
		}

		f.diskLatencyRows = append(f.diskLatencyRows, f.makeDiskLatencyRow(dim, snap))
	}

	// Disk bytes (counter).
	for dim, agg := range f.buf.DiskBytes {
		snap := agg.Snapshot()
		if snap.Count == 0 {
			continue
		}

		f.diskBytesRows = append(f.diskBytesRows, f.makeDiskCounterRow(dim, snap))
	}

	// Block merge (counter).
	for dim, agg := range f.buf.BlockMerge {
		snap := agg.Snapshot()
		if snap.Count == 0 {
			continue
		}

		f.blockMergeRows = append(f.blockMergeRows, f.makeDiskCounterRow(dim, snap))
	}

	// Disk queue depth (gauge).
	for dim, agg := range f.buf.DiskQueueDepth {
		snap := agg.Snapshot()
		if snap.Count == 0 {
			continue
		}

		f.diskQueueDepthRow = append(f.diskQueueDepthRow, f.makeDiskGaugeRow(dim, snap))
	}
}

// collectNetwork collects network metrics.
func (f *flusher) collectNetwork() {
	// Net I/O (counter).
	for dim, agg := range f.buf.NetIO {
		snap := agg.Snapshot()
		if snap.Count == 0 {
			continue
		}

		f.netIORows = append(f.netIORows, f.makeNetworkCounterRow(dim, snap))
	}

	// TCP retransmits (counter).
	for dim, agg := range f.buf.TcpRetransmit {
		snap := agg.Snapshot()
		if snap.Count == 0 {
			continue
		}

		f.tcpRetransmitRows = append(f.tcpRetransmitRows, f.makeNetworkCounterRow(dim, snap))
	}

	// TCP RTT (gauge).
	for dim, agg := range f.buf.TcpRTT {
		snap := agg.Snapshot()
		if snap.Count == 0 {
			continue
		}

		f.tcpRTTRows = append(f.tcpRTTRows, f.makeTcpGaugeRow(dim, snap))
	}

	// TCP CWND (gauge).
	for dim, agg := range f.buf.TcpCwnd {
		snap := agg.Snapshot()
		if snap.Count == 0 {
			continue
		}

		f.tcpCwndRows = append(f.tcpCwndRows, f.makeTcpGaugeRow(dim, snap))
	}

	// TCP state changes (counter - basic dimension).
	for dim, agg := range f.buf.TcpStateChange {
		snap := agg.Snapshot()
		if snap.Count == 0 {
			continue
		}

		f.tcpStateChangeRows = append(f.tcpStateChangeRows, f.makeCounterRow(dim, snap))
	}
}

// collectProcess collects process metrics.
func (f *flusher) collectProcess() {
	// FD open.
	for dim, agg := range f.buf.FDOpen {
		snap := agg.Snapshot()
		if snap.Count == 0 {
			continue
		}

		f.fdOpenRows = append(f.fdOpenRows, f.makeCounterRow(dim, snap))
	}

	// FD close.
	for dim, agg := range f.buf.FDClose {
		snap := agg.Snapshot()
		if snap.Count == 0 {
			continue
		}

		f.fdCloseRows = append(f.fdCloseRows, f.makeCounterRow(dim, snap))
	}

	// Process exit.
	for dim, agg := range f.buf.ProcessExit {
		snap := agg.Snapshot()
		if snap.Count == 0 {
			continue
		}

		f.processExitRows = append(f.processExitRows, f.makeCounterRow(dim, snap))
	}
}

// Row construction helpers.

func (f *flusher) makeLatencyRow(dim BasicDimension, snap LatencySnapshot) latencyRow {
	return latencyRow{
		UpdatedDateTime:            f.updatedDateTime,
		WindowStart:                f.buf.StartTime,
		IntervalMs:                 f.intervalMs,
		WallclockSlot:              f.wallclockSlot,
		WallclockSlotStartDateTime: f.wallclockSlotStartDateTime,
		PID:                        dim.PID,
		ClientType:                 dim.ClientType,
		Sum:                        snap.Sum,
		Count:                      uint32(snap.Count),
		Min:                        snap.Min,
		Max:                        snap.Max,
		Hist1us:                    uint32(snap.Histogram[0]),
		Hist10us:                   uint32(snap.Histogram[1]),
		Hist100us:                  uint32(snap.Histogram[2]),
		Hist1ms:                    uint32(snap.Histogram[3]),
		Hist10ms:                   uint32(snap.Histogram[4]),
		Hist100ms:                  uint32(snap.Histogram[5]),
		Hist1s:                     uint32(snap.Histogram[6]),
		Hist10s:                    uint32(snap.Histogram[7]),
		Hist100s:                   uint32(snap.Histogram[8]),
		HistInf:                    uint32(snap.Histogram[9]),
	}
}

func (f *flusher) makeDiskLatencyRow(dim DiskDimension, snap LatencySnapshot) diskLatencyRow {
	return diskLatencyRow{
		latencyRow: latencyRow{
			UpdatedDateTime:            f.updatedDateTime,
			WindowStart:                f.buf.StartTime,
			IntervalMs:                 f.intervalMs,
			WallclockSlot:              f.wallclockSlot,
			WallclockSlotStartDateTime: f.wallclockSlotStartDateTime,
			PID:                        dim.PID,
			ClientType:                 dim.ClientType,
			Sum:                        snap.Sum,
			Count:                      uint32(snap.Count),
			Min:                        snap.Min,
			Max:                        snap.Max,
			Hist1us:                    uint32(snap.Histogram[0]),
			Hist10us:                   uint32(snap.Histogram[1]),
			Hist100us:                  uint32(snap.Histogram[2]),
			Hist1ms:                    uint32(snap.Histogram[3]),
			Hist10ms:                   uint32(snap.Histogram[4]),
			Hist100ms:                  uint32(snap.Histogram[5]),
			Hist1s:                     uint32(snap.Histogram[6]),
			Hist10s:                    uint32(snap.Histogram[7]),
			Hist100s:                   uint32(snap.Histogram[8]),
			HistInf:                    uint32(snap.Histogram[9]),
		},
		DeviceID: dim.DeviceID,
		RW:       RWString(dim.ReadWrite),
	}
}

func (f *flusher) makeCounterRow(dim BasicDimension, snap CounterSnapshot) counterRow {
	return counterRow{
		UpdatedDateTime:            f.updatedDateTime,
		WindowStart:                f.buf.StartTime,
		IntervalMs:                 f.intervalMs,
		WallclockSlot:              f.wallclockSlot,
		WallclockSlotStartDateTime: f.wallclockSlotStartDateTime,
		PID:                        dim.PID,
		ClientType:                 dim.ClientType,
		Sum:                        snap.Sum,
		Count:                      uint32(snap.Count),
	}
}

func (f *flusher) makeDiskCounterRow(dim DiskDimension, snap CounterSnapshot) diskCounterRow {
	return diskCounterRow{
		counterRow: counterRow{
			UpdatedDateTime:            f.updatedDateTime,
			WindowStart:                f.buf.StartTime,
			IntervalMs:                 f.intervalMs,
			WallclockSlot:              f.wallclockSlot,
			WallclockSlotStartDateTime: f.wallclockSlotStartDateTime,
			PID:                        dim.PID,
			ClientType:                 dim.ClientType,
			Sum:                        snap.Sum,
			Count:                      uint32(snap.Count),
		},
		DeviceID: dim.DeviceID,
		RW:       RWString(dim.ReadWrite),
	}
}

func (f *flusher) makeNetworkCounterRow(dim NetworkDimension, snap CounterSnapshot) networkCounterRow {
	return networkCounterRow{
		counterRow: counterRow{
			UpdatedDateTime:            f.updatedDateTime,
			WindowStart:                f.buf.StartTime,
			IntervalMs:                 f.intervalMs,
			WallclockSlot:              f.wallclockSlot,
			WallclockSlotStartDateTime: f.wallclockSlotStartDateTime,
			PID:                        dim.PID,
			ClientType:                 dim.ClientType,
			Sum:                        snap.Sum,
			Count:                      uint32(snap.Count),
		},
		LocalPort: dim.LocalPort,
		Direction: DirectionString(dim.Direction),
	}
}

func (f *flusher) makeTcpGaugeRow(dim TCPMetricsDimension, snap GaugeSnapshot) tcpGaugeRow {
	return tcpGaugeRow{
		gaugeRow: gaugeRow{
			UpdatedDateTime:            f.updatedDateTime,
			WindowStart:                f.buf.StartTime,
			IntervalMs:                 f.intervalMs,
			WallclockSlot:              f.wallclockSlot,
			WallclockSlotStartDateTime: f.wallclockSlotStartDateTime,
			PID:                        dim.PID,
			ClientType:                 dim.ClientType,
			Sum:                        snap.Sum,
			Count:                      uint32(snap.Count),
			Min:                        snap.Min,
			Max:                        snap.Max,
		},
		LocalPort: dim.LocalPort,
	}
}

func (f *flusher) makeDiskGaugeRow(dim DiskDimension, snap GaugeSnapshot) diskGaugeRow {
	return diskGaugeRow{
		gaugeRow: gaugeRow{
			UpdatedDateTime:            f.updatedDateTime,
			WindowStart:                f.buf.StartTime,
			IntervalMs:                 f.intervalMs,
			WallclockSlot:              f.wallclockSlot,
			WallclockSlotStartDateTime: f.wallclockSlotStartDateTime,
			PID:                        dim.PID,
			ClientType:                 dim.ClientType,
			Sum:                        snap.Sum,
			Count:                      uint32(snap.Count),
			Min:                        snap.Min,
			Max:                        snap.Max,
		},
		DeviceID: dim.DeviceID,
		RW:       RWString(dim.ReadWrite),
	}
}

// Flush methods for each table type.

func (f *flusher) flushLatencyTable(ctx context.Context, tableName string, rows []latencyRow) error {
	if len(rows) == 0 {
		return nil
	}

	conn := f.writer.Conn()
	cfg := f.writer.Config()
	table := fmt.Sprintf("%s.%s", cfg.Database, tableName)

	batch, err := conn.PrepareBatch(ctx, fmt.Sprintf(`INSERT INTO %s (
		updated_date_time, window_start, interval_ms, wallclock_slot, wallclock_slot_start_date_time,
		pid, client_type, sum, count, min, max,
		hist_1us, hist_10us, hist_100us, hist_1ms, hist_10ms, hist_100ms, hist_1s, hist_10s, hist_100s, hist_inf,
		meta_client_name, meta_network_name
	)`, table))
	if err != nil {
		return fmt.Errorf("preparing %s batch: %w", tableName, err)
	}

	for _, row := range rows {
		if err := batch.Append(
			row.UpdatedDateTime, row.WindowStart, row.IntervalMs, row.WallclockSlot, row.WallclockSlotStartDateTime,
			row.PID, row.ClientType, row.Sum, row.Count, row.Min, row.Max,
			row.Hist1us, row.Hist10us, row.Hist100us, row.Hist1ms, row.Hist10ms, row.Hist100ms,
			row.Hist1s, row.Hist10s, row.Hist100s, row.HistInf,
			f.cfg.ClickHouse.MetaClientName, f.cfg.ClickHouse.MetaNetworkName,
		); err != nil {
			return fmt.Errorf("appending %s row: %w", tableName, err)
		}
	}

	if err := batch.Send(); err != nil {
		f.recordBatchError(tableName)

		return fmt.Errorf("sending %s batch: %w", tableName, err)
	}

	return nil
}

func (f *flusher) flushDiskLatencyTable(ctx context.Context) error {
	if len(f.diskLatencyRows) == 0 {
		return nil
	}

	conn := f.writer.Conn()
	cfg := f.writer.Config()
	table := fmt.Sprintf("%s.disk_latency", cfg.Database)

	batch, err := conn.PrepareBatch(ctx, fmt.Sprintf(`INSERT INTO %s (
		updated_date_time, window_start, interval_ms, wallclock_slot, wallclock_slot_start_date_time,
		pid, client_type, device_id, rw,
		sum, count, min, max,
		hist_1us, hist_10us, hist_100us, hist_1ms, hist_10ms, hist_100ms, hist_1s, hist_10s, hist_100s, hist_inf,
		meta_client_name, meta_network_name
	)`, table))
	if err != nil {
		return fmt.Errorf("preparing disk_latency batch: %w", err)
	}

	for _, row := range f.diskLatencyRows {
		if err := batch.Append(
			row.UpdatedDateTime, row.WindowStart, row.IntervalMs, row.WallclockSlot, row.WallclockSlotStartDateTime,
			row.PID, row.ClientType, row.DeviceID, row.RW,
			row.Sum, row.Count, row.Min, row.Max,
			row.Hist1us, row.Hist10us, row.Hist100us, row.Hist1ms, row.Hist10ms, row.Hist100ms,
			row.Hist1s, row.Hist10s, row.Hist100s, row.HistInf,
			f.cfg.ClickHouse.MetaClientName, f.cfg.ClickHouse.MetaNetworkName,
		); err != nil {
			return fmt.Errorf("appending disk_latency row: %w", err)
		}
	}

	if err := batch.Send(); err != nil {
		f.recordBatchError("disk_latency")

		return fmt.Errorf("sending disk_latency batch: %w", err)
	}

	return nil
}

func (f *flusher) flushCounterTable(ctx context.Context, tableName string, rows []counterRow) error {
	if len(rows) == 0 {
		return nil
	}

	conn := f.writer.Conn()
	cfg := f.writer.Config()
	table := fmt.Sprintf("%s.%s", cfg.Database, tableName)

	batch, err := conn.PrepareBatch(ctx, fmt.Sprintf(`INSERT INTO %s (
		updated_date_time, window_start, interval_ms, wallclock_slot, wallclock_slot_start_date_time,
		pid, client_type, sum, count,
		meta_client_name, meta_network_name
	)`, table))
	if err != nil {
		return fmt.Errorf("preparing %s batch: %w", tableName, err)
	}

	for _, row := range rows {
		if err := batch.Append(
			row.UpdatedDateTime, row.WindowStart, row.IntervalMs, row.WallclockSlot, row.WallclockSlotStartDateTime,
			row.PID, row.ClientType, row.Sum, row.Count,
			f.cfg.ClickHouse.MetaClientName, f.cfg.ClickHouse.MetaNetworkName,
		); err != nil {
			return fmt.Errorf("appending %s row: %w", tableName, err)
		}
	}

	if err := batch.Send(); err != nil {
		f.recordBatchError(tableName)

		return fmt.Errorf("sending %s batch: %w", tableName, err)
	}

	return nil
}

func (f *flusher) flushDiskCounterTable(ctx context.Context, tableName string, rows []diskCounterRow) error {
	if len(rows) == 0 {
		return nil
	}

	conn := f.writer.Conn()
	cfg := f.writer.Config()
	table := fmt.Sprintf("%s.%s", cfg.Database, tableName)

	batch, err := conn.PrepareBatch(ctx, fmt.Sprintf(`INSERT INTO %s (
		updated_date_time, window_start, interval_ms, wallclock_slot, wallclock_slot_start_date_time,
		pid, client_type, device_id, rw, sum, count,
		meta_client_name, meta_network_name
	)`, table))
	if err != nil {
		return fmt.Errorf("preparing %s batch: %w", tableName, err)
	}

	for _, row := range rows {
		if err := batch.Append(
			row.UpdatedDateTime, row.WindowStart, row.IntervalMs, row.WallclockSlot, row.WallclockSlotStartDateTime,
			row.PID, row.ClientType, row.DeviceID, row.RW, row.Sum, row.Count,
			f.cfg.ClickHouse.MetaClientName, f.cfg.ClickHouse.MetaNetworkName,
		); err != nil {
			return fmt.Errorf("appending %s row: %w", tableName, err)
		}
	}

	if err := batch.Send(); err != nil {
		f.recordBatchError(tableName)

		return fmt.Errorf("sending %s batch: %w", tableName, err)
	}

	return nil
}

func (f *flusher) flushNetworkCounterTable(ctx context.Context, tableName string, rows []networkCounterRow) error {
	if len(rows) == 0 {
		return nil
	}

	conn := f.writer.Conn()
	cfg := f.writer.Config()
	table := fmt.Sprintf("%s.%s", cfg.Database, tableName)

	batch, err := conn.PrepareBatch(ctx, fmt.Sprintf(`INSERT INTO %s (
		updated_date_time, window_start, interval_ms, wallclock_slot, wallclock_slot_start_date_time,
		pid, client_type, local_port, direction, sum, count,
		meta_client_name, meta_network_name
	)`, table))
	if err != nil {
		return fmt.Errorf("preparing %s batch: %w", tableName, err)
	}

	for _, row := range rows {
		if err := batch.Append(
			row.UpdatedDateTime, row.WindowStart, row.IntervalMs, row.WallclockSlot, row.WallclockSlotStartDateTime,
			row.PID, row.ClientType, row.LocalPort, row.Direction, row.Sum, row.Count,
			f.cfg.ClickHouse.MetaClientName, f.cfg.ClickHouse.MetaNetworkName,
		); err != nil {
			return fmt.Errorf("appending %s row: %w", tableName, err)
		}
	}

	if err := batch.Send(); err != nil {
		f.recordBatchError(tableName)

		return fmt.Errorf("sending %s batch: %w", tableName, err)
	}

	return nil
}

func (f *flusher) flushTcpGaugeTable(ctx context.Context, tableName string, rows []tcpGaugeRow) error {
	if len(rows) == 0 {
		return nil
	}

	conn := f.writer.Conn()
	cfg := f.writer.Config()
	table := fmt.Sprintf("%s.%s", cfg.Database, tableName)

	batch, err := conn.PrepareBatch(ctx, fmt.Sprintf(`INSERT INTO %s (
		updated_date_time, window_start, interval_ms, wallclock_slot, wallclock_slot_start_date_time,
		pid, client_type, local_port, sum, count, min, max,
		meta_client_name, meta_network_name
	)`, table))
	if err != nil {
		return fmt.Errorf("preparing %s batch: %w", tableName, err)
	}

	for _, row := range rows {
		if err := batch.Append(
			row.UpdatedDateTime, row.WindowStart, row.IntervalMs, row.WallclockSlot, row.WallclockSlotStartDateTime,
			row.PID, row.ClientType, row.LocalPort, row.Sum, row.Count, row.Min, row.Max,
			f.cfg.ClickHouse.MetaClientName, f.cfg.ClickHouse.MetaNetworkName,
		); err != nil {
			return fmt.Errorf("appending %s row: %w", tableName, err)
		}
	}

	if err := batch.Send(); err != nil {
		f.recordBatchError(tableName)

		return fmt.Errorf("sending %s batch: %w", tableName, err)
	}

	return nil
}

func (f *flusher) flushDiskGaugeTable(ctx context.Context) error {
	if len(f.diskQueueDepthRow) == 0 {
		return nil
	}

	conn := f.writer.Conn()
	cfg := f.writer.Config()
	table := fmt.Sprintf("%s.disk_queue_depth", cfg.Database)

	batch, err := conn.PrepareBatch(ctx, fmt.Sprintf(`INSERT INTO %s (
		updated_date_time, window_start, interval_ms, wallclock_slot, wallclock_slot_start_date_time,
		pid, client_type, device_id, rw, sum, count, min, max,
		meta_client_name, meta_network_name
	)`, table))
	if err != nil {
		return fmt.Errorf("preparing disk_queue_depth batch: %w", err)
	}

	for _, row := range f.diskQueueDepthRow {
		if err := batch.Append(
			row.UpdatedDateTime, row.WindowStart, row.IntervalMs, row.WallclockSlot, row.WallclockSlotStartDateTime,
			row.PID, row.ClientType, row.DeviceID, row.RW, row.Sum, row.Count, row.Min, row.Max,
			f.cfg.ClickHouse.MetaClientName, f.cfg.ClickHouse.MetaNetworkName,
		); err != nil {
			return fmt.Errorf("appending disk_queue_depth row: %w", err)
		}
	}

	if err := batch.Send(); err != nil {
		f.recordBatchError("disk_queue_depth")

		return fmt.Errorf("sending disk_queue_depth batch: %w", err)
	}

	return nil
}

func (f *flusher) recordBatchError(table string) {
	if f.health != nil {
		f.health.ExportBatchErrors.WithLabelValues("aggregated", table).Inc()
	}
}

// FlushSyncState writes a sync state row to ClickHouse.
func FlushSyncState(
	ctx context.Context,
	writer *export.ClickHouseWriter,
	cfg Config,
	health *export.HealthMetrics,
	row syncStateRow,
) error {
	conn := writer.Conn()
	chCfg := writer.Config()
	table := fmt.Sprintf("%s.sync_state", chCfg.Database)

	batch, err := conn.PrepareBatch(ctx, fmt.Sprintf(`INSERT INTO %s (
		updated_date_time, event_time, wallclock_slot, wallclock_slot_start_date_time,
		cl_syncing, el_optimistic, el_offline,
		meta_client_name, meta_network_name
	)`, table))
	if err != nil {
		return fmt.Errorf("preparing sync_state batch: %w", err)
	}

	if err := batch.Append(
		row.UpdatedDateTime, row.EventTime, row.WallclockSlot, row.WallclockSlotStartDateTime,
		row.CLSyncing, row.ELOptimistic, row.ELOffline,
		cfg.ClickHouse.MetaClientName, cfg.ClickHouse.MetaNetworkName,
	); err != nil {
		return fmt.Errorf("appending sync_state row: %w", err)
	}

	if err := batch.Send(); err != nil {
		if health != nil {
			health.ExportBatchErrors.WithLabelValues("aggregated", "sync_state").Inc()
		}

		return fmt.Errorf("sending sync_state batch: %w", err)
	}

	return nil
}
