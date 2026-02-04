package aggregated

import (
	"context"
	"time"

	processor "github.com/ethpandaops/go-batch-processor"
)

// AggregatedMetricJSON is the JSON schema for HTTP export of aggregated metrics.
type AggregatedMetricJSON struct {
	MetricType                 string   `json:"metric_type"`
	UpdatedDateTime            string   `json:"updated_date_time"`
	WindowStart                string   `json:"window_start"`
	IntervalMs                 uint16   `json:"interval_ms"`
	WallclockSlot              uint32   `json:"wallclock_slot"`
	WallclockSlotStartDateTime string   `json:"wallclock_slot_start_date_time"`
	PID                        uint32   `json:"pid"`
	ClientType                 string   `json:"client_type"`
	Sum                        int64    `json:"sum"`
	Count                      uint32   `json:"count"`
	Min                        int64    `json:"min,omitempty"`
	Max                        int64    `json:"max,omitempty"`
	Histogram                  []uint32 `json:"histogram,omitempty"`
	// Dimension fields (optional, depending on metric type).
	LocalPort uint16 `json:"local_port,omitempty"`
	Direction string `json:"direction,omitempty"`
	DeviceID  uint32 `json:"device_id,omitempty"`
	RW        string `json:"rw,omitempty"`
	// Metadata.
	MetaClientName  string `json:"meta_client_name,omitempty"`
	MetaNetworkName string `json:"meta_network_name,omitempty"`
}

// httpFlusher handles HTTP export of aggregated metrics.
type httpFlusher struct {
	proc           *processor.BatchItemProcessor[AggregatedMetricJSON]
	metaClientName string
	metaNetwork    string
	intervalMs     uint16
}

// flushHTTP exports buffer data to HTTP.
func (f *flusher) flushHTTP(
	ctx context.Context,
	buf *Buffer,
	proc *processor.BatchItemProcessor[AggregatedMetricJSON],
	metaClientName string,
	metaNetworkName string,
) {
	hf := &httpFlusher{
		proc:           proc,
		metaClientName: metaClientName,
		metaNetwork:    metaNetworkName,
		intervalMs:     f.intervalMs,
	}

	hf.exportLatencyMetrics(ctx, buf)
	hf.exportCounterMetrics(ctx, buf)
	hf.exportGaugeMetrics(ctx, buf)
}

func (hf *httpFlusher) exportLatencyMetrics(ctx context.Context, buf *Buffer) {
	// Syscall metrics.
	hf.exportBasicLatency(ctx, "syscall_read", buf.SyscallRead, buf)
	hf.exportBasicLatency(ctx, "syscall_write", buf.SyscallWrite, buf)
	hf.exportBasicLatency(ctx, "syscall_futex", buf.SyscallFutex, buf)
	hf.exportBasicLatency(ctx, "syscall_mmap", buf.SyscallMmap, buf)
	hf.exportBasicLatency(ctx, "syscall_epoll_wait", buf.SyscallEpollWait, buf)
	hf.exportBasicLatency(ctx, "syscall_fsync", buf.SyscallFsync, buf)
	hf.exportBasicLatency(ctx, "syscall_fdatasync", buf.SyscallFdatasync, buf)
	hf.exportBasicLatency(ctx, "syscall_pwrite", buf.SyscallPwrite, buf)

	// Scheduler metrics.
	hf.exportBasicLatency(ctx, "sched_on_cpu", buf.SchedSwitch, buf)
	hf.exportBasicLatency(ctx, "sched_off_cpu", buf.SchedOffCpu, buf)
	hf.exportBasicLatency(ctx, "sched_runqueue", buf.SchedRunqueue, buf)

	// Memory metrics.
	hf.exportBasicLatency(ctx, "mem_reclaim", buf.MemReclaim, buf)
	hf.exportBasicLatency(ctx, "mem_compaction", buf.MemCompaction, buf)

	// Disk latency.
	hf.exportDiskLatency(ctx, buf)
}

func (hf *httpFlusher) exportCounterMetrics(ctx context.Context, buf *Buffer) {
	// Basic counters.
	hf.exportBasicCounter(ctx, "page_fault_major", buf.PageFaultMajor, buf)
	hf.exportBasicCounter(ctx, "page_fault_minor", buf.PageFaultMinor, buf)
	hf.exportBasicCounter(ctx, "swap_in", buf.SwapIn, buf)
	hf.exportBasicCounter(ctx, "swap_out", buf.SwapOut, buf)
	hf.exportBasicCounter(ctx, "oom_kill", buf.OOMKill, buf)
	hf.exportBasicCounter(ctx, "fd_open", buf.FDOpen, buf)
	hf.exportBasicCounter(ctx, "fd_close", buf.FDClose, buf)
	hf.exportBasicCounter(ctx, "process_exit", buf.ProcessExit, buf)
	hf.exportBasicCounter(ctx, "tcp_state_change", buf.TcpStateChange, buf)

	// Network counters.
	hf.exportNetworkCounter(ctx, "net_io", buf.NetIO, buf)
	hf.exportNetworkCounter(ctx, "tcp_retransmit", buf.TcpRetransmit, buf)

	// Disk counters.
	hf.exportDiskCounter(ctx, "disk_bytes", buf.DiskBytes, buf)
	hf.exportDiskCounter(ctx, "block_merge", buf.BlockMerge, buf)
}

func (hf *httpFlusher) exportGaugeMetrics(ctx context.Context, buf *Buffer) {
	// TCP gauges.
	hf.exportTcpGauge(ctx, "tcp_rtt", buf.TcpRTT, buf)
	hf.exportTcpGauge(ctx, "tcp_cwnd", buf.TcpCwnd, buf)

	// Disk gauge.
	hf.exportDiskGauge(ctx, "disk_queue_depth", buf.DiskQueueDepth, buf)
}

func (hf *httpFlusher) exportBasicLatency(
	ctx context.Context,
	metricType string,
	data map[BasicDimension]*LatencyAggregate,
	buf *Buffer,
) {
	events := make([]*AggregatedMetricJSON, 0, len(data))

	for dim, agg := range data {
		snap := agg.Snapshot()
		if snap.Count == 0 {
			continue
		}

		hist := make([]uint32, 10)
		for i := range 10 {
			hist[i] = uint32(snap.Histogram[i])
		}

		events = append(events, &AggregatedMetricJSON{
			MetricType:                 metricType,
			UpdatedDateTime:            time.Now().Format(time.RFC3339Nano),
			WindowStart:                buf.StartTime.Format(time.RFC3339Nano),
			IntervalMs:                 hf.intervalMs,
			WallclockSlot:              uint32(buf.WallclockSlot),
			WallclockSlotStartDateTime: buf.WallclockSlotStartDateTime.Format(time.RFC3339Nano),
			PID:                        dim.PID,
			ClientType:                 dim.ClientType,
			Sum:                        snap.Sum,
			Count:                      uint32(snap.Count),
			Min:                        snap.Min,
			Max:                        snap.Max,
			Histogram:                  hist,
			MetaClientName:             hf.metaClientName,
			MetaNetworkName:            hf.metaNetwork,
		})
	}

	if len(events) > 0 {
		_ = hf.proc.Write(ctx, events)
	}
}

func (hf *httpFlusher) exportDiskLatency(ctx context.Context, buf *Buffer) {
	events := make([]*AggregatedMetricJSON, 0, len(buf.DiskLatency))

	for dim, agg := range buf.DiskLatency {
		snap := agg.Snapshot()
		if snap.Count == 0 {
			continue
		}

		hist := make([]uint32, 10)
		for i := range 10 {
			hist[i] = uint32(snap.Histogram[i])
		}

		events = append(events, &AggregatedMetricJSON{
			MetricType:                 "disk_latency",
			UpdatedDateTime:            time.Now().Format(time.RFC3339Nano),
			WindowStart:                buf.StartTime.Format(time.RFC3339Nano),
			IntervalMs:                 hf.intervalMs,
			WallclockSlot:              uint32(buf.WallclockSlot),
			WallclockSlotStartDateTime: buf.WallclockSlotStartDateTime.Format(time.RFC3339Nano),
			PID:                        dim.PID,
			ClientType:                 dim.ClientType,
			Sum:                        snap.Sum,
			Count:                      uint32(snap.Count),
			Min:                        snap.Min,
			Max:                        snap.Max,
			Histogram:                  hist,
			DeviceID:                   dim.DeviceID,
			RW:                         RWString(dim.ReadWrite),
			MetaClientName:             hf.metaClientName,
			MetaNetworkName:            hf.metaNetwork,
		})
	}

	if len(events) > 0 {
		_ = hf.proc.Write(ctx, events)
	}
}

func (hf *httpFlusher) exportBasicCounter(
	ctx context.Context,
	metricType string,
	data map[BasicDimension]*CounterAggregate,
	buf *Buffer,
) {
	events := make([]*AggregatedMetricJSON, 0, len(data))

	for dim, agg := range data {
		snap := agg.Snapshot()
		if snap.Count == 0 {
			continue
		}

		events = append(events, &AggregatedMetricJSON{
			MetricType:                 metricType,
			UpdatedDateTime:            time.Now().Format(time.RFC3339Nano),
			WindowStart:                buf.StartTime.Format(time.RFC3339Nano),
			IntervalMs:                 hf.intervalMs,
			WallclockSlot:              uint32(buf.WallclockSlot),
			WallclockSlotStartDateTime: buf.WallclockSlotStartDateTime.Format(time.RFC3339Nano),
			PID:                        dim.PID,
			ClientType:                 dim.ClientType,
			Sum:                        snap.Sum,
			Count:                      uint32(snap.Count),
			MetaClientName:             hf.metaClientName,
			MetaNetworkName:            hf.metaNetwork,
		})
	}

	if len(events) > 0 {
		_ = hf.proc.Write(ctx, events)
	}
}

func (hf *httpFlusher) exportNetworkCounter(
	ctx context.Context,
	metricType string,
	data map[NetworkDimension]*CounterAggregate,
	buf *Buffer,
) {
	events := make([]*AggregatedMetricJSON, 0, len(data))

	for dim, agg := range data {
		snap := agg.Snapshot()
		if snap.Count == 0 {
			continue
		}

		events = append(events, &AggregatedMetricJSON{
			MetricType:                 metricType,
			UpdatedDateTime:            time.Now().Format(time.RFC3339Nano),
			WindowStart:                buf.StartTime.Format(time.RFC3339Nano),
			IntervalMs:                 hf.intervalMs,
			WallclockSlot:              uint32(buf.WallclockSlot),
			WallclockSlotStartDateTime: buf.WallclockSlotStartDateTime.Format(time.RFC3339Nano),
			PID:                        dim.PID,
			ClientType:                 dim.ClientType,
			Sum:                        snap.Sum,
			Count:                      uint32(snap.Count),
			LocalPort:                  dim.LocalPort,
			Direction:                  DirectionString(dim.Direction),
			MetaClientName:             hf.metaClientName,
			MetaNetworkName:            hf.metaNetwork,
		})
	}

	if len(events) > 0 {
		_ = hf.proc.Write(ctx, events)
	}
}

func (hf *httpFlusher) exportDiskCounter(
	ctx context.Context,
	metricType string,
	data map[DiskDimension]*CounterAggregate,
	buf *Buffer,
) {
	events := make([]*AggregatedMetricJSON, 0, len(data))

	for dim, agg := range data {
		snap := agg.Snapshot()
		if snap.Count == 0 {
			continue
		}

		events = append(events, &AggregatedMetricJSON{
			MetricType:                 metricType,
			UpdatedDateTime:            time.Now().Format(time.RFC3339Nano),
			WindowStart:                buf.StartTime.Format(time.RFC3339Nano),
			IntervalMs:                 hf.intervalMs,
			WallclockSlot:              uint32(buf.WallclockSlot),
			WallclockSlotStartDateTime: buf.WallclockSlotStartDateTime.Format(time.RFC3339Nano),
			PID:                        dim.PID,
			ClientType:                 dim.ClientType,
			Sum:                        snap.Sum,
			Count:                      uint32(snap.Count),
			DeviceID:                   dim.DeviceID,
			RW:                         RWString(dim.ReadWrite),
			MetaClientName:             hf.metaClientName,
			MetaNetworkName:            hf.metaNetwork,
		})
	}

	if len(events) > 0 {
		_ = hf.proc.Write(ctx, events)
	}
}

func (hf *httpFlusher) exportTcpGauge(
	ctx context.Context,
	metricType string,
	data map[TCPMetricsDimension]*GaugeAggregate,
	buf *Buffer,
) {
	events := make([]*AggregatedMetricJSON, 0, len(data))

	for dim, agg := range data {
		snap := agg.Snapshot()
		if snap.Count == 0 {
			continue
		}

		events = append(events, &AggregatedMetricJSON{
			MetricType:                 metricType,
			UpdatedDateTime:            time.Now().Format(time.RFC3339Nano),
			WindowStart:                buf.StartTime.Format(time.RFC3339Nano),
			IntervalMs:                 hf.intervalMs,
			WallclockSlot:              uint32(buf.WallclockSlot),
			WallclockSlotStartDateTime: buf.WallclockSlotStartDateTime.Format(time.RFC3339Nano),
			PID:                        dim.PID,
			ClientType:                 dim.ClientType,
			Sum:                        snap.Sum,
			Count:                      uint32(snap.Count),
			Min:                        snap.Min,
			Max:                        snap.Max,
			LocalPort:                  dim.LocalPort,
			MetaClientName:             hf.metaClientName,
			MetaNetworkName:            hf.metaNetwork,
		})
	}

	if len(events) > 0 {
		_ = hf.proc.Write(ctx, events)
	}
}

func (hf *httpFlusher) exportDiskGauge(
	ctx context.Context,
	metricType string,
	data map[DiskDimension]*GaugeAggregate,
	buf *Buffer,
) {
	events := make([]*AggregatedMetricJSON, 0, len(data))

	for dim, agg := range data {
		snap := agg.Snapshot()
		if snap.Count == 0 {
			continue
		}

		events = append(events, &AggregatedMetricJSON{
			MetricType:                 metricType,
			UpdatedDateTime:            time.Now().Format(time.RFC3339Nano),
			WindowStart:                buf.StartTime.Format(time.RFC3339Nano),
			IntervalMs:                 hf.intervalMs,
			WallclockSlot:              uint32(buf.WallclockSlot),
			WallclockSlotStartDateTime: buf.WallclockSlotStartDateTime.Format(time.RFC3339Nano),
			PID:                        dim.PID,
			ClientType:                 dim.ClientType,
			Sum:                        snap.Sum,
			Count:                      uint32(snap.Count),
			Min:                        snap.Min,
			Max:                        snap.Max,
			DeviceID:                   dim.DeviceID,
			RW:                         RWString(dim.ReadWrite),
			MetaClientName:             hf.metaClientName,
			MetaNetworkName:            hf.metaNetwork,
		})
	}

	if len(events) > 0 {
		_ = hf.proc.Write(ctx, events)
	}
}
