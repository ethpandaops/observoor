package sink

import (
	"context"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/ethpandaops/observoor/internal/beacon"
	"github.com/ethpandaops/observoor/internal/export"
	"github.com/ethpandaops/observoor/internal/tracer"
)

// WindowConfig configures the configurable-window aggregation sink.
type WindowConfig struct {
	Enabled    bool                    `yaml:"enabled"`
	Interval   time.Duration           `yaml:"interval"`
	ClickHouse export.ClickHouseConfig `yaml:"clickhouse"`
}

// WindowSink aggregates events over configurable time windows.
type WindowSink struct {
	log logrus.FieldLogger
	cfg WindowConfig

	mu     sync.Mutex
	bucket *Bucket

	cancel context.CancelFunc
	done   chan struct{}
}

var _ Sink = (*WindowSink)(nil)

// NewWindowSink creates a new window aggregation sink.
func NewWindowSink(
	log logrus.FieldLogger,
	cfg WindowConfig,
) *WindowSink {
	if cfg.Interval <= 0 {
		cfg.Interval = 500 * time.Millisecond
	}

	return &WindowSink{
		log:  log.WithField("sink", "window"),
		cfg:  cfg,
		done: make(chan struct{}),
	}
}

func (s *WindowSink) Name() string { return "window" }

func (s *WindowSink) Start(ctx context.Context) error {
	s.bucket = NewBucket(0, time.Now())

	ctx, s.cancel = context.WithCancel(ctx)

	go s.runTimer(ctx)

	s.log.WithField("interval", s.cfg.Interval).
		Info("Window sink started")

	return nil
}

func (s *WindowSink) Stop() error {
	if s.cancel != nil {
		s.cancel()
		<-s.done
	}

	return nil
}

func (s *WindowSink) HandleEvent(event tracer.ParsedEvent) {
	s.mu.Lock()
	b := s.bucket
	s.mu.Unlock()

	if b != nil {
		b.Add(event)
	}
}

func (s *WindowSink) OnSlotChanged(newSlot uint64, _ time.Time) {
	s.mu.Lock()
	if s.bucket != nil {
		s.bucket.Slot = newSlot
	}
	s.mu.Unlock()
}

func (s *WindowSink) SetSyncState(_ beacon.SyncStatus) {
	// WindowSink only logs; sync state is not needed.
}

func (s *WindowSink) runTimer(ctx context.Context) {
	defer close(s.done)

	ticker := time.NewTicker(s.cfg.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.flushWindow()
		}
	}
}

func (s *WindowSink) flushWindow() {
	s.mu.Lock()
	oldBucket := s.bucket
	s.bucket = NewBucket(oldBucket.Slot, time.Now())
	s.mu.Unlock()

	if oldBucket.EventCount.Load() == 0 {
		return
	}

	snap := oldBucket.Snapshot()
	s.logSnapshot(snap)
}

func (s *WindowSink) logSnapshot(snap BucketSnapshot) {
	s.log.WithFields(logrus.Fields{
		"slot":                    snap.Slot,
		"events":                  snap.EventCount,
		"syscall_read_count":      snap.SyscallReadCount,
		"syscall_read_bytes":      snap.SyscallReadBytes,
		"syscall_write_count":     snap.SyscallWriteCount,
		"syscall_write_bytes":     snap.SyscallWriteBytes,
		"syscall_fsync_count":     snap.SyscallFsyncCount,
		"syscall_fdatasync_count": snap.SyscallFdatasyncCount,
		"syscall_pwrite_count":    snap.SyscallPwriteCount,
		"syscall_pwrite_bytes":    snap.SyscallPwriteBytes,
		"disk_read_count":         snap.DiskReadCount,
		"disk_read_bytes":         snap.DiskReadBytes,
		"disk_write_count":        snap.DiskWriteCount,
		"disk_write_bytes":        snap.DiskWriteBytes,
		"disk_queue_depth_sum":    snap.DiskQueueDepthSum,
		"block_merge_count":       snap.BlockMergeCount,
		"block_merge_bytes":       snap.BlockMergeBytes,
		"net_tx_count":            snap.NetTXCount,
		"net_tx_bytes":            snap.NetTXBytes,
		"net_rx_count":            snap.NetRXCount,
		"net_rx_bytes":            snap.NetRXBytes,
		"sched_switch_total":      snap.SchedSwitchTotal,
		"sched_switch_voluntary":  snap.SchedSwitchVoluntary,
		"sched_runqueue_count":    snap.SchedRunqueueCount,
		"sched_runqueue_ns":       snap.SchedRunqueueLatNs,
		"sched_off_cpu_ns":        snap.SchedOffCpuNs,
		"page_fault_total":        snap.PageFaultTotal,
		"page_fault_major":        snap.PageFaultMajor,
		"mem_reclaim_count":       snap.MemReclaimCount,
		"mem_reclaim_ns":          snap.MemReclaimNs,
		"mem_compaction_count":    snap.MemCompactionCount,
		"mem_compaction_ns":       snap.MemCompactionNs,
		"swap_in_count":           snap.SwapInCount,
		"swap_out_count":          snap.SwapOutCount,
		"swap_in_pages":           snap.SwapInPages,
		"swap_out_pages":          snap.SwapOutPages,
		"oom_kill_count":          snap.OOMKillCount,
		"fd_open_count":           snap.FDOpenCount,
		"fd_close_count":          snap.FDCloseCount,
		"tcp_retransmit_count":    snap.TcpRetransmitCount,
		"tcp_retransmit_bytes":    snap.TcpRetransmitBytes,
		"tcp_state_change_count":  snap.TcpStateChangeCount,
		"tcp_metrics_count":       snap.TcpMetricsCount,
		"tcp_srtt_us_sum":         snap.TcpSrttUsSum,
		"tcp_cwnd_sum":            snap.TcpCwndSum,
		"process_exit_count":      snap.ProcessExitCount,
		"process_exit_nonzero":    snap.ProcessExitNonZeroCount,
	}).Info("Window snapshot")
}
