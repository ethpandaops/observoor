package sink

import (
	"context"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

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

func (s *WindowSink) OnSlotChanged(newSlot uint64) {
	s.mu.Lock()
	if s.bucket != nil {
		s.bucket.Slot = newSlot
	}
	s.mu.Unlock()
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
		"slot":                   snap.Slot,
		"events":                 snap.EventCount,
		"syscall_read_count":     snap.SyscallReadCount,
		"syscall_read_bytes":     snap.SyscallReadBytes,
		"syscall_write_count":    snap.SyscallWriteCount,
		"syscall_write_bytes":    snap.SyscallWriteBytes,
		"disk_read_count":        snap.DiskReadCount,
		"disk_read_bytes":        snap.DiskReadBytes,
		"disk_write_count":       snap.DiskWriteCount,
		"disk_write_bytes":       snap.DiskWriteBytes,
		"net_tx_count":           snap.NetTXCount,
		"net_tx_bytes":           snap.NetTXBytes,
		"net_rx_count":           snap.NetRXCount,
		"net_rx_bytes":           snap.NetRXBytes,
		"sched_switch_total":     snap.SchedSwitchTotal,
		"sched_switch_voluntary": snap.SchedSwitchVoluntary,
		"page_fault_total":       snap.PageFaultTotal,
		"page_fault_major":       snap.PageFaultMajor,
		"fd_open_count":          snap.FDOpenCount,
		"fd_close_count":         snap.FDCloseCount,
	}).Info("Window snapshot")
}
