package sink

import (
	"context"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/ethpandaops/observoor/internal/tracer"
)

// SlotConfig configures the per-slot aggregation sink.
type SlotConfig struct {
	Enabled bool `yaml:"enabled"`
}

// SlotSink aggregates events per Ethereum slot and logs
// on slot boundaries.
type SlotSink struct {
	log logrus.FieldLogger
	cfg SlotConfig

	mu     sync.Mutex
	bucket *Bucket
}

var _ Sink = (*SlotSink)(nil)

// NewSlotSink creates a new per-slot aggregation sink.
func NewSlotSink(
	log logrus.FieldLogger,
	cfg SlotConfig,
) *SlotSink {
	return &SlotSink{
		log: log.WithField("sink", "slot"),
		cfg: cfg,
	}
}

func (s *SlotSink) Name() string { return "slot" }

func (s *SlotSink) Start(ctx context.Context) error {
	s.bucket = NewBucket(0, time.Now())
	s.log.Info("Slot sink started")

	return nil
}

func (s *SlotSink) Stop() error {
	return nil
}

func (s *SlotSink) HandleEvent(event tracer.ParsedEvent) {
	s.mu.Lock()
	b := s.bucket
	s.mu.Unlock()

	if b != nil {
		b.Add(event)
	}
}

func (s *SlotSink) OnSlotChanged(newSlot uint64) {
	s.mu.Lock()
	oldBucket := s.bucket
	s.bucket = NewBucket(newSlot, time.Now())
	s.mu.Unlock()

	if oldBucket == nil || oldBucket.EventCount.Load() == 0 {
		return
	}

	snap := oldBucket.Snapshot()
	s.logSnapshot(snap)
}

func (s *SlotSink) logSnapshot(snap BucketSnapshot) {
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
	}).Info("Slot snapshot")
}
