package sink

import (
	"context"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/ethpandaops/observoor/internal/export"
	"github.com/ethpandaops/observoor/internal/tracer"
)

// WindowConfig configures the configurable-window aggregation sink.
type WindowConfig struct {
	Enabled    bool                    `yaml:"enabled"`
	Interval   time.Duration           `yaml:"interval"`
	OTLP       export.OTLPConfig       `yaml:"otlp"`
	ClickHouse export.ClickHouseConfig `yaml:"clickhouse"`
}

// WindowSink aggregates events over configurable time windows.
type WindowSink struct {
	log      logrus.FieldLogger
	cfg      WindowConfig
	exporter *export.OTLPExporter

	mu     sync.Mutex
	bucket *Bucket

	cancel context.CancelFunc
	done   chan struct{}

	// OTLP instruments (same shape as SlotSink)
	meter                metric.Meter
	syscallReadCount     metric.Int64Counter
	syscallReadBytes     metric.Int64Counter
	syscallReadLatency   metric.Int64Counter
	syscallWriteCount    metric.Int64Counter
	syscallWriteBytes    metric.Int64Counter
	syscallWriteLatency  metric.Int64Counter
	syscallFutexCount    metric.Int64Counter
	syscallFutexLatency  metric.Int64Counter
	syscallMmapCount     metric.Int64Counter
	syscallEpollCount    metric.Int64Counter
	syscallEpollLatency  metric.Int64Counter
	diskReadCount        metric.Int64Counter
	diskReadBytes        metric.Int64Counter
	diskReadLatency      metric.Int64Counter
	diskWriteCount       metric.Int64Counter
	diskWriteBytes       metric.Int64Counter
	diskWriteLatency     metric.Int64Counter
	netTXCount           metric.Int64Counter
	netTXBytes           metric.Int64Counter
	netRXCount           metric.Int64Counter
	netRXBytes           metric.Int64Counter
	schedSwitchTotal     metric.Int64Counter
	schedSwitchVoluntary metric.Int64Counter
	schedOnCpuNs         metric.Int64Counter
	pageFaultTotal       metric.Int64Counter
	pageFaultMajor       metric.Int64Counter
	fdOpenCount          metric.Int64Counter
	fdCloseCount         metric.Int64Counter
	eventCount           metric.Int64Counter
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
		log:      log.WithField("sink", "window"),
		cfg:      cfg,
		exporter: export.NewOTLPExporter(log, cfg.OTLP),
		done:     make(chan struct{}),
	}
}

func (s *WindowSink) Name() string { return "window" }

func (s *WindowSink) Start(ctx context.Context) error {
	if err := s.exporter.Start(ctx); err != nil {
		return err
	}

	s.meter = s.exporter.MeterProvider().Meter("observoor.window")

	if err := s.createInstruments(); err != nil {
		return err
	}

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
	}

	<-s.done

	ctx, cancel := context.WithTimeout(
		context.Background(), 10*time.Second,
	)
	defer cancel()

	return s.exporter.Stop(ctx)
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
	s.exportSnapshot(snap)
}

func (s *WindowSink) exportSnapshot(snap BucketSnapshot) {
	ctx := context.Background()
	attrs := metric.WithAttributes(
		attribute.Int64("slot", int64(snap.Slot)),
		attribute.String("window_start", snap.StartTime.Format(
			time.RFC3339Nano,
		)),
	)

	s.syscallReadCount.Add(ctx, snap.SyscallReadCount, attrs)
	s.syscallReadBytes.Add(ctx, snap.SyscallReadBytes, attrs)
	s.syscallReadLatency.Add(ctx, snap.SyscallReadLatNs, attrs)
	s.syscallWriteCount.Add(ctx, snap.SyscallWriteCount, attrs)
	s.syscallWriteBytes.Add(ctx, snap.SyscallWriteBytes, attrs)
	s.syscallWriteLatency.Add(ctx, snap.SyscallWriteLatNs, attrs)
	s.syscallFutexCount.Add(ctx, snap.SyscallFutexCount, attrs)
	s.syscallFutexLatency.Add(ctx, snap.SyscallFutexLatNs, attrs)
	s.syscallMmapCount.Add(ctx, snap.SyscallMmapCount, attrs)
	s.syscallEpollCount.Add(ctx, snap.SyscallEpollCount, attrs)
	s.syscallEpollLatency.Add(ctx, snap.SyscallEpollLatNs, attrs)

	s.diskReadCount.Add(ctx, snap.DiskReadCount, attrs)
	s.diskReadBytes.Add(ctx, snap.DiskReadBytes, attrs)
	s.diskReadLatency.Add(ctx, snap.DiskReadLatNs, attrs)
	s.diskWriteCount.Add(ctx, snap.DiskWriteCount, attrs)
	s.diskWriteBytes.Add(ctx, snap.DiskWriteBytes, attrs)
	s.diskWriteLatency.Add(ctx, snap.DiskWriteLatNs, attrs)

	s.netTXCount.Add(ctx, snap.NetTXCount, attrs)
	s.netTXBytes.Add(ctx, snap.NetTXBytes, attrs)
	s.netRXCount.Add(ctx, snap.NetRXCount, attrs)
	s.netRXBytes.Add(ctx, snap.NetRXBytes, attrs)

	s.schedSwitchTotal.Add(ctx, snap.SchedSwitchTotal, attrs)
	s.schedSwitchVoluntary.Add(ctx, snap.SchedSwitchVoluntary, attrs)
	s.schedOnCpuNs.Add(ctx, snap.SchedOnCpuNs, attrs)

	s.pageFaultTotal.Add(ctx, snap.PageFaultTotal, attrs)
	s.pageFaultMajor.Add(ctx, snap.PageFaultMajor, attrs)

	s.fdOpenCount.Add(ctx, snap.FDOpenCount, attrs)
	s.fdCloseCount.Add(ctx, snap.FDCloseCount, attrs)
	s.eventCount.Add(ctx, snap.EventCount, attrs)

	s.log.WithFields(logrus.Fields{
		"slot":   snap.Slot,
		"events": snap.EventCount,
	}).Debug("Exported window snapshot")
}

//nolint:cyclop // instrument creation is inherently sequential
func (s *WindowSink) createInstruments() error {
	var err error

	s.syscallReadCount, err = s.meter.Int64Counter("syscall.read.count")
	if err != nil {
		return err
	}

	s.syscallReadBytes, err = s.meter.Int64Counter("syscall.read.bytes")
	if err != nil {
		return err
	}

	s.syscallReadLatency, err = s.meter.Int64Counter(
		"syscall.read.latency_ns",
	)
	if err != nil {
		return err
	}

	s.syscallWriteCount, err = s.meter.Int64Counter("syscall.write.count")
	if err != nil {
		return err
	}

	s.syscallWriteBytes, err = s.meter.Int64Counter("syscall.write.bytes")
	if err != nil {
		return err
	}

	s.syscallWriteLatency, err = s.meter.Int64Counter(
		"syscall.write.latency_ns",
	)
	if err != nil {
		return err
	}

	s.syscallFutexCount, err = s.meter.Int64Counter("syscall.futex.count")
	if err != nil {
		return err
	}

	s.syscallFutexLatency, err = s.meter.Int64Counter(
		"syscall.futex.latency_ns",
	)
	if err != nil {
		return err
	}

	s.syscallMmapCount, err = s.meter.Int64Counter("syscall.mmap.count")
	if err != nil {
		return err
	}

	s.syscallEpollCount, err = s.meter.Int64Counter(
		"syscall.epoll_wait.count",
	)
	if err != nil {
		return err
	}

	s.syscallEpollLatency, err = s.meter.Int64Counter(
		"syscall.epoll_wait.latency_ns",
	)
	if err != nil {
		return err
	}

	s.diskReadCount, err = s.meter.Int64Counter("disk.read.count")
	if err != nil {
		return err
	}

	s.diskReadBytes, err = s.meter.Int64Counter("disk.read.bytes")
	if err != nil {
		return err
	}

	s.diskReadLatency, err = s.meter.Int64Counter("disk.read.latency_ns")
	if err != nil {
		return err
	}

	s.diskWriteCount, err = s.meter.Int64Counter("disk.write.count")
	if err != nil {
		return err
	}

	s.diskWriteBytes, err = s.meter.Int64Counter("disk.write.bytes")
	if err != nil {
		return err
	}

	s.diskWriteLatency, err = s.meter.Int64Counter(
		"disk.write.latency_ns",
	)
	if err != nil {
		return err
	}

	s.netTXCount, err = s.meter.Int64Counter("net.tx.count")
	if err != nil {
		return err
	}

	s.netTXBytes, err = s.meter.Int64Counter("net.tx.bytes")
	if err != nil {
		return err
	}

	s.netRXCount, err = s.meter.Int64Counter("net.rx.count")
	if err != nil {
		return err
	}

	s.netRXBytes, err = s.meter.Int64Counter("net.rx.bytes")
	if err != nil {
		return err
	}

	s.schedSwitchTotal, err = s.meter.Int64Counter("sched.switch.total")
	if err != nil {
		return err
	}

	s.schedSwitchVoluntary, err = s.meter.Int64Counter(
		"sched.switch.voluntary",
	)
	if err != nil {
		return err
	}

	s.schedOnCpuNs, err = s.meter.Int64Counter(
		"sched.on_cpu_ns",
	)
	if err != nil {
		return err
	}

	s.pageFaultTotal, err = s.meter.Int64Counter("mem.pagefault.total")
	if err != nil {
		return err
	}

	s.pageFaultMajor, err = s.meter.Int64Counter("mem.pagefault.major")
	if err != nil {
		return err
	}

	s.fdOpenCount, err = s.meter.Int64Counter("fd.open.count")
	if err != nil {
		return err
	}

	s.fdCloseCount, err = s.meter.Int64Counter("fd.close.count")
	if err != nil {
		return err
	}

	s.eventCount, err = s.meter.Int64Counter("events.total")
	if err != nil {
		return err
	}

	return nil
}
