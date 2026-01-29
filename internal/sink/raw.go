package sink

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/ethpandaops/observoor/internal/export"
	"github.com/ethpandaops/observoor/internal/tracer"
)

// RawConfig configures the raw event sink.
type RawConfig struct {
	Enabled    bool                    `yaml:"enabled"`
	ClickHouse export.ClickHouseConfig `yaml:"clickhouse"`
}

// RawSink writes every event to ClickHouse in batches.
type RawSink struct {
	log    logrus.FieldLogger
	cfg    RawConfig
	writer *export.ClickHouseWriter
	health *export.HealthMetrics

	currentSlot atomic.Uint64

	mu      sync.Mutex
	batch   []rawRow
	cancel  context.CancelFunc
	done    chan struct{}
	eventCh chan tracer.ParsedEvent
}

type rawRow struct {
	TimestampNs uint64
	Slot        uint64
	PID         uint32
	TID         uint32
	EventType   string
	ClientType  string
	LatencyNs   uint64
	Bytes       int64
	SrcPort     uint16
	DstPort     uint16
	FD          int32
	Filename    string
	Voluntary   bool
	Major       bool
	Address     uint64
	OnCpuNs     uint64
}

var _ Sink = (*RawSink)(nil)

// NewRawSink creates a new raw event sink.
func NewRawSink(
	log logrus.FieldLogger,
	cfg RawConfig,
	health *export.HealthMetrics,
) *RawSink {
	return &RawSink{
		log:     log.WithField("sink", "raw"),
		cfg:     cfg,
		writer:  export.NewClickHouseWriter(log, cfg.ClickHouse),
		health:  health,
		batch:   make([]rawRow, 0, cfg.ClickHouse.BatchSize),
		done:    make(chan struct{}),
		eventCh: make(chan tracer.ParsedEvent, 4096),
	}
}

func (s *RawSink) Name() string { return "raw" }

func (s *RawSink) Start(ctx context.Context) error {
	if err := s.writer.Start(ctx); err != nil {
		return err
	}

	ctx, s.cancel = context.WithCancel(ctx)

	go s.runLoop(ctx)

	s.log.Info("Raw sink started")

	return nil
}

func (s *RawSink) Stop() error {
	if s.cancel == nil {
		return s.writer.Stop()
	}

	s.cancel()
	<-s.done

	// Flush remaining events.
	s.mu.Lock()
	remaining := s.batch
	s.batch = nil
	s.mu.Unlock()

	if len(remaining) > 0 {
		if err := s.flush(context.Background(), remaining); err != nil {
			s.log.WithError(err).Error("Final flush failed")
			s.reportExportError()
		}
	}

	return s.writer.Stop()
}

func (s *RawSink) HandleEvent(event tracer.ParsedEvent) {
	select {
	case s.eventCh <- event:
	default:
		s.log.Warn("Raw sink event channel full, dropping event")
		s.reportDrop()
	}
}

func (s *RawSink) OnSlotChanged(slot uint64) {
	s.currentSlot.Store(slot)
}

func (s *RawSink) runLoop(ctx context.Context) {
	defer close(s.done)

	ticker := time.NewTicker(s.writer.Config().FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case event := <-s.eventCh:
			s.addEvent(ctx, event)
		case <-ticker.C:
			s.tickFlush(ctx)
		}
	}
}

func (s *RawSink) addEvent(
	ctx context.Context,
	event tracer.ParsedEvent,
) {
	row := toRawRow(event, s.currentSlot.Load())

	s.mu.Lock()
	s.batch = append(s.batch, row)
	shouldFlush := len(s.batch) >= s.writer.Config().BatchSize
	var toFlush []rawRow

	if shouldFlush {
		toFlush = s.batch
		s.batch = make([]rawRow, 0, s.writer.Config().BatchSize)
	}

	s.mu.Unlock()

	if shouldFlush {
		if err := s.flush(ctx, toFlush); err != nil {
			s.log.WithError(err).Error("Batch flush failed")
			s.reportExportError()
		}
	}
}

func (s *RawSink) tickFlush(ctx context.Context) {
	s.mu.Lock()

	if len(s.batch) == 0 {
		s.mu.Unlock()

		return
	}

	toFlush := s.batch
	s.batch = make([]rawRow, 0, s.writer.Config().BatchSize)
	s.mu.Unlock()

	if err := s.flush(ctx, toFlush); err != nil {
		s.log.WithError(err).Error("Periodic flush failed")
		s.reportExportError()
	}
}

func (s *RawSink) flush(ctx context.Context, rows []rawRow) error {
	if len(rows) == 0 {
		return nil
	}

	conn := s.writer.Conn()
	cfg := s.writer.Config()
	table := fmt.Sprintf("%s.%s", cfg.Database, cfg.Table)

	batch, err := conn.PrepareBatch(
		ctx,
		fmt.Sprintf("INSERT INTO %s", table),
	)
	if err != nil {
		return fmt.Errorf("preparing batch: %w", err)
	}

	for _, row := range rows {
		if err := batch.Append(
			row.TimestampNs,
			row.Slot,
			row.PID,
			row.TID,
			row.EventType,
			row.ClientType,
			row.LatencyNs,
			row.Bytes,
			row.SrcPort,
			row.DstPort,
			row.FD,
			row.Filename,
			row.Voluntary,
			row.Major,
			row.Address,
			row.OnCpuNs,
		); err != nil {
			return fmt.Errorf("appending row: %w", err)
		}
	}

	if err := batch.Send(); err != nil {
		return fmt.Errorf("sending batch of %d rows: %w", len(rows), err)
	}

	s.log.WithField("rows", len(rows)).
		Debug("Flushed raw events")

	return nil
}

func toRawRow(event tracer.ParsedEvent, slot uint64) rawRow {
	row := rawRow{
		// Use wall clock time for storage. The BPF ktime_get_ns()
		// value is monotonic (since boot), not Unix epoch.
		TimestampNs: uint64(time.Now().UnixNano()),
		Slot:        slot,
		PID:         event.Raw.PID,
		TID:         event.Raw.TID,
		EventType:   event.Raw.Type.String(),
		ClientType:  event.Raw.Client.String(),
	}

	switch e := event.Typed.(type) {
	case tracer.SyscallEvent:
		row.LatencyNs = e.LatencyNs
		row.Bytes = e.Return
		row.FD = e.FD
	case tracer.DiskIOEvent:
		row.LatencyNs = e.LatencyNs
		row.Bytes = int64(e.Bytes)
	case tracer.NetIOEvent:
		row.Bytes = int64(e.Bytes)
		row.SrcPort = e.SrcPort
		row.DstPort = e.DstPort
	case tracer.SchedEvent:
		row.Voluntary = e.Voluntary
		row.OnCpuNs = e.OnCpuNs
	case tracer.PageFaultEvent:
		row.Address = e.Address
		row.Major = e.Major
	case tracer.FDEvent:
		row.FD = e.FD
		row.Filename = e.Filename
	}

	return row
}

func (s *RawSink) reportDrop() {
	if s.health == nil {
		return
	}

	s.health.EventsDropped.Inc()
}

func (s *RawSink) reportExportError() {
	if s.health == nil {
		return
	}

	s.health.ExportErrors.Inc()
}
