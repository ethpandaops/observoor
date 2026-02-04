package sink

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	processor "github.com/ethpandaops/go-batch-processor"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/ethpandaops/observoor/internal/beacon"
	"github.com/ethpandaops/observoor/internal/export"
	httpexport "github.com/ethpandaops/observoor/internal/export/http"
	"github.com/ethpandaops/observoor/internal/tracer"
)

// RawConfig configures the raw event sink.
type RawConfig struct {
	Enabled    bool                    `yaml:"enabled"`
	ClickHouse export.ClickHouseConfig `yaml:"clickhouse"`
	// HTTP configures optional HTTP export (e.g., to Vector).
	HTTP httpexport.Config `yaml:"http"`
	// IncludeFilenames controls whether fd_open filenames are stored.
	// Defaults to true when unset.
	IncludeFilenames *bool `yaml:"include_filenames"`
}

// RawSink writes every event to ClickHouse in batches.
type RawSink struct {
	log    logrus.FieldLogger
	cfg    RawConfig
	writer *export.ClickHouseWriter
	health *export.HealthMetrics

	// HTTP export processor (optional).
	httpProcessor *processor.BatchItemProcessor[RawEventJSON]

	currentSlot       atomic.Uint64
	currentSlotStart  atomic.Int64
	monotonicOffsetNs atomic.Int64
	includeFilenames  bool

	// Sync state fields (stored as uint32: 0=false, 1=true for atomic access).
	clSyncing    atomic.Uint32
	elOptimistic atomic.Uint32
	elOffline    atomic.Uint32

	mu      sync.Mutex
	batch   []rawRow
	cancel  context.CancelFunc
	done    chan struct{}
	eventCh chan tracer.ParsedEvent
}

type rawRow struct {
	TimestampNs   uint64
	WallclockSlot uint64
	SlotStart     time.Time
	PID           uint32
	TID           uint32
	EventType     string
	ClientType    string
	LatencyNs     uint64
	Bytes         int64
	SrcPort       uint16
	DstPort       uint16
	FD            int32
	Filename      string
	Voluntary     bool
	Major         bool
	Address       uint64
	OnCpuNs       uint64
	RW            uint8
	QueueDepth    uint32
	DeviceID      uint32
	RunqueueNs    uint64
	OffCpuNs      uint64
	TcpState      uint8
	TcpOldState   uint8
	TcpSrttUs     uint32
	TcpCwnd       uint32
	Pages         uint64
	ExitCode      uint32
	TargetPID     uint32
	CLSyncing     bool
	ELOptimistic  bool
	ELOffline     bool
}

var _ Sink = (*RawSink)(nil)

// NewRawSink creates a new raw event sink.
func NewRawSink(
	log logrus.FieldLogger,
	cfg RawConfig,
	health *export.HealthMetrics,
) (*RawSink, error) {
	includeFilenames := true
	if cfg.IncludeFilenames != nil {
		includeFilenames = *cfg.IncludeFilenames
	}

	sink := &RawSink{
		log:              log.WithField("sink", "raw"),
		cfg:              cfg,
		writer:           export.NewClickHouseWriter(log, cfg.ClickHouse),
		health:           health,
		batch:            make([]rawRow, 0, cfg.ClickHouse.BatchSize),
		done:             make(chan struct{}),
		eventCh:          make(chan tracer.ParsedEvent, 65536),
		includeFilenames: includeFilenames,
	}

	// Initialize HTTP processor if enabled.
	if cfg.HTTP.Enabled {
		proc, err := httpexport.NewProcessor[RawEventJSON](
			log,
			cfg.HTTP,
			"raw_http",
		)
		if err != nil {
			return nil, fmt.Errorf("creating HTTP processor: %w", err)
		}

		sink.httpProcessor = proc
	}

	return sink, nil
}

func (s *RawSink) Name() string { return "raw" }

func (s *RawSink) Start(ctx context.Context) error {
	if err := s.writer.Start(ctx); err != nil {
		return err
	}

	// Record channel capacity metric.
	if s.health != nil {
		s.health.SinkEventChannelCapacity.WithLabelValues("raw").
			Set(float64(cap(s.eventCh)))
		s.health.ClickHouseConnected.WithLabelValues("raw").Set(1)
	}

	offset, err := monotonicOffsetNs()
	if err != nil {
		s.log.WithError(err).
			Warn("Failed to compute monotonic offset")
	} else {
		s.monotonicOffsetNs.Store(offset)
	}

	ctx, s.cancel = context.WithCancel(ctx)

	// Start HTTP processor if enabled.
	if s.httpProcessor != nil {
		s.httpProcessor.Start(ctx)
		s.log.Info("HTTP export started")
	}

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

	// Shutdown HTTP processor.
	if s.httpProcessor != nil {
		if err := s.httpProcessor.Shutdown(context.Background()); err != nil {
			s.log.WithError(err).Error("HTTP processor shutdown failed")
		}
	}

	return s.writer.Stop()
}

func (s *RawSink) HandleEvent(event tracer.ParsedEvent) {
	select {
	case s.eventCh <- event:
		if s.health != nil {
			s.health.SinkEventsProcessed.WithLabelValues("raw").Inc()
		}
	default:
		s.log.Warn("Raw sink event channel full, dropping event")
		s.reportDrop()
	}
}

func (s *RawSink) OnSlotChanged(slot uint64, slotStart time.Time) {
	s.currentSlot.Store(slot)
	s.currentSlotStart.Store(slotStart.UnixNano())
}

func (s *RawSink) SetSyncState(status beacon.SyncStatus) {
	if status.IsSyncing {
		s.clSyncing.Store(1)
	} else {
		s.clSyncing.Store(0)
	}

	if status.IsOptimistic {
		s.elOptimistic.Store(1)
	} else {
		s.elOptimistic.Store(0)
	}

	if status.ELOffline {
		s.elOffline.Store(1)
	} else {
		s.elOffline.Store(0)
	}
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
			// Update channel length metric periodically.
			if s.health != nil {
				s.health.SinkEventChannelLength.WithLabelValues("raw").
					Set(float64(len(s.eventCh)))
			}

			s.refreshMonotonicOffset()
			s.tickFlush(ctx)
		}
	}
}

func (s *RawSink) addEvent(
	ctx context.Context,
	event tracer.ParsedEvent,
) {
	row := toRawRow(
		event,
		s.currentSlot.Load(),
		s.currentSlotStart.Load(),
		s.monotonicOffsetNs.Load(),
		s.includeFilenames,
		s.clSyncing.Load() == 1,
		s.elOptimistic.Load() == 1,
		s.elOffline.Load() == 1,
	)

	s.mu.Lock()
	s.batch = append(s.batch, row)
	shouldFlush := len(s.batch) >= s.writer.Config().BatchSize
	var toFlush []rawRow

	if shouldFlush {
		toFlush = s.batch
		s.batch = s.batch[:0]
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
	s.batch = s.batch[:0]
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

	// Export to HTTP if enabled.
	if s.httpProcessor != nil {
		s.exportHTTP(ctx, rows)
	}

	start := time.Now()

	conn := s.writer.Conn()
	cfg := s.writer.Config()
	table := fmt.Sprintf("%s.%s", cfg.Database, cfg.Table)

	batch, err := conn.PrepareBatch(
		ctx,
		fmt.Sprintf(
			"INSERT INTO %s (timestamp_ns, wallclock_slot, wallclock_slot_start_date_time, pid, tid, event_type, client_type, latency_ns, bytes, src_port, dst_port, fd, filename, voluntary, major, address, on_cpu_ns, rw, queue_depth, device_id, runqueue_ns, off_cpu_ns, tcp_state, tcp_old_state, tcp_srtt_us, tcp_cwnd, pages, exit_code, target_pid, cl_syncing, el_optimistic, el_offline)",
			table,
		),
	)
	if err != nil {
		s.recordBatchError("prepare")

		return fmt.Errorf("preparing batch: %w", err)
	}

	for _, row := range rows {
		if err := batch.Append(
			row.TimestampNs,
			row.WallclockSlot,
			row.SlotStart,
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
			row.RW,
			row.QueueDepth,
			row.DeviceID,
			row.RunqueueNs,
			row.OffCpuNs,
			row.TcpState,
			row.TcpOldState,
			row.TcpSrttUs,
			row.TcpCwnd,
			row.Pages,
			row.ExitCode,
			row.TargetPID,
			row.CLSyncing,
			row.ELOptimistic,
			row.ELOffline,
		); err != nil {
			s.recordBatchError("append")

			return fmt.Errorf("appending row: %w", err)
		}
	}

	if err := batch.Send(); err != nil {
		s.recordBatchError("send")

		return fmt.Errorf("sending batch of %d rows: %w", len(rows), err)
	}

	// Record success metrics.
	if s.health != nil {
		duration := time.Since(start)
		s.health.SinkFlushDuration.WithLabelValues("raw").Observe(duration.Seconds())
		s.health.SinkBatchSize.WithLabelValues("raw").Observe(float64(len(rows)))
		s.health.ClickHouseBatchDuration.WithLabelValues("send").Observe(duration.Seconds())
	}

	s.log.WithField("rows", len(rows)).
		Debug("Flushed raw events")

	return nil
}

// exportHTTP exports rows to the HTTP processor.
func (s *RawSink) exportHTTP(ctx context.Context, rows []rawRow) {
	events := make([]*RawEventJSON, 0, len(rows))

	for _, row := range rows {
		event := toRawEventJSON(row, s.cfg.HTTP.MetaClientName, s.cfg.HTTP.MetaNetworkName)
		events = append(events, &event)
	}

	if err := s.httpProcessor.Write(ctx, events); err != nil {
		s.log.WithError(err).Debug("HTTP export failed (queue may be full)")
	}
}

func toRawRow(
	event tracer.ParsedEvent,
	wallclockSlot uint64,
	slotStartNs int64,
	monotonicOffsetNs int64,
	includeFilenames bool,
	clSyncing bool,
	elOptimistic bool,
	elOffline bool,
) rawRow {
	timestampNs := int64(event.Raw.TimestampNs) + monotonicOffsetNs
	if timestampNs < 0 {
		timestampNs = 0
	}

	row := rawRow{
		// Use wall clock time for storage. The BPF ktime_get_ns()
		// value is monotonic (since boot), not Unix epoch.
		TimestampNs:   uint64(timestampNs),
		WallclockSlot: wallclockSlot,
		SlotStart:     time.Unix(0, slotStartNs),
		PID:           event.Raw.PID,
		TID:           event.Raw.TID,
		EventType:     event.Raw.Type.String(),
		ClientType:    event.Raw.Client.String(),
		CLSyncing:     clSyncing,
		ELOptimistic:  elOptimistic,
		ELOffline:     elOffline,
	}

	switch e := event.Typed.(type) {
	case tracer.SyscallEvent:
		row.LatencyNs = e.LatencyNs
		row.Bytes = e.Return
		row.FD = e.FD
	case tracer.DiskIOEvent:
		row.LatencyNs = e.LatencyNs
		row.Bytes = int64(e.Bytes)
		row.RW = e.ReadWrite
		row.QueueDepth = e.QueueDepth
		row.DeviceID = e.DeviceID
	case tracer.NetIOEvent:
		row.Bytes = int64(e.Bytes)
		row.SrcPort = e.SrcPort
		row.DstPort = e.DstPort
	case tracer.SchedEvent:
		row.Voluntary = e.Voluntary
		row.OnCpuNs = e.OnCpuNs
	case tracer.SchedRunqueueEvent:
		row.RunqueueNs = e.RunqueueNs
		row.OffCpuNs = e.OffCpuNs
	case tracer.PageFaultEvent:
		row.Address = e.Address
		row.Major = e.Major
	case tracer.FDEvent:
		row.FD = e.FD
		if includeFilenames {
			row.Filename = e.Filename
		}
	case tracer.BlockMergeEvent:
		row.Bytes = int64(e.Bytes)
		row.RW = e.ReadWrite
	case tracer.TcpRetransmitEvent:
		row.Bytes = int64(e.Bytes)
		row.SrcPort = e.SrcPort
		row.DstPort = e.DstPort
	case tracer.TcpStateEvent:
		row.SrcPort = e.SrcPort
		row.DstPort = e.DstPort
		row.TcpState = e.NewState
		row.TcpOldState = e.OldState
	case tracer.TcpMetricsEvent:
		row.SrcPort = e.SrcPort
		row.DstPort = e.DstPort
		row.TcpSrttUs = e.SrttUs
		row.TcpCwnd = e.Cwnd
	case tracer.MemLatencyEvent:
		row.LatencyNs = e.DurationNs
	case tracer.SwapEvent:
		row.Pages = e.Pages
	case tracer.OOMKillEvent:
		row.TargetPID = e.TargetPID
	case tracer.ProcessExitEvent:
		row.ExitCode = e.ExitCode
	}

	return row
}

func (s *RawSink) refreshMonotonicOffset() {
	offset, err := monotonicOffsetNs()
	if err != nil {
		s.log.WithError(err).
			Debug("Failed to refresh monotonic offset")
		return
	}

	s.monotonicOffsetNs.Store(offset)
}

func monotonicOffsetNs() (int64, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0, err
	}

	mono := ts.Nano()
	now := time.Now().UnixNano()

	return now - mono, nil
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

// recordBatchError records a batch error with categorized error type.
func (s *RawSink) recordBatchError(errorType string) {
	if s.health == nil {
		return
	}

	s.health.ExportBatchErrors.WithLabelValues("raw", errorType).Inc()
}
