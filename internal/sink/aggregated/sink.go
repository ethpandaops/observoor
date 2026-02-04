package aggregated

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	processor "github.com/ethpandaops/go-batch-processor"
	"github.com/sirupsen/logrus"

	"github.com/ethpandaops/observoor/internal/beacon"
	"github.com/ethpandaops/observoor/internal/export"
	httpexport "github.com/ethpandaops/observoor/internal/export/http"
	"github.com/ethpandaops/observoor/internal/tracer"
)

// Sink is the aggregated metrics sink that provides configurable
// time-resolution aggregation with dimensional breakdown.
type Sink struct {
	log    logrus.FieldLogger
	cfg    Config
	writer *export.ClickHouseWriter
	health *export.HealthMetrics

	// HTTP export processor (optional).
	httpProcessor *processor.BatchItemProcessor[AggregatedMetricJSON]

	buffer atomic.Pointer[Buffer]

	currentSlot      atomic.Uint64
	currentSlotStart atomic.Int64

	// Sync state fields (stored as uint32: 0=false, 1=true for atomic access).
	clSyncing    atomic.Uint32
	elOptimistic atomic.Uint32
	elOffline    atomic.Uint32

	cancel  context.CancelFunc
	done    chan struct{}
	eventCh chan tracer.ParsedEvent
}

// New creates a new aggregated metrics sink.
func New(
	log logrus.FieldLogger,
	cfg Config,
	health *export.HealthMetrics,
) (*Sink, error) {
	// Apply defaults.
	if cfg.Resolution.Interval <= 0 {
		cfg.Resolution.Interval = time.Second
	}

	if cfg.ClickHouse.BatchSize <= 0 {
		cfg.ClickHouse.BatchSize = 10000
	}

	if cfg.ClickHouse.FlushInterval <= 0 {
		cfg.ClickHouse.FlushInterval = time.Second
	}

	sink := &Sink{
		log:     log.WithField("sink", "aggregated"),
		cfg:     cfg,
		writer:  export.NewClickHouseWriter(log, cfg.ClickHouse),
		health:  health,
		done:    make(chan struct{}),
		eventCh: make(chan tracer.ParsedEvent, 65536),
	}

	// Initialize HTTP processor if enabled.
	if cfg.HTTP.Enabled {
		proc, err := httpexport.NewProcessor[AggregatedMetricJSON](
			log,
			cfg.HTTP,
			"aggregated_http",
		)
		if err != nil {
			return nil, fmt.Errorf("creating HTTP processor: %w", err)
		}

		sink.httpProcessor = proc
	}

	return sink, nil
}

// Name returns the sink name.
func (s *Sink) Name() string { return "aggregated" }

// SetPortWhitelist sets the port whitelist for network dimensions.
// Only ports in this set will be tracked; others will be recorded as port 0.
// Must be called before Start().
func (s *Sink) SetPortWhitelist(ports map[uint16]struct{}) {
	s.cfg.Dimensions.Network.SetPortWhitelist(ports)
}

// Start initializes the sink and starts the event processing loop.
func (s *Sink) Start(ctx context.Context) error {
	if err := s.writer.Start(ctx); err != nil {
		return err
	}

	// Record channel capacity metric.
	if s.health != nil {
		s.health.SinkEventChannelCapacity.WithLabelValues("aggregated").
			Set(float64(cap(s.eventCh)))
		s.health.ClickHouseConnected.WithLabelValues("aggregated").Set(1)
	}

	ctx, s.cancel = context.WithCancel(ctx)

	// Start HTTP processor if enabled.
	if s.httpProcessor != nil {
		s.httpProcessor.Start(ctx)
		s.log.Info("HTTP export started")
	}

	// Initialize first buffer with current sync state.
	now := time.Now()
	slotStartNs := s.currentSlotStart.Load()
	slotStartTime := time.Unix(0, slotStartNs)

	s.buffer.Store(NewBuffer(
		now,
		0,
		slotStartTime,
		s.clSyncing.Load() == 1,
		s.elOptimistic.Load() == 1,
		s.elOffline.Load() == 1,
	))

	go s.runLoop(ctx)

	s.log.WithFields(logrus.Fields{
		"interval":     s.cfg.Resolution.Interval,
		"slot_aligned": s.cfg.Resolution.SlotAligned,
	}).Info("Aggregated sink started")

	return nil
}

// Stop shuts down the sink gracefully.
func (s *Sink) Stop() error {
	if s.cancel == nil {
		return s.writer.Stop()
	}

	s.cancel()
	<-s.done

	// Final flush - atomically swap to nil.
	finalBuffer := s.buffer.Swap(nil)

	if finalBuffer != nil {
		if err := s.flush(context.Background(), finalBuffer); err != nil {
			s.log.WithError(err).Error("Final flush failed")
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

// HandleEvent processes a single event from the tracer.
func (s *Sink) HandleEvent(event tracer.ParsedEvent) {
	select {
	case s.eventCh <- event:
		if s.health != nil {
			s.health.SinkEventsProcessed.WithLabelValues("aggregated").Inc()
		}
	default:
		s.log.Warn("Aggregated sink event channel full, dropping event")
	}
}

// OnSlotChanged is called at slot boundaries.
func (s *Sink) OnSlotChanged(slot uint64, slotStart time.Time) {
	s.currentSlot.Store(slot)
	s.currentSlotStart.Store(slotStart.UnixNano())

	if s.cfg.Resolution.SlotAligned {
		// Trigger buffer rotation on slot change.
		s.rotateBuffer(slotStart, slot)
	}
}

// SetSyncState updates the current sync state from the beacon node.
func (s *Sink) SetSyncState(status beacon.SyncStatus) {
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

// runLoop is the main event processing loop.
// Optimized for high throughput by batching event processing.
func (s *Sink) runLoop(ctx context.Context) {
	defer close(s.done)

	ticker := time.NewTicker(s.cfg.Resolution.Interval)
	defer ticker.Stop()

	// Sync state ticker - default to 12s if not configured.
	syncInterval := s.cfg.Resolution.SyncStatePollInterval
	if syncInterval <= 0 {
		syncInterval = 12 * time.Second
	}

	syncTicker := time.NewTicker(syncInterval)
	defer syncTicker.Stop()

	// Batch size for draining events.
	const batchSize = 256

	for {
		select {
		case <-ctx.Done():
			return
		case event := <-s.eventCh:
			// Process the first event.
			s.processEvent(event)

			// Drain up to batchSize-1 more events without blocking.
			s.drainEvents(batchSize - 1)
		case <-ticker.C:
			// Update channel length metric periodically.
			if s.health != nil {
				s.health.SinkEventChannelLength.WithLabelValues("aggregated").
					Set(float64(len(s.eventCh)))
			}

			s.tickFlush(ctx)
		case <-syncTicker.C:
			s.flushSyncState(ctx)
		}
	}
}

// drainEvents processes up to n events from the channel without blocking.
func (s *Sink) drainEvents(n int) {
	for i := 0; i < n; i++ {
		select {
		case event := <-s.eventCh:
			s.processEvent(event)
		default:
			return
		}
	}
}

// processEvent routes the event to the appropriate aggregator.
func (s *Sink) processEvent(event tracer.ParsedEvent) {
	// Atomic load - no mutex needed!
	buf := s.buffer.Load()
	if buf == nil {
		return
	}

	basicDim := BasicDimension{
		PID:        event.Raw.PID,
		ClientType: event.Raw.Client.String(),
	}

	switch e := event.Typed.(type) {
	case tracer.SyscallEvent:
		buf.AddSyscall(event.Raw.Type.String(), basicDim, e.LatencyNs)

	case tracer.NetIOEvent:
		netDim := s.buildNetworkDimension(event.Raw, e)
		buf.AddNetIO(netDim, int64(e.Bytes))

	case tracer.TcpRetransmitEvent:
		netDim := s.buildNetworkDimensionFromTcpRetransmit(event.Raw, e)
		buf.AddTcpRetransmit(netDim, int64(e.Bytes))

	case tracer.TcpMetricsEvent:
		tcpDim := s.buildTcpMetricsDimension(event.Raw, e)
		buf.AddTcpMetrics(tcpDim, e.SrttUs, e.Cwnd)

	case tracer.TcpStateEvent:
		buf.AddTcpStateChange(basicDim)

	case tracer.DiskIOEvent:
		diskDim := s.buildDiskDimension(event.Raw, e.DeviceID, e.ReadWrite)
		buf.AddDiskIO(diskDim, e.LatencyNs, e.Bytes, e.QueueDepth)

	case tracer.BlockMergeEvent:
		diskDim := s.buildDiskDimension(event.Raw, 0, e.ReadWrite)
		buf.AddBlockMerge(diskDim, e.Bytes)

	case tracer.SchedEvent:
		buf.AddSchedSwitch(basicDim, e.OnCpuNs)

	case tracer.SchedRunqueueEvent:
		buf.AddSchedRunqueue(basicDim, e.RunqueueNs, e.OffCpuNs)

	case tracer.PageFaultEvent:
		buf.AddPageFault(basicDim, e.Major)

	case tracer.FDEvent:
		if event.Raw.Type == tracer.EventTypeFDOpen {
			buf.AddFDOpen(basicDim)
		} else {
			buf.AddFDClose(basicDim)
		}

	case tracer.MemLatencyEvent:
		if event.Raw.Type == tracer.EventTypeMemReclaim {
			buf.AddMemReclaim(basicDim, e.DurationNs)
		} else {
			buf.AddMemCompaction(basicDim, e.DurationNs)
		}

	case tracer.SwapEvent:
		if event.Raw.Type == tracer.EventTypeSwapIn {
			buf.AddSwapIn(basicDim, e.Pages)
		} else {
			buf.AddSwapOut(basicDim, e.Pages)
		}

	case tracer.OOMKillEvent:
		buf.AddOOMKill(basicDim)

	case tracer.ProcessExitEvent:
		buf.AddProcessExit(basicDim)
	}
}

// buildNetworkDimension creates a NetworkDimension based on config.
func (s *Sink) buildNetworkDimension(
	raw tracer.Event,
	e tracer.NetIOEvent,
) NetworkDimension {
	dim := NetworkDimension{
		PID:        raw.PID,
		ClientType: raw.Client.String(),
	}

	if s.cfg.Dimensions.Network.IncludeDirection() {
		dim.Direction = uint8(e.Dir)
	}

	if s.cfg.Dimensions.Network.IncludePort() {
		// Filter port through whitelist - untracked ports become 0.
		dim.LocalPort = s.cfg.Dimensions.Network.FilterPort(localPort(e))
	}

	return dim
}

// buildNetworkDimensionFromTcpRetransmit creates a NetworkDimension for retransmits.
func (s *Sink) buildNetworkDimensionFromTcpRetransmit(
	raw tracer.Event,
	e tracer.TcpRetransmitEvent,
) NetworkDimension {
	dim := NetworkDimension{
		PID:        raw.PID,
		ClientType: raw.Client.String(),
		Direction:  0, // Retransmits are always TX.
	}

	if s.cfg.Dimensions.Network.IncludePort() {
		// For retransmits, source port is local port.
		dim.LocalPort = s.cfg.Dimensions.Network.FilterPort(e.SrcPort)
	}

	return dim
}

// buildTcpMetricsDimension creates a TCPMetricsDimension based on config.
func (s *Sink) buildTcpMetricsDimension(
	raw tracer.Event,
	e tracer.TcpMetricsEvent,
) TCPMetricsDimension {
	dim := TCPMetricsDimension{
		PID:        raw.PID,
		ClientType: raw.Client.String(),
	}

	if s.cfg.Dimensions.Network.IncludePort() {
		// Source port is typically local port for TCP metrics.
		dim.LocalPort = s.cfg.Dimensions.Network.FilterPort(e.SrcPort)
	}

	return dim
}

// buildDiskDimension creates a DiskDimension based on config.
func (s *Sink) buildDiskDimension(
	raw tracer.Event,
	deviceID uint32,
	rw uint8,
) DiskDimension {
	dim := DiskDimension{
		PID:        raw.PID,
		ClientType: raw.Client.String(),
	}

	if s.cfg.Dimensions.Disk.IncludeDevice() {
		dim.DeviceID = deviceID
	}

	if s.cfg.Dimensions.Disk.IncludeRW() {
		dim.ReadWrite = rw
	}

	return dim
}

// localPort extracts the local port from a network event.
// For TX (outbound), source is local. For RX (inbound), dest is local.
func localPort(e tracer.NetIOEvent) uint16 {
	if e.Dir == tracer.DirectionTX {
		return e.SrcPort
	}

	return e.DstPort
}

// tickFlush is called periodically to flush the current buffer.
func (s *Sink) tickFlush(ctx context.Context) {
	s.rotateBuffer(time.Now(), s.currentSlot.Load())
}

// rotateBuffer swaps the current buffer with a new one and flushes the old one.
func (s *Sink) rotateBuffer(now time.Time, slot uint64) {
	slotStartNs := s.currentSlotStart.Load()
	slotStartTime := time.Unix(0, slotStartNs)

	newBuf := NewBuffer(
		now,
		slot,
		slotStartTime,
		s.clSyncing.Load() == 1,
		s.elOptimistic.Load() == 1,
		s.elOffline.Load() == 1,
	)
	oldBuffer := s.buffer.Swap(newBuf)

	if oldBuffer == nil {
		return
	}

	go func() {
		if err := s.flush(context.Background(), oldBuffer); err != nil {
			s.log.WithError(err).Error("Buffer flush failed")
		}
	}()
}

// flush writes the buffer contents to ClickHouse.
func (s *Sink) flush(ctx context.Context, buf *Buffer) error {
	start := time.Now()
	flusher := newFlusher(s.log, s.writer, s.cfg, s.health)

	// Export to HTTP if enabled.
	if s.httpProcessor != nil {
		flusher.flushHTTP(ctx, buf, s.httpProcessor)
	}

	err := flusher.Flush(ctx, buf)

	// Record flush metrics.
	if s.health != nil && err == nil {
		duration := time.Since(start)
		s.health.SinkFlushDuration.WithLabelValues("aggregated").Observe(duration.Seconds())
	}

	return err
}

// flushSyncState writes the current sync state to ClickHouse.
func (s *Sink) flushSyncState(ctx context.Context) {
	now := time.Now()
	slotStartNs := s.currentSlotStart.Load()
	slotStartTime := time.Unix(0, slotStartNs)

	row := syncStateRow{
		UpdatedDateTime:            now,
		EventTime:                  now,
		WallclockSlot:              uint32(s.currentSlot.Load()),
		WallclockSlotStartDateTime: slotStartTime,
		CLSyncing:                  s.clSyncing.Load() == 1,
		ELOptimistic:               s.elOptimistic.Load() == 1,
		ELOffline:                  s.elOffline.Load() == 1,
	}

	if err := FlushSyncState(ctx, s.writer, s.cfg, s.health, row); err != nil {
		s.log.WithError(err).Error("Sync state flush failed")
	}
}
