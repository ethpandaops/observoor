package agent

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/ethpandaops/observoor/internal/beacon"
	"github.com/ethpandaops/observoor/internal/clock"
	"github.com/ethpandaops/observoor/internal/export"
	"github.com/ethpandaops/observoor/internal/migrate"
	"github.com/ethpandaops/observoor/internal/pid"
	"github.com/ethpandaops/observoor/internal/sink"
	"github.com/ethpandaops/observoor/internal/sink/aggregated"
	"github.com/ethpandaops/observoor/internal/tracer"
)

// Agent is the top-level orchestrator for observoor.
type Agent interface {
	// Start initializes all components and begins observation.
	Start(ctx context.Context) error
	// Stop shuts down all components gracefully.
	Stop() error
}

type agent struct {
	log    logrus.FieldLogger
	cfg    *Config
	health *export.HealthMetrics
	beacon beacon.Client
	clock  clock.Clock
	disc   pid.Discovery
	tracer tracer.Tracer
	sinks  []sink.Sink

	// aggregatedSink is a reference to the aggregated sink for port whitelist configuration.
	aggregatedSink *aggregated.Sink

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// New creates a new Agent.
func New(log logrus.FieldLogger, cfg *Config) (Agent, error) {
	health := export.NewHealthMetrics(log, cfg.Health)

	a := &agent{
		log:    log.WithField("component", "agent"),
		cfg:    cfg,
		health: health,
		beacon: beacon.NewClient(log, cfg.Beacon, health),
		disc:   pid.NewDiscovery(log, cfg.PID, health),
		tracer: tracer.New(log, cfg.RingBufferSize, health),
		sinks:  make([]sink.Sink, 0, 3),
	}

	// Configure enabled sinks.
	if cfg.Sinks.Raw.Enabled {
		rawSink, err := sink.NewRawSink(
			log, cfg.Sinks.Raw, a.health,
			cfg.MetaClientName, cfg.MetaNetworkName,
		)
		if err != nil {
			return nil, fmt.Errorf("creating raw sink: %w", err)
		}

		a.sinks = append(a.sinks, rawSink)
	}

	if cfg.Sinks.Aggregated.Enabled {
		aggSink, err := aggregated.New(
			log, cfg.Sinks.Aggregated, health,
			cfg.MetaClientName, cfg.MetaNetworkName,
		)
		if err != nil {
			return nil, fmt.Errorf("creating aggregated sink: %w", err)
		}

		a.aggregatedSink = aggSink
		a.sinks = append(a.sinks, a.aggregatedSink)
	}

	return a, nil
}

func (a *agent) Start(ctx context.Context) error {
	ctx, a.cancel = context.WithCancel(ctx)

	// 0. Run migrations if enabled.
	if a.cfg.Sinks.Aggregated.Enabled && a.cfg.Sinks.Aggregated.ClickHouse.Migrations.Enabled {
		if err := a.runMigrations(ctx); err != nil {
			return fmt.Errorf("running migrations: %w", err)
		}
	}

	// 1. Start health metrics server.
	if err := a.health.Start(ctx); err != nil {
		return fmt.Errorf("starting health metrics: %w", err)
	}

	a.log.Info("Health metrics server started")

	// 2. Fetch genesis and spec from beacon node.
	genesis, err := a.beacon.FetchGenesis(ctx)
	if err != nil {
		return fmt.Errorf("fetching genesis: %w", err)
	}

	a.log.WithField("genesis_time", genesis.GenesisTime).
		Info("Fetched genesis info")

	spec, err := a.beacon.FetchSpec(ctx)
	if err != nil {
		return fmt.Errorf("fetching chain spec: %w", err)
	}

	a.log.WithFields(logrus.Fields{
		"seconds_per_slot": spec.SecondsPerSlot,
		"slots_per_epoch":  spec.SlotsPerEpoch,
	}).Info("Fetched chain spec")

	// 3. Fetch initial sync state (no longer wait for sync - collect data during sync).
	initialSync, err := a.beacon.FetchSyncStatus(ctx)
	if err != nil {
		a.log.WithError(err).Warn("Failed to fetch initial sync status, using defaults")

		initialSync = &beacon.SyncStatus{}
	}

	a.updateSyncMetrics(initialSync)

	a.log.WithFields(logrus.Fields{
		"is_syncing":    initialSync.IsSyncing,
		"is_optimistic": initialSync.IsOptimistic,
		"el_offline":    initialSync.ELOffline,
		"head_slot":     initialSync.HeadSlot,
		"sync_distance": initialSync.SyncDistance,
	}).Info("Fetched initial sync state (collecting data regardless of sync status)")

	// 4. Initialize wall clock.
	a.clock, err = clock.New(
		a.log, genesis.GenesisTime,
		spec.SecondsPerSlot, spec.SlotsPerEpoch,
	)
	if err != nil {
		return fmt.Errorf("creating clock: %w", err)
	}

	// 5. Discover PIDs.
	pids, err := a.disc.Discover(ctx)
	if err != nil {
		return fmt.Errorf("discovering PIDs: %w", err)
	}

	if len(pids) == 0 {
		return fmt.Errorf("no PIDs discovered")
	}

	a.health.PIDsTracked.Set(float64(len(pids)))

	clientTypes := resolveClientTypes(pids)

	// Update PIDs by client metric.
	a.updatePIDsByClient(clientTypes)

	// 5b. Discover well-known ports from process cmdlines.
	if a.aggregatedSink != nil {
		portInfos := DiscoverPorts(a.log, pids, clientTypes)
		allPorts := GetAllTrackedPorts(portInfos)

		a.aggregatedSink.SetPortWhitelist(allPorts)

		portList := make([]uint16, 0, len(allPorts))
		for p := range allPorts {
			portList = append(portList, p)
		}

		a.log.WithField("ports", portList).
			Info("Discovered well-known ports for tracking")
	}

	// 6. Start all enabled sinks.
	for _, s := range a.sinks {
		if err := s.Start(ctx); err != nil {
			return fmt.Errorf("starting sink %s: %w", s.Name(), err)
		}

		a.log.WithField("sink", s.Name()).Info("Sink started")
	}

	// 6b. Set initial sync state on all sinks.
	for _, s := range a.sinks {
		s.SetSyncState(*initialSync)
	}

	// 7. Register slot change callback.
	a.clock.OnSlotChanged(func(slot uint64) {
		a.health.CurrentSlot.Set(float64(slot))
		a.health.SlotsFlushed.Inc()

		slotStart := a.clock.SlotStartTime(slot)
		for _, s := range a.sinks {
			s.OnSlotChanged(slot, slotStart)
		}
	})

	// 8. Seed all sinks with the current slot so events arriving
	// after handlers are registered get a valid slot immediately.
	initialSlot := a.clock.CurrentSlot()
	a.health.CurrentSlot.Set(float64(initialSlot))
	for _, s := range a.sinks {
		s.OnSlotChanged(initialSlot, a.clock.SlotStartTime(initialSlot))
	}

	// 9. Start the clock.
	if err := a.clock.Start(ctx); err != nil {
		return fmt.Errorf("starting clock: %w", err)
	}

	// 10. Register tracer handlers for events, errors, and ringbuf stats.
	a.tracer.OnEvent(func(event tracer.ParsedEvent) {
		start := time.Now()

		a.health.EventsReceived.Inc()

		// Track events by type and client.
		a.health.EventsByType.WithLabelValues(event.Raw.Type.String()).Inc()
		a.health.EventsByClient.WithLabelValues(event.Raw.Client.String()).Inc()

		for _, s := range a.sinks {
			s.HandleEvent(event)
		}

		// Track event processing duration.
		a.health.EventProcessingDuration.Observe(time.Since(start).Seconds())
	})

	a.tracer.OnError(func(err error) {
		a.health.EventsDropped.Inc()
		a.log.WithError(err).Debug("Tracer error")
	})

	a.tracer.OnRingbufStats(func(stats tracer.RingbufStats) {
		a.health.RingBufUsed.Set(float64(stats.UsedBytes))
	})

	// 11. Load BPF programs and populate PID map.
	if err := a.tracer.Start(ctx); err != nil {
		return fmt.Errorf("starting BPF tracer: %w", err)
	}

	if err := a.tracer.UpdatePIDs(pids, clientTypes); err != nil {
		return fmt.Errorf("updating PIDs in BPF map: %w", err)
	}

	// 11b. Discover TIDs and populate tracked_tids map.
	tids, tidInfo := a.discoverTIDs(pids, clientTypes)

	if err := a.tracer.UpdateTIDs(tids, tidInfo); err != nil {
		return fmt.Errorf("updating TIDs in BPF map: %w", err)
	}

	// Update TID discovery count metric.
	a.health.TIDDiscoveryCount.Set(float64(len(tids)))

	a.log.WithField("count", len(tids)).
		Info("Updated tracked TIDs")

	// 12. Start sync state monitor.
	a.wg.Add(1)

	go a.monitorSyncState(ctx)

	// 13. Start PID refresh monitor.
	a.wg.Add(1)

	go a.monitorPIDs(ctx)

	a.log.Info("Agent fully started")

	return nil
}

func (a *agent) Stop() error {
	if a.cancel != nil {
		a.cancel()
	}

	a.wg.Wait()

	// Stop in reverse order.
	if a.clock != nil {
		a.clock.Stop()
	}

	if a.tracer != nil {
		a.tracer.Stop()
	}

	for _, s := range a.sinks {
		if err := s.Stop(); err != nil {
			a.log.WithError(err).WithField("sink", s.Name()).
				Error("Error stopping sink")
		}
	}

	if a.health != nil {
		a.health.Stop()
	}

	return nil
}

func (a *agent) monitorSyncState(ctx context.Context) {
	defer a.wg.Done()

	ticker := time.NewTicker(a.cfg.SyncPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			status, err := a.beacon.FetchSyncStatus(ctx)
			if err != nil {
				a.log.WithError(err).
					Warn("Sync status poll failed")

				continue
			}

			// Update metrics and propagate sync state to all sinks.
			a.updateSyncMetrics(status)

			for _, s := range a.sinks {
				s.SetSyncState(*status)
			}
		}
	}
}

// updateSyncMetrics updates all sync-related Prometheus metrics.
func (a *agent) updateSyncMetrics(status *beacon.SyncStatus) {
	if status.IsSyncing {
		a.health.IsSyncing.Set(1)
	} else {
		a.health.IsSyncing.Set(0)
	}

	if status.IsOptimistic {
		a.health.IsOptimistic.Set(1)
	} else {
		a.health.IsOptimistic.Set(0)
	}

	if status.ELOffline {
		a.health.ELOffline.Set(1)
	} else {
		a.health.ELOffline.Set(0)
	}

	a.health.BeaconSyncDistance.Set(float64(status.SyncDistance))
}

func (a *agent) monitorPIDs(ctx context.Context) {
	defer a.wg.Done()

	ticker := time.NewTicker(a.cfg.SyncPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			start := time.Now()

			pids, err := a.disc.Discover(ctx)
			if err != nil {
				a.log.WithError(err).
					Warn("PID refresh failed")

				continue
			}

			a.health.PIDsTracked.Set(float64(len(pids)))
			clientTypes := resolveClientTypes(pids)

			// Update PIDs by client metric.
			a.updatePIDsByClient(clientTypes)

			if err := a.tracer.UpdatePIDs(pids, clientTypes); err != nil {
				a.log.WithError(err).
					Warn("PID map update failed")
			}

			tids, tidInfo := a.discoverTIDs(
				pids, clientTypes,
			)

			if err := a.tracer.UpdateTIDs(
				tids, tidInfo,
			); err != nil {
				a.log.WithError(err).
					Warn("TID map update failed")
			}

			// Update TID discovery count metric.
			a.health.TIDDiscoveryCount.Set(float64(len(tids)))

			// Record PID refresh duration.
			a.health.PIDRefreshDuration.Observe(time.Since(start).Seconds())

			a.log.WithField("count", len(tids)).
				Debug("Updated tracked TIDs")
		}
	}
}

// discoverTIDs scans /proc/<pid>/task/ for each PID to discover all
// thread IDs, mapping each TID to its parent PID's client type.
func (a *agent) discoverTIDs(
	pids []uint32,
	clientTypes map[uint32]tracer.ClientType,
) ([]uint32, map[uint32]tracer.TrackedTidInfo) {
	tids := make([]uint32, 0, len(pids)*64)
	tidInfo := make(
		map[uint32]tracer.TrackedTidInfo, len(pids)*64,
	)

	for _, p := range pids {
		ct := tracer.ClientTypeUnknown
		if c, ok := clientTypes[p]; ok {
			ct = c
		}

		taskDir := fmt.Sprintf("/proc/%d/task", p)

		entries, err := os.ReadDir(taskDir)
		if err != nil {
			a.log.WithError(err).WithField("pid", p).
				Warn("Failed to read task directory")

			continue
		}

		for _, entry := range entries {
			var tid uint32
			if _, err := fmt.Sscanf(
				entry.Name(), "%d", &tid,
			); err != nil {
				continue
			}

			tids = append(tids, tid)
			tidInfo[tid] = tracer.TrackedTidInfo{
				PID:    p,
				Client: ct,
			}
		}
	}

	return tids, tidInfo
}

// resolveClientTypes attempts to determine the Ethereum client type
// for each PID by reading /proc/<pid>/comm and /proc/<pid>/cmdline.
func resolveClientTypes(
	pids []uint32,
) map[uint32]tracer.ClientType {
	types := make(map[uint32]tracer.ClientType, len(pids))

	commMap := map[string]tracer.ClientType{
		"geth":            tracer.ClientTypeGeth,
		"reth":            tracer.ClientTypeReth,
		"besu":            tracer.ClientTypeBesu,
		"nethermind":      tracer.ClientTypeNethermind,
		"erigon":          tracer.ClientTypeErigon,
		"ethrex":          tracer.ClientTypeEthrex,
		"prysm":           tracer.ClientTypePrysm,
		"lighthouse":      tracer.ClientTypeLighthouse,
		"teku":            tracer.ClientTypeTeku,
		"lodestar":        tracer.ClientTypeLodestar,
		"nimbus":          tracer.ClientTypeNimbus,
		"nimbus_beacon_n": tracer.ClientTypeNimbus, // truncated to 15 chars
		"beacon-chain":    tracer.ClientTypePrysm,
	}

	// Keywords to search for in /proc/<pid>/cmdline when comm
	// doesn't match (e.g. Teku/Besu run as "java", Lodestar as "node").
	cmdlineKeywords := []struct {
		keyword    string
		clientType tracer.ClientType
	}{
		{"teku", tracer.ClientTypeTeku},
		{"besu", tracer.ClientTypeBesu},
		{"lodestar", tracer.ClientTypeLodestar},
		{"nimbus", tracer.ClientTypeNimbus},
		{"ethrex", tracer.ClientTypeEthrex},
	}

	for _, p := range pids {
		comm, err := readProcComm(p)
		if err != nil {
			types[p] = tracer.ClientTypeUnknown

			continue
		}

		if ct, ok := commMap[comm]; ok {
			types[p] = ct

			continue
		}

		// Fallback: search cmdline for client keywords.
		cmdline, err := readProcCmdline(p)
		if err != nil {
			types[p] = tracer.ClientTypeUnknown

			continue
		}

		matched := false

		for _, kw := range cmdlineKeywords {
			if strings.Contains(
				strings.ToLower(cmdline), kw.keyword,
			) {
				types[p] = kw.clientType
				matched = true

				break
			}
		}

		if !matched {
			types[p] = tracer.ClientTypeUnknown
		}
	}

	return types
}

func readProcComm(p uint32) (string, error) {
	path := fmt.Sprintf("/proc/%d/comm", p)

	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", path, err)
	}

	return strings.TrimSpace(string(data)), nil
}

func readProcCmdline(p uint32) (string, error) {
	path := fmt.Sprintf("/proc/%d/cmdline", p)

	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", path, err)
	}

	// cmdline uses null bytes as separators.
	return strings.ReplaceAll(string(data), "\x00", " "), nil
}

// updatePIDsByClient updates the PIDs by client metric gauge.
func (a *agent) updatePIDsByClient(clientTypes map[uint32]tracer.ClientType) {
	// Count PIDs per client type.
	counts := make(map[string]int, 12)

	for _, ct := range clientTypes {
		counts[ct.String()]++
	}

	// Update metrics for all client types (including zero counts).
	for _, name := range tracer.AllClientNames() {
		count := counts[name]
		a.health.PIDsByClient.WithLabelValues(name).Set(float64(count))
	}
}

// runMigrations executes database migrations using the aggregated sink's ClickHouse config.
func (a *agent) runMigrations(ctx context.Context) error {
	a.log.Info("Running ClickHouse migrations...")

	dsn := a.cfg.Sinks.Aggregated.ClickHouse.DSN()
	m := migrate.New(a.log, dsn)

	if err := m.Up(ctx); err != nil {
		return fmt.Errorf("applying migrations: %w", err)
	}

	return nil
}
