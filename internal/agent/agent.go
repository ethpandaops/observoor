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
	"github.com/ethpandaops/observoor/internal/pid"
	"github.com/ethpandaops/observoor/internal/sink"
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

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// New creates a new Agent.
func New(log logrus.FieldLogger, cfg *Config) (Agent, error) {
	a := &agent{
		log:    log.WithField("component", "agent"),
		cfg:    cfg,
		health: export.NewHealthMetrics(log, cfg.Health),
		beacon: beacon.NewClient(log, cfg.Beacon),
		disc:   pid.NewDiscovery(log, cfg.PID),
		tracer: tracer.New(log, cfg.RingBufferSize),
		sinks:  make([]sink.Sink, 0, 3),
	}

	// Configure enabled sinks.
	if cfg.Sinks.Slot.Enabled {
		a.sinks = append(a.sinks, sink.NewSlotSink(log, cfg.Sinks.Slot))
	}

	if cfg.Sinks.Raw.Enabled {
		a.sinks = append(a.sinks, sink.NewRawSink(log, cfg.Sinks.Raw))
	}

	if cfg.Sinks.Window.Enabled {
		a.sinks = append(a.sinks, sink.NewWindowSink(
			log, cfg.Sinks.Window,
		))
	}

	return a, nil
}

func (a *agent) Start(ctx context.Context) error {
	ctx, a.cancel = context.WithCancel(ctx)

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

	// 3. Wait for beacon node to be synced.
	if err := a.waitForSync(ctx); err != nil {
		return fmt.Errorf("waiting for sync: %w", err)
	}

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

	// 6-7. Load BPF programs and populate PID map.
	if err := a.tracer.Start(ctx); err != nil {
		return fmt.Errorf("starting BPF tracer: %w", err)
	}

	clientTypes := resolveClientTypes(pids)

	if err := a.tracer.UpdatePIDs(pids, clientTypes); err != nil {
		return fmt.Errorf("updating PIDs in BPF map: %w", err)
	}

	// 6b. Discover TIDs and populate tracked_tids map.
	tids, tidClientTypes := a.discoverTIDs(pids, clientTypes)

	if err := a.tracer.UpdateTIDs(tids, tidClientTypes); err != nil {
		return fmt.Errorf("updating TIDs in BPF map: %w", err)
	}

	a.log.WithField("count", len(tids)).
		Info("Updated tracked TIDs")

	// 8. Start all enabled sinks.
	for _, s := range a.sinks {
		if err := s.Start(ctx); err != nil {
			return fmt.Errorf("starting sink %s: %w", s.Name(), err)
		}

		a.log.WithField("sink", s.Name()).Info("Sink started")
	}

	// 9. Register event handler for fan-out to sinks.
	a.tracer.OnEvent(func(event tracer.ParsedEvent) {
		a.health.EventsReceived.Inc()

		for _, s := range a.sinks {
			s.HandleEvent(event)
		}
	})

	// 10. Register slot change callback.
	a.clock.OnSlotChanged(func(slot uint64) {
		a.health.CurrentSlot.Set(float64(slot))
		a.health.SlotsFlushed.Inc()

		for _, s := range a.sinks {
			s.OnSlotChanged(slot)
		}
	})

	// 11. Start the clock.
	if err := a.clock.Start(ctx); err != nil {
		return fmt.Errorf("starting clock: %w", err)
	}

	// Seed all sinks with the current slot so events arriving
	// before the first OnSlotChanged callback get a valid slot.
	initialSlot := a.clock.CurrentSlot()
	for _, s := range a.sinks {
		s.OnSlotChanged(initialSlot)
	}

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

	for _, s := range a.sinks {
		if err := s.Stop(); err != nil {
			a.log.WithError(err).WithField("sink", s.Name()).
				Error("Error stopping sink")
		}
	}

	if a.tracer != nil {
		a.tracer.Stop()
	}

	if a.health != nil {
		a.health.Stop()
	}

	return nil
}

func (a *agent) waitForSync(ctx context.Context) error {
	a.log.Info("Waiting for beacon node to be synced")

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		status, err := a.beacon.FetchSyncStatus(ctx)
		if err != nil {
			a.log.WithError(err).
				Warn("Failed to fetch sync status, retrying")

			time.Sleep(5 * time.Second)

			continue
		}

		if !status.IsSyncing {
			a.log.WithField("head_slot", status.HeadSlot).
				Info("Beacon node is synced")

			a.health.IsSyncing.Set(0)

			return nil
		}

		a.health.IsSyncing.Set(1)
		a.log.WithFields(logrus.Fields{
			"head_slot":     status.HeadSlot,
			"sync_distance": status.SyncDistance,
		}).Info("Beacon node is syncing, waiting...")

		time.Sleep(10 * time.Second)
	}
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

			if status.IsSyncing {
				a.health.IsSyncing.Set(1)
			} else {
				a.health.IsSyncing.Set(0)
			}
		}
	}
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
			pids, err := a.disc.Discover(ctx)
			if err != nil {
				a.log.WithError(err).
					Warn("PID refresh failed")

				continue
			}

			a.health.PIDsTracked.Set(float64(len(pids)))
			clientTypes := resolveClientTypes(pids)

			if err := a.tracer.UpdatePIDs(pids, clientTypes); err != nil {
				a.log.WithError(err).
					Warn("PID map update failed")
			}

			tids, tidClientTypes := a.discoverTIDs(
				pids, clientTypes,
			)

			if err := a.tracer.UpdateTIDs(
				tids, tidClientTypes,
			); err != nil {
				a.log.WithError(err).
					Warn("TID map update failed")
			}

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
) ([]uint32, map[uint32]tracer.ClientType) {
	tids := make([]uint32, 0, len(pids)*64)
	tidClientTypes := make(
		map[uint32]tracer.ClientType, len(pids)*64,
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
			tidClientTypes[tid] = ct
		}
	}

	return tids, tidClientTypes
}

// resolveClientTypes attempts to determine the Ethereum client type
// for each PID by reading /proc/<pid>/comm and /proc/<pid>/cmdline.
func resolveClientTypes(
	pids []uint32,
) map[uint32]tracer.ClientType {
	types := make(map[uint32]tracer.ClientType, len(pids))

	commMap := map[string]tracer.ClientType{
		"geth":         tracer.ClientTypeGeth,
		"reth":         tracer.ClientTypeReth,
		"besu":         tracer.ClientTypeBesu,
		"nethermind":   tracer.ClientTypeNethermind,
		"erigon":       tracer.ClientTypeErigon,
		"prysm":        tracer.ClientTypePrysm,
		"lighthouse":   tracer.ClientTypeLighthouse,
		"teku":         tracer.ClientTypeTeku,
		"lodestar":     tracer.ClientTypeLodestar,
		"nimbus":       tracer.ClientTypeNimbus,
		"beacon-chain": tracer.ClientTypePrysm,
	}

	// Keywords to search for in /proc/<pid>/cmdline when comm
	// doesn't match (e.g. Teku/Besu run as "java").
	cmdlineKeywords := []struct {
		keyword    string
		clientType tracer.ClientType
	}{
		{"teku", tracer.ClientTypeTeku},
		{"besu", tracer.ClientTypeBesu},
		{"lodestar", tracer.ClientTypeLodestar},
		{"nimbus", tracer.ClientTypeNimbus},
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
