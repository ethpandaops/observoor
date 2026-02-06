package export

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
)

// HealthConfig configures the Prometheus health metrics server.
type HealthConfig struct {
	// Addr is the listen address for the health metrics server.
	// Defaults to ":9090".
	Addr string `yaml:"addr"`
}

// HealthMetrics exposes Prometheus metrics for agent health.
type HealthMetrics struct {
	log      logrus.FieldLogger
	addr     string
	server   *http.Server
	listener net.Listener
	registry *prometheus.Registry

	// === Existing Metrics (preserved for backwards compatibility) ===
	EventsReceived prometheus.Counter
	EventsDropped  prometheus.Counter
	SlotsFlushed   prometheus.Counter
	ExportErrors   prometheus.Counter
	PIDsTracked    prometheus.Gauge
	CurrentSlot    prometheus.Gauge
	IsSyncing      prometheus.Gauge
	IsOptimistic   prometheus.Gauge
	ELOffline      prometheus.Gauge
	RingBufUsed    prometheus.Gauge

	// === Tier 1: Critical (Detect Failures) ===

	// BPF/Tracer Layer
	BPFProgramsAttached *prometheus.GaugeVec   // type (tracepoint/kprobe/kretprobe)
	BPFProgramsFailed   *prometheus.GaugeVec   // type
	BPFRingbufOverflows prometheus.Counter     // ring buffer overflows
	EventParseErrors    *prometheus.CounterVec // error_type

	// Discovery Layer
	PIDDiscoveryErrors *prometheus.CounterVec // source (process/cgroup)
	PIDsByClient       *prometheus.GaugeVec   // client_type

	// Export Layer
	ClickHouseConnected *prometheus.GaugeVec   // sink
	ExportBatchErrors   *prometheus.CounterVec // sink, error_type

	// Beacon Client
	BeaconRequestsTotal *prometheus.CounterVec // endpoint, status
	BeaconSyncDistance  prometheus.Gauge

	// === Tier 2: Important (Diagnose Performance) ===

	// BPF/Tracer Layer
	EventProcessingDuration prometheus.Histogram   // 10us-5ms buckets
	RingbufCapacityBytes    prometheus.Gauge       // total ring buffer size
	EventsByType            *prometheus.CounterVec // event_type

	// Sink Layer
	SinkEventChannelLength   *prometheus.GaugeVec     // sink
	SinkEventChannelCapacity *prometheus.GaugeVec     // sink
	SinkFlushDuration        *prometheus.HistogramVec // sink
	SinkBatchSize            *prometheus.HistogramVec // sink
	SinkEventsProcessed      *prometheus.CounterVec   // sink

	// Export Layer
	ClickHouseBatchDuration *prometheus.HistogramVec // operation

	// Beacon Client
	BeaconRequestDuration *prometheus.HistogramVec // endpoint

	// === Tier 3: Nice-to-Have (Deep Observability) ===

	BPFMapEntries        *prometheus.GaugeVec // map
	EventsByClient       *prometheus.CounterVec
	AgentStartDuration   *prometheus.GaugeVec   // phase
	TIDDiscoveryCount    prometheus.Gauge       // total TIDs discovered
	PIDRefreshDuration   prometheus.Histogram   // PID refresh latency
	SlotDuration         prometheus.Histogram   // actual slot duration observed
	AggregatedDimensions *prometheus.CounterVec // dimension_type

	running atomic.Bool
}

// NewHealthMetrics creates a new health metrics server.
func NewHealthMetrics(
	log logrus.FieldLogger,
	cfg HealthConfig,
) *HealthMetrics {
	reg := prometheus.NewRegistry()

	h := &HealthMetrics{
		log:      log.WithField("component", "health"),
		addr:     cfg.Addr,
		registry: reg,

		// === Existing Metrics ===
		EventsReceived: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "observoor",
			Name:      "events_received_total",
			Help:      "Total events received from BPF ring buffer.",
		}),
		EventsDropped: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "observoor",
			Name:      "events_dropped_total",
			Help:      "Total events dropped due to processing errors.",
		}),
		SlotsFlushed: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "observoor",
			Name:      "slots_flushed_total",
			Help:      "Total slot aggregation flushes.",
		}),
		ExportErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "observoor",
			Name:      "export_errors_total",
			Help:      "Total export errors across all sinks.",
		}),
		PIDsTracked: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "observoor",
			Name:      "pids_tracked",
			Help:      "Number of PIDs currently tracked.",
		}),
		CurrentSlot: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "observoor",
			Name:      "current_slot",
			Help:      "Current Ethereum slot number.",
		}),
		IsSyncing: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "observoor",
			Name:      "is_syncing",
			Help:      "Whether the beacon node is syncing (1=yes, 0=no).",
		}),
		IsOptimistic: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "observoor",
			Name:      "is_optimistic",
			Help:      "Whether the execution layer is in optimistic sync mode (1=yes, 0=no).",
		}),
		ELOffline: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "observoor",
			Name:      "el_offline",
			Help:      "Whether the execution layer is unreachable (1=yes, 0=no).",
		}),
		RingBufUsed: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "observoor",
			Name:      "ringbuf_used_bytes",
			Help:      "Approximate ring buffer usage in bytes.",
		}),

		// === Tier 1: Critical ===

		BPFProgramsAttached: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: "observoor",
				Name:      "bpf_programs_attached",
				Help:      "Number of successfully attached BPF programs by type.",
			},
			[]string{"type"},
		),
		BPFProgramsFailed: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: "observoor",
				Name:      "bpf_programs_failed",
				Help:      "Number of BPF programs that failed to attach by type.",
			},
			[]string{"type"},
		),
		BPFRingbufOverflows: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "observoor",
			Name:      "bpf_ringbuf_overflows_total",
			Help:      "Total ring buffer overflow events.",
		}),
		EventParseErrors: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "observoor",
				Name:      "event_parse_errors_total",
				Help:      "Total event parse errors by error type.",
			},
			[]string{"error_type"},
		),
		PIDDiscoveryErrors: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "observoor",
				Name:      "pid_discovery_errors_total",
				Help:      "Total PID discovery errors by source.",
			},
			[]string{"source"},
		),
		PIDsByClient: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: "observoor",
				Name:      "pids_by_client",
				Help:      "Number of PIDs tracked per client type.",
			},
			[]string{"client_type"},
		),
		ClickHouseConnected: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: "observoor",
				Name:      "clickhouse_connected",
				Help:      "Whether ClickHouse connection is established (1=yes, 0=no).",
			},
			[]string{"sink"},
		),
		ExportBatchErrors: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "observoor",
				Name:      "export_batch_errors_total",
				Help:      "Total export batch errors by sink and error type.",
			},
			[]string{"sink", "error_type"},
		),
		BeaconRequestsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "observoor",
				Name:      "beacon_requests_total",
				Help:      "Total beacon node API requests by endpoint and status.",
			},
			[]string{"endpoint", "status"},
		),
		BeaconSyncDistance: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "observoor",
			Name:      "beacon_sync_distance",
			Help:      "Beacon node sync distance in slots.",
		}),

		// === Tier 2: Important ===

		EventProcessingDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: "observoor",
			Name:      "event_processing_duration_seconds",
			Help:      "Time to process a single event from BPF ring buffer.",
			Buckets:   []float64{0.00001, 0.00005, 0.0001, 0.0005, 0.001, 0.005}, // 10us-5ms
		}),
		RingbufCapacityBytes: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "observoor",
			Name:      "ringbuf_capacity_bytes",
			Help:      "Total ring buffer capacity in bytes.",
		}),
		EventsByType: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "observoor",
				Name:      "events_by_type_total",
				Help:      "Total events received by event type.",
			},
			[]string{"event_type"},
		),
		SinkEventChannelLength: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: "observoor",
				Name:      "sink_event_channel_length",
				Help:      "Current number of events in sink channel.",
			},
			[]string{"sink"},
		),
		SinkEventChannelCapacity: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: "observoor",
				Name:      "sink_event_channel_capacity",
				Help:      "Capacity of sink event channel.",
			},
			[]string{"sink"},
		),
		SinkFlushDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: "observoor",
				Name:      "sink_flush_duration_seconds",
				Help:      "Time to flush a batch to ClickHouse by sink.",
				Buckets:   []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1}, // 1ms-1s
			},
			[]string{"sink"},
		),
		SinkBatchSize: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: "observoor",
				Name:      "sink_batch_size",
				Help:      "Number of rows per batch flush by sink.",
				Buckets:   []float64{100, 500, 1000, 5000, 10000, 25000, 50000}, // 100-50000
			},
			[]string{"sink"},
		),
		SinkEventsProcessed: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "observoor",
				Name:      "sink_events_processed_total",
				Help:      "Total events processed by sink.",
			},
			[]string{"sink"},
		),
		ClickHouseBatchDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: "observoor",
				Name:      "clickhouse_batch_duration_seconds",
				Help:      "Time to write a batch to ClickHouse by operation.",
				Buckets:   []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5}, // 1ms-500ms
			},
			[]string{"operation"},
		),
		BeaconRequestDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: "observoor",
				Name:      "beacon_request_duration_seconds",
				Help:      "Beacon node API request duration by endpoint.",
				Buckets:   []float64{0.01, 0.05, 0.1, 0.5, 1, 5}, // 10ms-5s
			},
			[]string{"endpoint"},
		),

		// === Tier 3: Nice-to-Have ===

		BPFMapEntries: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: "observoor",
				Name:      "bpf_map_entries",
				Help:      "Number of entries in BPF maps.",
			},
			[]string{"map"},
		),
		EventsByClient: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "observoor",
				Name:      "events_by_client_total",
				Help:      "Total events received by client type.",
			},
			[]string{"client_type"},
		),
		AgentStartDuration: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: "observoor",
				Name:      "agent_start_duration_seconds",
				Help:      "Duration of agent startup phases.",
			},
			[]string{"phase"},
		),
		TIDDiscoveryCount: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "observoor",
			Name:      "tid_discovery_count",
			Help:      "Total number of TIDs discovered.",
		}),
		PIDRefreshDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: "observoor",
			Name:      "pid_refresh_duration_seconds",
			Help:      "Time to refresh PID discovery.",
			Buckets:   []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1},
		}),
		SlotDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: "observoor",
			Name:      "slot_duration_seconds",
			Help:      "Observed slot duration in seconds.",
			Buckets:   []float64{11, 11.5, 12, 12.5, 13, 14, 15},
		}),
		AggregatedDimensions: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "observoor",
				Name:      "aggregated_dimensions_total",
				Help:      "Total aggregated dimensions by type.",
			},
			[]string{"dimension_type"},
		),
	}

	// Register existing metrics
	reg.MustRegister(
		h.EventsReceived,
		h.EventsDropped,
		h.SlotsFlushed,
		h.ExportErrors,
		h.PIDsTracked,
		h.CurrentSlot,
		h.IsSyncing,
		h.IsOptimistic,
		h.ELOffline,
		h.RingBufUsed,
	)

	// Register Tier 1 metrics
	reg.MustRegister(
		h.BPFProgramsAttached,
		h.BPFProgramsFailed,
		h.BPFRingbufOverflows,
		h.EventParseErrors,
		h.PIDDiscoveryErrors,
		h.PIDsByClient,
		h.ClickHouseConnected,
		h.ExportBatchErrors,
		h.BeaconRequestsTotal,
		h.BeaconSyncDistance,
	)

	// Register Tier 2 metrics
	reg.MustRegister(
		h.EventProcessingDuration,
		h.RingbufCapacityBytes,
		h.EventsByType,
		h.SinkEventChannelLength,
		h.SinkEventChannelCapacity,
		h.SinkFlushDuration,
		h.SinkBatchSize,
		h.SinkEventsProcessed,
		h.ClickHouseBatchDuration,
		h.BeaconRequestDuration,
	)

	// Register Tier 3 metrics
	reg.MustRegister(
		h.BPFMapEntries,
		h.EventsByClient,
		h.AgentStartDuration,
		h.TIDDiscoveryCount,
		h.PIDRefreshDuration,
		h.SlotDuration,
		h.AggregatedDimensions,
	)

	return h
}

// Start begins serving the /metrics endpoint.
func (h *HealthMetrics) Start(_ context.Context) error {
	if h.addr == "" {
		h.addr = ":9090"
	}

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(
		h.registry,
		promhttp.HandlerOpts{},
	))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	})

	// pprof endpoints for CPU/memory profiling.
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

	ln, err := net.Listen("tcp", h.addr)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", h.addr, err)
	}

	h.listener = ln

	h.server = &http.Server{
		Handler: mux,
	}

	h.running.Store(true)

	go func() {
		h.log.WithField("addr", ln.Addr().String()).
			Info("Health metrics server started")

		if err := h.server.Serve(ln); err != nil &&
			err != http.ErrServerClosed {
			h.log.WithError(err).
				Error("Health metrics server error")
		}

		h.running.Store(false)
	}()

	return nil
}

// Addr returns the actual listener address. Useful when started
// with ":0" to get the OS-assigned port.
func (h *HealthMetrics) Addr() string {
	if h.listener != nil {
		return h.listener.Addr().String()
	}

	return h.addr
}

// Stop gracefully shuts down the health metrics server.
func (h *HealthMetrics) Stop() error {
	if h.server == nil {
		return nil
	}

	return h.server.Close()
}
