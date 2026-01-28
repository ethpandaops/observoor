package export

import (
	"context"
	"fmt"
	"net"
	"net/http"
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

	// Counters
	EventsReceived prometheus.Counter
	EventsDropped  prometheus.Counter
	SlotsFlushed   prometheus.Counter
	ExportErrors   prometheus.Counter
	PIDsTracked    prometheus.Gauge
	CurrentSlot    prometheus.Gauge
	IsSyncing      prometheus.Gauge
	RingBufUsed    prometheus.Gauge

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
		RingBufUsed: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "observoor",
			Name:      "ringbuf_used_bytes",
			Help:      "Approximate ring buffer usage in bytes.",
		}),
	}

	reg.MustRegister(
		h.EventsReceived,
		h.EventsDropped,
		h.SlotsFlushed,
		h.ExportErrors,
		h.PIDsTracked,
		h.CurrentSlot,
		h.IsSyncing,
		h.RingBufUsed,
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
