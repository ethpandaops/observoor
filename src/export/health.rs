use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use prometheus::{
    Counter, CounterVec, Encoder, Gauge, GaugeVec, Histogram, HistogramOpts, HistogramVec, Opts,
    Registry, TextEncoder,
};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

/// Prometheus metrics for agent health and observability.
///
/// All metrics use the "observoor" namespace. Organized into tiers:
/// - Core: essential operational counters/gauges
/// - Tier 1: critical failure-detection metrics
/// - Tier 2: performance diagnostic metrics
/// - Tier 3: deep observability metrics
pub struct HealthMetrics {
    registry: Registry,
    addr: String,
    shutdown: parking_lot::Mutex<Option<CancellationToken>>,

    // === Core Metrics ===
    /// Total events received from BPF ring buffer.
    pub events_received: Counter,
    /// Total events dropped due to processing errors.
    pub events_dropped: Counter,
    /// Total slot aggregation flushes.
    pub slots_flushed: Counter,
    /// Total export errors across all sinks.
    #[allow(dead_code)]
    pub export_errors: Counter,
    /// Number of PIDs currently tracked.
    pub pids_tracked: Gauge,
    /// Current Ethereum slot number.
    pub current_slot: Gauge,
    /// Whether the beacon node is syncing (1=yes, 0=no).
    pub is_syncing: Gauge,
    /// Whether the EL is in optimistic sync mode (1=yes, 0=no).
    pub is_optimistic: Gauge,
    /// Whether the execution layer is unreachable (1=yes, 0=no).
    pub el_offline: Gauge,
    /// Approximate ring buffer usage in bytes.
    pub ringbuf_used: Gauge,

    // === Tier 1: Critical ===
    /// BPF programs attached by type (tracepoint/kprobe/kretprobe).
    pub bpf_programs_attached: GaugeVec,
    /// BPF programs that failed to attach by type.
    pub bpf_programs_failed: GaugeVec,
    /// Total ring buffer overflow events.
    pub bpf_ringbuf_overflows: Counter,
    /// Event parse errors by error_type.
    #[allow(dead_code)]
    pub event_parse_errors: CounterVec,
    /// PID discovery errors by source (process/cgroup).
    #[allow(dead_code)]
    pub pid_discovery_errors: CounterVec,
    /// PIDs tracked per client type.
    pub pids_by_client: GaugeVec,
    /// ClickHouse connection state per sink (1=connected, 0=disconnected).
    pub clickhouse_connected: GaugeVec,
    /// Export batch errors by sink and error_type.
    pub export_batch_errors: CounterVec,
    /// Beacon API requests by endpoint and status.
    pub beacon_requests_total: CounterVec,
    /// Beacon request duration by endpoint.
    pub beacon_request_duration: HistogramVec,
    /// Beacon node sync distance in slots.
    pub beacon_sync_distance: Gauge,

    // === Tier 2: Important ===
    /// Per-event processing duration (10us-5ms buckets).
    pub event_processing_duration: Histogram,
    /// Total ring buffer capacity in bytes.
    pub ringbuf_capacity_bytes: Gauge,
    /// Events by event type.
    pub events_by_type: CounterVec,
    /// Events by client type.
    pub events_by_client: CounterVec,
    /// Current sink event channel length.
    pub sink_event_channel_length: GaugeVec,
    /// Sink event channel capacity.
    pub sink_event_channel_capacity: GaugeVec,
    /// Sink events processed total.
    pub sink_events_processed: CounterVec,
    /// Sink flush duration (1ms-1s buckets).
    pub sink_flush_duration: HistogramVec,
    /// Sink batch size (100-50000 buckets).
    pub sink_batch_size: HistogramVec,
    /// ClickHouse batch write duration by operation (1ms-500ms buckets).
    pub clickhouse_batch_duration: HistogramVec,

    // === Tier 3: Nice-to-Have ===
    /// BPF map entries by map name.
    pub bpf_map_entries: GaugeVec,
    /// Agent startup duration by phase.
    pub agent_start_duration: GaugeVec,
    /// Total TIDs discovered.
    pub tid_discovery_count: Gauge,
    /// PID refresh latency.
    pub pid_refresh_duration: Histogram,
    /// Observed slot duration in seconds (11-15s buckets).
    pub slot_duration: Histogram,
    /// Aggregated dimensions by type.
    pub aggregated_dimensions: CounterVec,
}

impl HealthMetrics {
    /// Creates a new health metrics instance with all metrics registered.
    pub fn new(addr: &str) -> Result<Self> {
        let registry = Registry::new();

        // === Core Metrics ===
        let events_received = Counter::with_opts(
            Opts::new(
                "events_received_total",
                "Total events received from BPF ring buffer.",
            )
            .namespace("observoor"),
        )?;
        let events_dropped = Counter::with_opts(
            Opts::new(
                "events_dropped_total",
                "Total events dropped due to processing errors.",
            )
            .namespace("observoor"),
        )?;
        let slots_flushed = Counter::with_opts(
            Opts::new("slots_flushed_total", "Total slot aggregation flushes.")
                .namespace("observoor"),
        )?;
        let export_errors = Counter::with_opts(
            Opts::new(
                "export_errors_total",
                "Total export errors across all sinks.",
            )
            .namespace("observoor"),
        )?;
        let pids_tracked = Gauge::with_opts(
            Opts::new("pids_tracked", "Number of PIDs currently tracked.").namespace("observoor"),
        )?;
        let current_slot = Gauge::with_opts(
            Opts::new("current_slot", "Current Ethereum slot number.").namespace("observoor"),
        )?;
        let is_syncing = Gauge::with_opts(
            Opts::new(
                "is_syncing",
                "Whether the beacon node is syncing (1=yes, 0=no).",
            )
            .namespace("observoor"),
        )?;
        let is_optimistic = Gauge::with_opts(
            Opts::new(
                "is_optimistic",
                "Whether the execution layer is in optimistic sync mode (1=yes, 0=no).",
            )
            .namespace("observoor"),
        )?;
        let el_offline = Gauge::with_opts(
            Opts::new(
                "el_offline",
                "Whether the execution layer is unreachable (1=yes, 0=no).",
            )
            .namespace("observoor"),
        )?;
        let ringbuf_used = Gauge::with_opts(
            Opts::new(
                "ringbuf_used_bytes",
                "Approximate ring buffer usage in bytes.",
            )
            .namespace("observoor"),
        )?;

        // === Tier 1: Critical ===
        let bpf_programs_attached = GaugeVec::new(
            Opts::new(
                "bpf_programs_attached",
                "Number of successfully attached BPF programs by type.",
            )
            .namespace("observoor"),
            &["type"],
        )?;
        let bpf_programs_failed = GaugeVec::new(
            Opts::new(
                "bpf_programs_failed",
                "Number of BPF programs that failed to attach by type.",
            )
            .namespace("observoor"),
            &["type"],
        )?;
        let bpf_ringbuf_overflows = Counter::with_opts(
            Opts::new(
                "bpf_ringbuf_overflows_total",
                "Total ring buffer overflow events.",
            )
            .namespace("observoor"),
        )?;
        let event_parse_errors = CounterVec::new(
            Opts::new(
                "event_parse_errors_total",
                "Total event parse errors by error type.",
            )
            .namespace("observoor"),
            &["error_type"],
        )?;
        let pid_discovery_errors = CounterVec::new(
            Opts::new(
                "pid_discovery_errors_total",
                "Total PID discovery errors by source.",
            )
            .namespace("observoor"),
            &["source"],
        )?;
        let pids_by_client = GaugeVec::new(
            Opts::new("pids_by_client", "Number of PIDs tracked per client type.")
                .namespace("observoor"),
            &["client_type"],
        )?;
        let clickhouse_connected = GaugeVec::new(
            Opts::new(
                "clickhouse_connected",
                "Whether ClickHouse connection is established (1=yes, 0=no).",
            )
            .namespace("observoor"),
            &["sink"],
        )?;
        let export_batch_errors = CounterVec::new(
            Opts::new(
                "export_batch_errors_total",
                "Total export batch errors by sink and error type.",
            )
            .namespace("observoor"),
            &["sink", "error_type"],
        )?;
        let beacon_requests_total = CounterVec::new(
            Opts::new(
                "beacon_requests_total",
                "Total beacon node API requests by endpoint and status.",
            )
            .namespace("observoor"),
            &["endpoint", "status"],
        )?;
        let beacon_request_duration = HistogramVec::new(
            HistogramOpts::new(
                "beacon_request_duration_seconds",
                "Beacon node API request duration by endpoint.",
            )
            .namespace("observoor")
            .buckets(vec![0.01, 0.05, 0.1, 0.5, 1.0, 5.0]),
            &["endpoint"],
        )?;
        let beacon_sync_distance = Gauge::with_opts(
            Opts::new(
                "beacon_sync_distance",
                "Beacon node sync distance in slots.",
            )
            .namespace("observoor"),
        )?;

        // === Tier 2: Important ===
        let event_processing_duration = Histogram::with_opts(
            HistogramOpts::new(
                "event_processing_duration_seconds",
                "Time to process a single event from BPF ring buffer.",
            )
            .namespace("observoor")
            .buckets(vec![0.00001, 0.00005, 0.0001, 0.0005, 0.001, 0.005]),
        )?;
        let ringbuf_capacity_bytes = Gauge::with_opts(
            Opts::new(
                "ringbuf_capacity_bytes",
                "Total ring buffer capacity in bytes.",
            )
            .namespace("observoor"),
        )?;
        let events_by_type = CounterVec::new(
            Opts::new(
                "events_by_type_total",
                "Total events received by event type.",
            )
            .namespace("observoor"),
            &["event_type"],
        )?;
        let events_by_client = CounterVec::new(
            Opts::new(
                "events_by_client_total",
                "Total events received by client type.",
            )
            .namespace("observoor"),
            &["client_type"],
        )?;
        let sink_event_channel_length = GaugeVec::new(
            Opts::new(
                "sink_event_channel_length",
                "Current number of events in sink channel.",
            )
            .namespace("observoor"),
            &["sink"],
        )?;
        let sink_event_channel_capacity = GaugeVec::new(
            Opts::new(
                "sink_event_channel_capacity",
                "Capacity of sink event channel.",
            )
            .namespace("observoor"),
            &["sink"],
        )?;
        let sink_events_processed = CounterVec::new(
            Opts::new(
                "sink_events_processed_total",
                "Total events processed by sink.",
            )
            .namespace("observoor"),
            &["sink"],
        )?;
        let sink_flush_duration = HistogramVec::new(
            HistogramOpts::new(
                "sink_flush_duration_seconds",
                "Time to flush a batch to ClickHouse by sink.",
            )
            .namespace("observoor")
            .buckets(vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0]),
            &["sink"],
        )?;
        let sink_batch_size = HistogramVec::new(
            HistogramOpts::new("sink_batch_size", "Number of rows per batch flush by sink.")
                .namespace("observoor")
                .buckets(vec![
                    100.0, 500.0, 1000.0, 5000.0, 10000.0, 25000.0, 50000.0,
                ]),
            &["sink"],
        )?;
        let clickhouse_batch_duration = HistogramVec::new(
            HistogramOpts::new(
                "clickhouse_batch_duration_seconds",
                "Time to write a batch to ClickHouse by operation.",
            )
            .namespace("observoor")
            .buckets(vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5]),
            &["operation"],
        )?;

        // === Tier 3: Nice-to-Have ===
        let bpf_map_entries = GaugeVec::new(
            Opts::new("bpf_map_entries", "Number of entries in BPF maps.").namespace("observoor"),
            &["map"],
        )?;
        let agent_start_duration = GaugeVec::new(
            Opts::new(
                "agent_start_duration_seconds",
                "Duration of agent startup phases.",
            )
            .namespace("observoor"),
            &["phase"],
        )?;
        let tid_discovery_count = Gauge::with_opts(
            Opts::new("tid_discovery_count", "Total number of TIDs discovered.")
                .namespace("observoor"),
        )?;
        let pid_refresh_duration = Histogram::with_opts(
            HistogramOpts::new(
                "pid_refresh_duration_seconds",
                "Time to refresh PID discovery.",
            )
            .namespace("observoor")
            .buckets(vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0]),
        )?;
        let slot_duration = Histogram::with_opts(
            HistogramOpts::new(
                "slot_duration_seconds",
                "Observed slot duration in seconds.",
            )
            .namespace("observoor")
            .buckets(vec![11.0, 11.5, 12.0, 12.5, 13.0, 14.0, 15.0]),
        )?;
        let aggregated_dimensions = CounterVec::new(
            Opts::new(
                "aggregated_dimensions_total",
                "Total aggregated dimensions by type.",
            )
            .namespace("observoor"),
            &["dimension_type"],
        )?;

        // Register all metrics with the custom registry.
        // Core
        registry.register(Box::new(events_received.clone()))?;
        registry.register(Box::new(events_dropped.clone()))?;
        registry.register(Box::new(slots_flushed.clone()))?;
        registry.register(Box::new(export_errors.clone()))?;
        registry.register(Box::new(pids_tracked.clone()))?;
        registry.register(Box::new(current_slot.clone()))?;
        registry.register(Box::new(is_syncing.clone()))?;
        registry.register(Box::new(is_optimistic.clone()))?;
        registry.register(Box::new(el_offline.clone()))?;
        registry.register(Box::new(ringbuf_used.clone()))?;

        // Tier 1
        registry.register(Box::new(bpf_programs_attached.clone()))?;
        registry.register(Box::new(bpf_programs_failed.clone()))?;
        registry.register(Box::new(bpf_ringbuf_overflows.clone()))?;
        registry.register(Box::new(event_parse_errors.clone()))?;
        registry.register(Box::new(pid_discovery_errors.clone()))?;
        registry.register(Box::new(pids_by_client.clone()))?;
        registry.register(Box::new(clickhouse_connected.clone()))?;
        registry.register(Box::new(export_batch_errors.clone()))?;
        registry.register(Box::new(beacon_requests_total.clone()))?;
        registry.register(Box::new(beacon_request_duration.clone()))?;
        registry.register(Box::new(beacon_sync_distance.clone()))?;

        // Tier 2
        registry.register(Box::new(event_processing_duration.clone()))?;
        registry.register(Box::new(ringbuf_capacity_bytes.clone()))?;
        registry.register(Box::new(events_by_type.clone()))?;
        registry.register(Box::new(events_by_client.clone()))?;
        registry.register(Box::new(sink_event_channel_length.clone()))?;
        registry.register(Box::new(sink_event_channel_capacity.clone()))?;
        registry.register(Box::new(sink_events_processed.clone()))?;
        registry.register(Box::new(sink_flush_duration.clone()))?;
        registry.register(Box::new(sink_batch_size.clone()))?;
        registry.register(Box::new(clickhouse_batch_duration.clone()))?;

        // Tier 3
        registry.register(Box::new(bpf_map_entries.clone()))?;
        registry.register(Box::new(agent_start_duration.clone()))?;
        registry.register(Box::new(tid_discovery_count.clone()))?;
        registry.register(Box::new(pid_refresh_duration.clone()))?;
        registry.register(Box::new(slot_duration.clone()))?;
        registry.register(Box::new(aggregated_dimensions.clone()))?;

        Ok(Self {
            registry,
            addr: addr.to_string(),
            shutdown: parking_lot::Mutex::new(None),
            events_received,
            events_dropped,
            slots_flushed,
            export_errors,
            pids_tracked,
            current_slot,
            is_syncing,
            is_optimistic,
            el_offline,
            ringbuf_used,
            bpf_programs_attached,
            bpf_programs_failed,
            bpf_ringbuf_overflows,
            event_parse_errors,
            pid_discovery_errors,
            pids_by_client,
            clickhouse_connected,
            export_batch_errors,
            beacon_requests_total,
            beacon_request_duration,
            beacon_sync_distance,
            event_processing_duration,
            ringbuf_capacity_bytes,
            events_by_type,
            events_by_client,
            sink_event_channel_length,
            sink_event_channel_capacity,
            sink_events_processed,
            sink_flush_duration,
            sink_batch_size,
            clickhouse_batch_duration,
            bpf_map_entries,
            agent_start_duration,
            tid_discovery_count,
            pid_refresh_duration,
            slot_duration,
            aggregated_dimensions,
        })
    }

    /// Starts the HTTP server serving /metrics, /healthz, and debug endpoints.
    pub async fn start(&self) -> Result<()> {
        let addr = if self.addr.is_empty() {
            ":9090"
        } else {
            &self.addr
        };

        // Parse address, handling ":port" shorthand.
        let bind_addr = if addr.starts_with(':') {
            format!("0.0.0.0{addr}")
        } else {
            addr.to_string()
        };

        let registry = self.registry.clone();
        let app_state = Arc::new(AppState { registry });

        let app = Router::new()
            .route("/metrics", get(metrics_handler))
            .route("/healthz", get(healthz_handler));

        // Feature-gated pprof endpoints.
        #[cfg(feature = "profiling")]
        let app = app
            .route("/debug/pprof/profile", get(pprof_profile_handler))
            .route("/debug/pprof/flamegraph", get(pprof_flamegraph_handler));

        let app = app.with_state(app_state);

        let listener = TcpListener::bind(&bind_addr)
            .await
            .with_context(|| format!("listening on {bind_addr}"))?;

        let local_addr = listener.local_addr().context("getting local address")?;

        let cancel = CancellationToken::new();
        *self.shutdown.lock() = Some(cancel.clone());

        tokio::spawn(async move {
            tracing::info!(addr = %local_addr, "health metrics server started");

            let result = axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .with_graceful_shutdown(async move {
                cancel.cancelled().await;
            })
            .await;

            if let Err(e) = result {
                tracing::error!(error = %e, "health metrics server error");
            }
        });

        Ok(())
    }

    /// Gracefully shuts down the health metrics server.
    pub async fn stop(&self) -> Result<()> {
        if let Some(cancel) = self.shutdown.lock().take() {
            cancel.cancel();
        }

        Ok(())
    }
}

/// Shared state for axum handlers.
struct AppState {
    registry: Registry,
}

/// GET /metrics - Prometheus text format.
async fn metrics_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let encoder = TextEncoder::new();
    let metric_families = state.registry.gather();

    let mut buffer = Vec::new();
    if let Err(e) = encoder.encode(&metric_families, &mut buffer) {
        tracing::error!(error = %e, "encoding metrics");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "encoding error".to_string(),
        );
    }

    match String::from_utf8(buffer) {
        Ok(text) => (StatusCode::OK, text),
        Err(e) => {
            tracing::error!(error = %e, "converting metrics to string");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "encoding error".to_string(),
            )
        }
    }
}

/// GET /healthz - Simple health check.
async fn healthz_handler() -> &'static str {
    "ok"
}

/// GET /debug/pprof/profile - CPU profile (protobuf).
#[cfg(feature = "profiling")]
async fn pprof_profile_handler(
    axum::extract::Query(params): axum::extract::Query<PprofQuery>,
) -> impl IntoResponse {
    use std::time::Duration;

    let seconds = params.seconds.unwrap_or(30);

    match tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<u8>> {
        let guard = pprof::ProfilerGuardBuilder::default()
            .frequency(100)
            .build()
            .map_err(|e| anyhow::anyhow!("building profiler: {e}"))?;

        std::thread::sleep(Duration::from_secs(seconds));

        let report = guard
            .report()
            .build()
            .map_err(|e| anyhow::anyhow!("building report: {e}"))?;

        let profile = report
            .pprof()
            .map_err(|e| anyhow::anyhow!("generating pprof: {e}"))?;

        use prost::Message;
        let mut buf = Vec::with_capacity(profile.encoded_len());
        profile
            .encode(&mut buf)
            .map_err(|e| anyhow::anyhow!("encoding protobuf: {e}"))?;

        Ok(buf)
    })
    .await
    {
        Ok(Ok(body)) => (
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
            body,
        )
            .into_response(),
        Ok(Err(e)) => {
            tracing::error!(error = %e, "pprof profile");
            (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "pprof task panicked");
            (StatusCode::INTERNAL_SERVER_ERROR, "task failed").into_response()
        }
    }
}

/// GET /debug/pprof/flamegraph - SVG flamegraph.
#[cfg(feature = "profiling")]
async fn pprof_flamegraph_handler(
    axum::extract::Query(params): axum::extract::Query<PprofQuery>,
) -> impl IntoResponse {
    use std::time::Duration;

    let seconds = params.seconds.unwrap_or(30);

    match tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<u8>> {
        let guard = pprof::ProfilerGuardBuilder::default()
            .frequency(100)
            .build()
            .map_err(|e| anyhow::anyhow!("building profiler: {e}"))?;

        std::thread::sleep(Duration::from_secs(seconds));

        let report = guard
            .report()
            .build()
            .map_err(|e| anyhow::anyhow!("building report: {e}"))?;

        let mut body = Vec::new();
        report
            .flamegraph(&mut body)
            .map_err(|e| anyhow::anyhow!("generating flamegraph: {e}"))?;

        Ok(body)
    })
    .await
    {
        Ok(Ok(body)) => (
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "image/svg+xml")],
            body,
        )
            .into_response(),
        Ok(Err(e)) => {
            tracing::error!(error = %e, "pprof flamegraph");
            (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "pprof task panicked");
            (StatusCode::INTERNAL_SERVER_ERROR, "task failed").into_response()
        }
    }
}

/// Query parameters for pprof endpoints.
#[cfg(feature = "profiling")]
#[derive(serde::Deserialize)]
struct PprofQuery {
    seconds: Option<u64>,
}
