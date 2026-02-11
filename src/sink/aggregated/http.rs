use std::io::Write;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use serde::Serialize;
use tokio::sync::{mpsc, Semaphore};

use crate::config::HttpExportConfig;

#[cfg(feature = "bpf")]
use super::metric::MemoryUsageMetric;
use super::metric::{CounterMetric, CpuUtilMetric, GaugeMetric, LatencyMetric, MetricBatch};

/// Number of histogram buckets.
const NUM_BUCKETS: usize = 10;

/// Histogram as a named JSON struct matching the ClickHouse Tuple.
#[derive(Debug, Clone, Serialize)]
pub struct HistogramJson {
    pub le_1us: u32,
    pub le_10us: u32,
    pub le_100us: u32,
    pub le_1ms: u32,
    pub le_10ms: u32,
    pub le_100ms: u32,
    pub le_1s: u32,
    pub le_10s: u32,
    pub le_100s: u32,
    pub inf: u32,
}

/// Converts a histogram bucket slice to the named JSON struct.
fn histogram_to_json(h: &[u32]) -> Option<HistogramJson> {
    if h.len() != NUM_BUCKETS {
        return None;
    }
    Some(HistogramJson {
        le_1us: h.first().copied().unwrap_or(0),
        le_10us: h.get(1).copied().unwrap_or(0),
        le_100us: h.get(2).copied().unwrap_or(0),
        le_1ms: h.get(3).copied().unwrap_or(0),
        le_10ms: h.get(4).copied().unwrap_or(0),
        le_100ms: h.get(5).copied().unwrap_or(0),
        le_1s: h.get(6).copied().unwrap_or(0),
        le_10s: h.get(7).copied().unwrap_or(0),
        le_100s: h.get(8).copied().unwrap_or(0),
        inf: h.get(9).copied().unwrap_or(0),
    })
}

/// JSON schema for HTTP export of aggregated metrics.
#[derive(Debug, Clone, Serialize)]
pub struct AggregatedMetricJson {
    pub metric_type: &'static str,
    pub updated_date_time: Arc<str>,
    pub window_start: Arc<str>,
    pub interval_ms: u16,
    pub wallclock_slot: u32,
    pub wallclock_slot_start_date_time: Arc<str>,
    pub pid: u32,
    pub client_type: &'static str,
    pub sum: i64,
    pub count: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub histogram: Option<HistogramJson>,
    #[serde(skip_serializing_if = "is_empty_str")]
    pub port_label: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direction: Option<&'static str>,
    #[serde(skip_serializing_if = "is_zero_u32")]
    pub device_id: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rw: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_on_cpu_ns: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_cores: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system_cores: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_core_on_cpu_ns: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_core_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mean_core_pct: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_core_pct: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_core_pct: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vm_size_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vm_rss_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rss_anon_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rss_file_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rss_shmem_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vm_swap_bytes: Option<u64>,
    #[serde(skip_serializing_if = "is_arc_str_empty")]
    pub meta_client_name: Arc<str>,
    #[serde(skip_serializing_if = "is_arc_str_empty")]
    pub meta_network_name: Arc<str>,
}

fn is_empty_str(v: &&str) -> bool {
    v.is_empty()
}

fn is_zero_u32(v: &u32) -> bool {
    *v == 0
}

fn is_arc_str_empty(v: &Arc<str>) -> bool {
    v.is_empty()
}

#[derive(Clone)]
struct SharedBatchStrings {
    updated_date_time: Arc<str>,
    wallclock_slot_start_date_time: Arc<str>,
    meta_client_name: Arc<str>,
    meta_network_name: Arc<str>,
}

/// HTTP NDJSON exporter with worker pool and compression.
///
/// Converts metric batches to newline-delimited JSON, optionally compresses,
/// and sends via HTTP POST. Uses a bounded channel and semaphore-limited
/// workers for backpressure.
pub struct HttpExporter {
    cfg: HttpExportConfig,
    tx: Option<mpsc::Sender<AggregatedMetricJson>>,
    cancel: Option<tokio_util::sync::CancellationToken>,
}

impl HttpExporter {
    /// Creates a new HTTP exporter with the given configuration.
    pub fn new(cfg: HttpExportConfig) -> Self {
        Self {
            cfg,
            tx: None,
            cancel: None,
        }
    }

    fn shared_strings(batch: &MetricBatch) -> Option<SharedBatchStrings> {
        let slot_start = if let Some(m) = batch.latency.first() {
            m.slot.start_time
        } else if let Some(m) = batch.counter.first() {
            m.slot.start_time
        } else if let Some(m) = batch.gauge.first() {
            m.slot.start_time
        } else if let Some(m) = batch.cpu_util.first() {
            m.slot.start_time
        } else {
            #[cfg(feature = "bpf")]
            {
                if let Some(m) = batch.memory_usage.first() {
                    m.slot.start_time
                } else {
                    return None;
                }
            }
            #[cfg(not(feature = "bpf"))]
            {
                return None;
            }
        };

        Some(SharedBatchStrings {
            updated_date_time: Arc::from(format_datetime(batch.metadata.updated_time)),
            wallclock_slot_start_date_time: Arc::from(format_datetime(slot_start)),
            meta_client_name: Arc::clone(&batch.metadata.client_name),
            meta_network_name: Arc::clone(&batch.metadata.network_name),
        })
    }

    /// Converts a latency metric to JSON.
    fn latency_to_json(m: &LatencyMetric, shared: &SharedBatchStrings) -> AggregatedMetricJson {
        AggregatedMetricJson {
            metric_type: m.metric_type,
            updated_date_time: Arc::clone(&shared.updated_date_time),
            window_start: Arc::from(format_datetime(m.window.start)),
            interval_ms: m.window.interval_ms,
            wallclock_slot: m.slot.number,
            wallclock_slot_start_date_time: Arc::clone(&shared.wallclock_slot_start_date_time),
            pid: m.pid,
            client_type: m.client_type.as_str(),
            sum: m.sum,
            count: m.count,
            min: Some(m.min),
            max: Some(m.max),
            histogram: histogram_to_json(&m.histogram),
            port_label: "",
            direction: None,
            device_id: m.device_id.unwrap_or(0),
            rw: m.rw,
            total_on_cpu_ns: None,
            event_count: None,
            active_cores: None,
            system_cores: None,
            max_core_on_cpu_ns: None,
            max_core_id: None,
            mean_core_pct: None,
            min_core_pct: None,
            max_core_pct: None,
            vm_size_bytes: None,
            vm_rss_bytes: None,
            rss_anon_bytes: None,
            rss_file_bytes: None,
            rss_shmem_bytes: None,
            vm_swap_bytes: None,
            meta_client_name: Arc::clone(&shared.meta_client_name),
            meta_network_name: Arc::clone(&shared.meta_network_name),
        }
    }

    /// Converts a counter metric to JSON.
    fn counter_to_json(m: &CounterMetric, shared: &SharedBatchStrings) -> AggregatedMetricJson {
        AggregatedMetricJson {
            metric_type: m.metric_type,
            updated_date_time: Arc::clone(&shared.updated_date_time),
            window_start: Arc::from(format_datetime(m.window.start)),
            interval_ms: m.window.interval_ms,
            wallclock_slot: m.slot.number,
            wallclock_slot_start_date_time: Arc::clone(&shared.wallclock_slot_start_date_time),
            pid: m.pid,
            client_type: m.client_type.as_str(),
            sum: m.sum,
            count: m.count,
            min: None,
            max: None,
            histogram: None,
            port_label: m.port_label.unwrap_or(""),
            direction: m.direction,
            device_id: m.device_id.unwrap_or(0),
            rw: m.rw,
            total_on_cpu_ns: None,
            event_count: None,
            active_cores: None,
            system_cores: None,
            max_core_on_cpu_ns: None,
            max_core_id: None,
            mean_core_pct: None,
            min_core_pct: None,
            max_core_pct: None,
            vm_size_bytes: None,
            vm_rss_bytes: None,
            rss_anon_bytes: None,
            rss_file_bytes: None,
            rss_shmem_bytes: None,
            vm_swap_bytes: None,
            meta_client_name: Arc::clone(&shared.meta_client_name),
            meta_network_name: Arc::clone(&shared.meta_network_name),
        }
    }

    /// Converts a gauge metric to JSON.
    fn gauge_to_json(m: &GaugeMetric, shared: &SharedBatchStrings) -> AggregatedMetricJson {
        AggregatedMetricJson {
            metric_type: m.metric_type,
            updated_date_time: Arc::clone(&shared.updated_date_time),
            window_start: Arc::from(format_datetime(m.window.start)),
            interval_ms: m.window.interval_ms,
            wallclock_slot: m.slot.number,
            wallclock_slot_start_date_time: Arc::clone(&shared.wallclock_slot_start_date_time),
            pid: m.pid,
            client_type: m.client_type.as_str(),
            sum: m.sum,
            count: m.count,
            min: Some(m.min),
            max: Some(m.max),
            histogram: None,
            port_label: m.port_label.unwrap_or(""),
            direction: None,
            device_id: m.device_id.unwrap_or(0),
            rw: m.rw,
            total_on_cpu_ns: None,
            event_count: None,
            active_cores: None,
            system_cores: None,
            max_core_on_cpu_ns: None,
            max_core_id: None,
            mean_core_pct: None,
            min_core_pct: None,
            max_core_pct: None,
            vm_size_bytes: None,
            vm_rss_bytes: None,
            rss_anon_bytes: None,
            rss_file_bytes: None,
            rss_shmem_bytes: None,
            vm_swap_bytes: None,
            meta_client_name: Arc::clone(&shared.meta_client_name),
            meta_network_name: Arc::clone(&shared.meta_network_name),
        }
    }

    /// Converts a CPU utilization metric to JSON.
    fn cpu_util_to_json(m: &CpuUtilMetric, shared: &SharedBatchStrings) -> AggregatedMetricJson {
        AggregatedMetricJson {
            metric_type: m.metric_type,
            updated_date_time: Arc::clone(&shared.updated_date_time),
            window_start: Arc::from(format_datetime(m.window.start)),
            interval_ms: m.window.interval_ms,
            wallclock_slot: m.slot.number,
            wallclock_slot_start_date_time: Arc::clone(&shared.wallclock_slot_start_date_time),
            pid: m.pid,
            client_type: m.client_type.as_str(),
            sum: m.total_on_cpu_ns,
            count: m.event_count,
            min: None,
            max: None,
            histogram: None,
            port_label: "",
            direction: None,
            device_id: 0,
            rw: None,
            total_on_cpu_ns: Some(m.total_on_cpu_ns),
            event_count: Some(m.event_count),
            active_cores: Some(m.active_cores),
            system_cores: Some(m.system_cores),
            max_core_on_cpu_ns: Some(m.max_core_on_cpu_ns),
            max_core_id: Some(m.max_core_id),
            mean_core_pct: Some(m.mean_core_pct),
            min_core_pct: Some(m.min_core_pct),
            max_core_pct: Some(m.max_core_pct),
            vm_size_bytes: None,
            vm_rss_bytes: None,
            rss_anon_bytes: None,
            rss_file_bytes: None,
            rss_shmem_bytes: None,
            vm_swap_bytes: None,
            meta_client_name: Arc::clone(&shared.meta_client_name),
            meta_network_name: Arc::clone(&shared.meta_network_name),
        }
    }

    /// Converts a process memory usage metric to JSON.
    #[cfg(feature = "bpf")]
    fn memory_usage_to_json(
        m: &MemoryUsageMetric,
        shared: &SharedBatchStrings,
    ) -> AggregatedMetricJson {
        AggregatedMetricJson {
            metric_type: m.metric_type,
            updated_date_time: Arc::clone(&shared.updated_date_time),
            window_start: Arc::from(format_datetime(m.window.start)),
            interval_ms: m.window.interval_ms,
            wallclock_slot: m.slot.number,
            wallclock_slot_start_date_time: Arc::clone(&shared.wallclock_slot_start_date_time),
            pid: m.pid,
            client_type: m.client_type.as_str(),
            sum: m.vm_rss_bytes as i64,
            count: 1,
            min: None,
            max: None,
            histogram: None,
            port_label: "",
            direction: None,
            device_id: 0,
            rw: None,
            total_on_cpu_ns: None,
            event_count: None,
            active_cores: None,
            system_cores: None,
            max_core_on_cpu_ns: None,
            max_core_id: None,
            mean_core_pct: None,
            min_core_pct: None,
            max_core_pct: None,
            vm_size_bytes: Some(m.vm_size_bytes),
            vm_rss_bytes: Some(m.vm_rss_bytes),
            rss_anon_bytes: Some(m.rss_anon_bytes),
            rss_file_bytes: Some(m.rss_file_bytes),
            rss_shmem_bytes: Some(m.rss_shmem_bytes),
            vm_swap_bytes: Some(m.vm_swap_bytes),
            meta_client_name: Arc::clone(&shared.meta_client_name),
            meta_network_name: Arc::clone(&shared.meta_network_name),
        }
    }

    #[inline]
    fn memory_usage_len(_batch: &MetricBatch) -> usize {
        #[cfg(feature = "bpf")]
        {
            _batch.memory_usage.len()
        }
        #[cfg(not(feature = "bpf"))]
        {
            0
        }
    }
}

// --- Exporter interface (called by Exporter enum dispatch) ---

impl HttpExporter {
    /// Returns the exporter name for logging.
    pub fn name(&self) -> &str {
        "http"
    }

    /// Start the HTTP exporter background accumulator task.
    pub async fn start(&mut self, ctx: tokio_util::sync::CancellationToken) -> Result<()> {
        if self.cfg.max_queue_size == 0 {
            bail!("http max_queue_size must be positive");
        }
        if self.cfg.workers == 0 {
            bail!("http workers must be positive");
        }

        let (tx, mut rx) = mpsc::channel::<AggregatedMetricJson>(self.cfg.max_queue_size);
        self.tx = Some(tx);
        self.cancel = Some(ctx.clone());

        let cfg = Arc::new(self.cfg.clone());

        // Build reqwest client.
        let mut client_builder = reqwest::Client::builder().timeout(cfg.export_timeout);

        if !cfg.keep_alive {
            client_builder = client_builder.pool_max_idle_per_host(0);
        }

        let client = client_builder.build().context("building HTTP client")?;

        let semaphore = Arc::new(Semaphore::new(cfg.workers));

        // Spawn accumulator task that batches items and dispatches to workers.
        tokio::spawn(async move {
            let batch_size = cfg.batch_size;
            let batch_timeout = cfg.batch_timeout;
            let mut batch = Vec::with_capacity(batch_size);
            let mut in_flight = tokio::task::JoinSet::new();
            let mut interval = tokio::time::interval(batch_timeout);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                tokio::select! {
                    _ = ctx.cancelled() => {
                        // Flush remaining items.
                        if !batch.is_empty() {
                            let items = std::mem::take(&mut batch);
                            spawn_send_batch(
                                &mut in_flight,
                                client.clone(),
                                Arc::clone(&cfg),
                                Arc::clone(&semaphore),
                                items,
                            );
                        }

                        // Drain queue and flush remaining items.
                        while let Ok(item) = rx.try_recv() {
                            batch.push(item);
                            if batch.len() >= batch_size {
                                let items = std::mem::replace(
                                    &mut batch,
                                    Vec::with_capacity(batch_size),
                                );
                                spawn_send_batch(
                                    &mut in_flight,
                                    client.clone(),
                                    Arc::clone(&cfg),
                                    Arc::clone(&semaphore),
                                    items,
                                );
                            }
                        }

                        if !batch.is_empty() {
                            let items = std::mem::take(&mut batch);
                            spawn_send_batch(
                                &mut in_flight,
                                client.clone(),
                                Arc::clone(&cfg),
                                Arc::clone(&semaphore),
                                items,
                            );
                        }

                        while let Some(joined) = in_flight.join_next().await {
                            if let Err(e) = joined {
                                tracing::debug!(error = %e, "HTTP export worker join failed");
                            }
                        }
                        return;
                    }

                    item = rx.recv() => {
                        match item {
                            Some(item) => {
                                batch.push(item);

                                // Drain more items without blocking.
                                while batch.len() < batch_size {
                                    match rx.try_recv() {
                                        Ok(item) => batch.push(item),
                                        Err(_) => break,
                                    }
                                }

                                if batch.len() >= batch_size {
                                    let items = std::mem::replace(
                                        &mut batch,
                                        Vec::with_capacity(batch_size),
                                    );
                                    spawn_send_batch(
                                        &mut in_flight,
                                        client.clone(),
                                        Arc::clone(&cfg),
                                        Arc::clone(&semaphore),
                                        items,
                                    );
                                }
                            }
                            None => {
                                if !batch.is_empty() {
                                    let items = std::mem::take(&mut batch);
                                    spawn_send_batch(
                                        &mut in_flight,
                                        client.clone(),
                                        Arc::clone(&cfg),
                                        Arc::clone(&semaphore),
                                        items,
                                    );
                                }

                                while let Some(joined) = in_flight.join_next().await {
                                    if let Err(e) = joined {
                                        tracing::debug!(error = %e, "HTTP export worker join failed");
                                    }
                                }
                                return;
                            }
                        }
                    }

                    _ = interval.tick() => {
                        if !batch.is_empty() {
                            let items = std::mem::replace(
                                &mut batch,
                                Vec::with_capacity(batch_size),
                            );
                            spawn_send_batch(
                                &mut in_flight,
                                client.clone(),
                                Arc::clone(&cfg),
                                Arc::clone(&semaphore),
                                items,
                            );
                        }
                    }

                    joined = in_flight.join_next(), if !in_flight.is_empty() => {
                        if let Some(Err(e)) = joined {
                            tracing::debug!(error = %e, "HTTP export worker join failed");
                        }
                    }
                }
            }
        });

        tracing::info!(
            address = %self.cfg.address,
            compression = %self.cfg.compression,
            workers = self.cfg.workers,
            "HTTP exporter started",
        );

        Ok(())
    }

    /// Export a batch of metrics by enqueuing JSON items.
    pub async fn export(&self, batch: &MetricBatch) -> Result<()> {
        let tx = match &self.tx {
            Some(tx) => tx,
            None => return Ok(()),
        };

        let Some(shared) = Self::shared_strings(batch) else {
            return Ok(());
        };

        let mut dropped = 0usize;
        let memory_usage_len = Self::memory_usage_len(batch);

        // Convert all metrics to JSON items and enqueue.
        for (i, m) in batch.latency.iter().enumerate() {
            if tx.capacity() == 0 {
                dropped += batch.latency.len() - i
                    + batch.counter.len()
                    + batch.gauge.len()
                    + batch.cpu_util.len()
                    + memory_usage_len;
                break;
            }

            let json = Self::latency_to_json(m, &shared);
            if tx.try_send(json).is_err() {
                dropped += batch.latency.len() - i
                    + batch.counter.len()
                    + batch.gauge.len()
                    + batch.cpu_util.len()
                    + memory_usage_len;
                break;
            }
        }

        if dropped == 0 {
            for (i, m) in batch.counter.iter().enumerate() {
                if tx.capacity() == 0 {
                    dropped += batch.counter.len() - i
                        + batch.gauge.len()
                        + batch.cpu_util.len()
                        + memory_usage_len;
                    break;
                }

                let json = Self::counter_to_json(m, &shared);
                if tx.try_send(json).is_err() {
                    dropped += batch.counter.len() - i
                        + batch.gauge.len()
                        + batch.cpu_util.len()
                        + memory_usage_len;
                    break;
                }
            }
        }

        if dropped == 0 {
            for (i, m) in batch.gauge.iter().enumerate() {
                if tx.capacity() == 0 {
                    dropped += batch.gauge.len() - i + batch.cpu_util.len() + memory_usage_len;
                    break;
                }

                let json = Self::gauge_to_json(m, &shared);
                if tx.try_send(json).is_err() {
                    dropped += batch.gauge.len() - i + batch.cpu_util.len() + memory_usage_len;
                    break;
                }
            }
        }

        if dropped == 0 {
            for (i, m) in batch.cpu_util.iter().enumerate() {
                if tx.capacity() == 0 {
                    dropped += batch.cpu_util.len() - i + memory_usage_len;
                    break;
                }

                let json = Self::cpu_util_to_json(m, &shared);
                if tx.try_send(json).is_err() {
                    dropped += batch.cpu_util.len() - i + memory_usage_len;
                    break;
                }
            }
        }

        #[cfg(feature = "bpf")]
        if dropped == 0 {
            for (i, m) in batch.memory_usage.iter().enumerate() {
                if tx.capacity() == 0 {
                    dropped += batch.memory_usage.len() - i;
                    break;
                }

                let json = Self::memory_usage_to_json(m, &shared);
                if tx.try_send(json).is_err() {
                    dropped += batch.memory_usage.len() - i;
                    break;
                }
            }
        }

        if dropped > 0 {
            tracing::warn!(dropped, "HTTP export queue full, dropping items");
        }

        Ok(())
    }

    /// Stop the HTTP exporter, draining remaining items.
    pub async fn stop(&mut self) -> Result<()> {
        // Drop the sender to signal the accumulator to stop.
        self.tx.take();

        if let Some(cancel) = self.cancel.take() {
            cancel.cancel();
        }

        Ok(())
    }
}

fn spawn_send_batch(
    in_flight: &mut tokio::task::JoinSet<()>,
    client: reqwest::Client,
    cfg: Arc<HttpExportConfig>,
    semaphore: Arc<Semaphore>,
    items: Vec<AggregatedMetricJson>,
) {
    if items.is_empty() {
        return;
    }

    in_flight.spawn(async move {
        let permit = match semaphore.acquire_owned().await {
            Ok(permit) => permit,
            Err(e) => {
                tracing::warn!(error = %e, "HTTP exporter semaphore closed");
                return;
            }
        };

        let _permit = permit;

        if let Err(e) = send_batch(&client, &cfg, items).await {
            tracing::warn!(error = %e, "HTTP export request failed");
        }
    });
}

/// Sends one batch of items via HTTP.
async fn send_batch(
    client: &reqwest::Client,
    cfg: &HttpExportConfig,
    items: Vec<AggregatedMetricJson>,
) -> Result<()> {
    if items.is_empty() {
        return Ok(());
    }

    // Serialize to NDJSON.
    let mut buf = Vec::with_capacity(items.len() * 256);
    for item in &items {
        serde_json::to_writer(&mut buf, item).context("serializing metric to JSON")?;
        buf.push(b'\n');
    }

    let raw_len = buf.len();

    // Compress.
    let compressed = compress(&buf, &cfg.compression).context("compressing NDJSON data")?;

    // Build request.
    let mut request = client
        .post(&cfg.address)
        .header("Content-Type", "application/x-ndjson")
        .body(compressed);

    if let Some(encoding) = content_encoding(&cfg.compression) {
        request = request.header("Content-Encoding", encoding);
    }

    // Add custom headers.
    for (k, v) in &cfg.headers {
        request = request.header(k.as_str(), v.as_str());
    }

    // Send.
    let resp = request
        .send()
        .await
        .context("sending HTTP export request")?;

    let status = resp.status();
    // Drain body for connection reuse.
    let _ = resp.bytes().await;

    if !status.is_success() {
        anyhow::bail!("HTTP export unexpected status: {status}");
    }

    tracing::debug!(
        items = items.len(),
        bytes = raw_len,
        "exported batch via HTTP",
    );

    Ok(())
}

// --- Compression ---

/// Compresses data using the specified algorithm.
fn compress(data: &[u8], algorithm: &str) -> Result<Vec<u8>> {
    match algorithm {
        "none" | "" => Ok(data.to_vec()),
        "gzip" => compress_gzip(data),
        "zstd" => compress_zstd(data),
        "zlib" => compress_zlib(data),
        "snappy" => compress_snappy(data),
        other => anyhow::bail!("unsupported compression: {other}"),
    }
}

/// Returns the Content-Encoding header value for the algorithm.
fn content_encoding(algorithm: &str) -> Option<&'static str> {
    match algorithm {
        "gzip" => Some("gzip"),
        "zstd" => Some("zstd"),
        "zlib" => Some("deflate"),
        "snappy" => Some("snappy"),
        _ => None,
    }
}

fn compress_gzip(data: &[u8]) -> Result<Vec<u8>> {
    use flate2::write::GzEncoder;
    use flate2::Compression;

    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data).context("gzip write")?;
    encoder.finish().context("gzip finish")
}

fn compress_zstd(data: &[u8]) -> Result<Vec<u8>> {
    zstd::encode_all(data, 0).context("zstd encode")
}

fn compress_zlib(data: &[u8]) -> Result<Vec<u8>> {
    use flate2::write::ZlibEncoder;
    use flate2::Compression;

    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data).context("zlib write")?;
    encoder.finish().context("zlib finish")
}

fn compress_snappy(data: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = snap::raw::Encoder::new();
    encoder.compress_vec(data).context("snappy encode")
}

// --- Datetime formatting ---

/// Formats a SystemTime as a datetime string matching Go's "2006-01-02 15:04:05.000".
fn format_datetime(t: std::time::SystemTime) -> String {
    let dt: DateTime<Utc> = t.into();
    dt.format("%Y-%m-%d %H:%M:%S%.3f").to_string()
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use super::*;
    use crate::sink::aggregated::metric::{BatchMetadata, SamplingMode, SlotInfo, WindowInfo};
    use crate::tracer::event::ClientType;

    #[test]
    fn test_compress_none() {
        let data = b"hello world";
        let result = compress(data, "none").expect("compress none");
        assert_eq!(result, data);
    }

    #[test]
    fn test_compress_gzip_roundtrip() {
        let data = b"hello world compressed with gzip";
        let compressed = compress(data, "gzip").expect("gzip compress");
        assert_ne!(compressed, data.as_slice());

        // Decompress and verify.
        use flate2::read::GzDecoder;
        use std::io::Read;
        let mut decoder = GzDecoder::new(compressed.as_slice());
        let mut decompressed = Vec::new();
        decoder
            .read_to_end(&mut decompressed)
            .expect("gzip decompress");
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_compress_zstd_roundtrip() {
        let data = b"hello world compressed with zstd";
        let compressed = compress(data, "zstd").expect("zstd compress");
        let decompressed = zstd::decode_all(compressed.as_slice()).expect("zstd decompress");
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_compress_zlib_roundtrip() {
        let data = b"hello world compressed with zlib";
        let compressed = compress(data, "zlib").expect("zlib compress");

        use flate2::read::ZlibDecoder;
        use std::io::Read;
        let mut decoder = ZlibDecoder::new(compressed.as_slice());
        let mut decompressed = Vec::new();
        decoder
            .read_to_end(&mut decompressed)
            .expect("zlib decompress");
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_compress_snappy_roundtrip() {
        let data = b"hello world compressed with snappy";
        let compressed = compress(data, "snappy").expect("snappy compress");
        let mut decoder = snap::raw::Decoder::new();
        let decompressed = decoder
            .decompress_vec(&compressed)
            .expect("snappy decompress");
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_content_encoding() {
        assert_eq!(content_encoding("gzip"), Some("gzip"));
        assert_eq!(content_encoding("zstd"), Some("zstd"));
        assert_eq!(content_encoding("zlib"), Some("deflate"));
        assert_eq!(content_encoding("snappy"), Some("snappy"));
        assert_eq!(content_encoding("none"), None);
        assert_eq!(content_encoding(""), None);
    }

    #[test]
    fn test_histogram_to_json() {
        let h = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let json = histogram_to_json(&h).expect("valid histogram");
        assert_eq!(json.le_1us, 1);
        assert_eq!(json.le_10us, 2);
        assert_eq!(json.inf, 10);
    }

    #[test]
    fn test_histogram_to_json_wrong_size() {
        let h = vec![1, 2, 3];
        assert!(histogram_to_json(&h).is_none());
    }

    #[test]
    fn test_format_datetime() {
        let t = std::time::SystemTime::UNIX_EPOCH;
        assert_eq!(format_datetime(t), "1970-01-01 00:00:00.000");
    }

    #[test]
    fn test_aggregated_metric_json_serialization() {
        let metric = AggregatedMetricJson {
            metric_type: "syscall_read",
            updated_date_time: Arc::from("2024-01-01 00:00:00.000"),
            window_start: Arc::from("2024-01-01 00:00:00.000"),
            interval_ms: 1000,
            wallclock_slot: 42,
            wallclock_slot_start_date_time: Arc::from("2024-01-01 00:00:00.000"),
            pid: 123,
            client_type: "geth",
            sum: 100,
            count: 10,
            min: Some(5),
            max: Some(20),
            histogram: Some(HistogramJson {
                le_1us: 1,
                le_10us: 2,
                le_100us: 3,
                le_1ms: 4,
                le_10ms: 0,
                le_100ms: 0,
                le_1s: 0,
                le_10s: 0,
                le_100s: 0,
                inf: 0,
            }),
            port_label: "",
            direction: None,
            device_id: 0,
            rw: None,
            total_on_cpu_ns: None,
            event_count: None,
            active_cores: None,
            system_cores: None,
            max_core_on_cpu_ns: None,
            max_core_id: None,
            mean_core_pct: None,
            min_core_pct: None,
            max_core_pct: None,
            vm_size_bytes: None,
            vm_rss_bytes: None,
            rss_anon_bytes: None,
            rss_file_bytes: None,
            rss_shmem_bytes: None,
            vm_swap_bytes: None,
            meta_client_name: Arc::from("test-node"),
            meta_network_name: Arc::from("mainnet"),
        };

        let json_str = serde_json::to_string(&metric).expect("serialize");
        assert!(json_str.contains("syscall_read"));
        assert!(json_str.contains("geth"));
        // Empty-value optional fields should be skipped.
        assert!(!json_str.contains("port_label"));
        assert!(!json_str.contains("direction"));
        assert!(!json_str.contains("device_id"));
    }

    #[test]
    fn test_window_start_is_serialized_per_metric() {
        let slot_start = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(12);

        let batch = MetricBatch {
            metadata: BatchMetadata {
                client_name: Arc::from("node-a"),
                network_name: Arc::from("mainnet"),
                updated_time: SystemTime::UNIX_EPOCH,
            },
            latency: vec![LatencyMetric {
                metric_type: "syscall_read",
                window: WindowInfo {
                    start: SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1),
                    interval_ms: 100,
                },
                slot: SlotInfo {
                    number: 1,
                    start_time: slot_start,
                },
                pid: 1,
                client_type: ClientType::Geth,
                device_id: None,
                rw: None,
                sampling_mode: SamplingMode::None,
                sampling_rate: 1.0,
                sum: 10,
                count: 1,
                min: 10,
                max: 10,
                histogram: [0; NUM_BUCKETS],
            }],
            counter: vec![CounterMetric {
                metric_type: "net_io",
                window: WindowInfo {
                    start: SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(2),
                    interval_ms: 100,
                },
                slot: SlotInfo {
                    number: 1,
                    start_time: slot_start,
                },
                pid: 1,
                client_type: ClientType::Geth,
                device_id: None,
                rw: None,
                port_label: Some("el_p2p_tcp"),
                direction: Some("tx"),
                sampling_mode: SamplingMode::None,
                sampling_rate: 1.0,
                sum: 1024,
                count: 1,
            }],
            gauge: vec![],
            cpu_util: vec![],
            #[cfg(feature = "bpf")]
            memory_usage: vec![],
        };

        let shared = HttpExporter::shared_strings(&batch).expect("batch should not be empty");
        let latency_json = HttpExporter::latency_to_json(&batch.latency[0], &shared);
        let counter_json = HttpExporter::counter_to_json(&batch.counter[0], &shared);

        assert_eq!(&*latency_json.window_start, "1970-01-01 00:00:01.000");
        assert_eq!(&*counter_json.window_start, "1970-01-01 00:00:02.000");
        assert_ne!(latency_json.window_start, counter_json.window_start);
    }
}
