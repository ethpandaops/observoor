use std::io::Write;
use std::sync::Arc;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::Serialize;
use tokio::sync::{mpsc, Semaphore};

use crate::config::HttpExportConfig;

use super::metric::{BatchMetadata, CounterMetric, GaugeMetric, LatencyMetric, MetricBatch};

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
    pub metric_type: String,
    pub updated_date_time: String,
    pub window_start: String,
    pub interval_ms: u16,
    pub wallclock_slot: u32,
    pub wallclock_slot_start_date_time: String,
    pub pid: u32,
    pub client_type: String,
    pub sum: i64,
    pub count: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub histogram: Option<HistogramJson>,
    #[serde(skip_serializing_if = "is_zero_u16")]
    pub local_port: u16,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub direction: String,
    #[serde(skip_serializing_if = "is_zero_u32")]
    pub device_id: u32,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub rw: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub meta_client_name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub meta_network_name: String,
}

fn is_zero_u16(v: &u16) -> bool {
    *v == 0
}

fn is_zero_u32(v: &u32) -> bool {
    *v == 0
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

    /// Converts a latency metric to JSON.
    fn latency_to_json(m: &LatencyMetric, meta: &BatchMetadata) -> AggregatedMetricJson {
        AggregatedMetricJson {
            metric_type: m.metric_type.clone(),
            updated_date_time: format_datetime(meta.updated_time),
            window_start: format_datetime(m.window.start),
            interval_ms: m.window.interval_ms,
            wallclock_slot: m.slot.number,
            wallclock_slot_start_date_time: format_datetime(m.slot.start_time),
            pid: m.pid,
            client_type: m.client_type.to_string(),
            sum: m.sum,
            count: m.count,
            min: Some(m.min),
            max: Some(m.max),
            histogram: histogram_to_json(&m.histogram),
            local_port: 0,
            direction: String::new(),
            device_id: m.device_id.unwrap_or(0),
            rw: m.rw.clone().unwrap_or_default(),
            meta_client_name: meta.client_name.clone(),
            meta_network_name: meta.network_name.clone(),
        }
    }

    /// Converts a counter metric to JSON.
    fn counter_to_json(m: &CounterMetric, meta: &BatchMetadata) -> AggregatedMetricJson {
        AggregatedMetricJson {
            metric_type: m.metric_type.clone(),
            updated_date_time: format_datetime(meta.updated_time),
            window_start: format_datetime(m.window.start),
            interval_ms: m.window.interval_ms,
            wallclock_slot: m.slot.number,
            wallclock_slot_start_date_time: format_datetime(m.slot.start_time),
            pid: m.pid,
            client_type: m.client_type.to_string(),
            sum: m.sum,
            count: m.count,
            min: None,
            max: None,
            histogram: None,
            local_port: m.local_port.unwrap_or(0),
            direction: m.direction.clone().unwrap_or_default(),
            device_id: m.device_id.unwrap_or(0),
            rw: m.rw.clone().unwrap_or_default(),
            meta_client_name: meta.client_name.clone(),
            meta_network_name: meta.network_name.clone(),
        }
    }

    /// Converts a gauge metric to JSON.
    fn gauge_to_json(m: &GaugeMetric, meta: &BatchMetadata) -> AggregatedMetricJson {
        AggregatedMetricJson {
            metric_type: m.metric_type.clone(),
            updated_date_time: format_datetime(meta.updated_time),
            window_start: format_datetime(m.window.start),
            interval_ms: m.window.interval_ms,
            wallclock_slot: m.slot.number,
            wallclock_slot_start_date_time: format_datetime(m.slot.start_time),
            pid: m.pid,
            client_type: m.client_type.to_string(),
            sum: m.sum,
            count: m.count,
            min: Some(m.min),
            max: Some(m.max),
            histogram: None,
            local_port: m.local_port.unwrap_or(0),
            direction: String::new(),
            device_id: m.device_id.unwrap_or(0),
            rw: m.rw.clone().unwrap_or_default(),
            meta_client_name: meta.client_name.clone(),
            meta_network_name: meta.network_name.clone(),
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
        let (tx, mut rx) = mpsc::channel::<AggregatedMetricJson>(self.cfg.max_queue_size);
        self.tx = Some(tx);
        self.cancel = Some(ctx.clone());

        let cfg = self.cfg.clone();

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
            let mut interval = tokio::time::interval(batch_timeout);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                tokio::select! {
                    _ = ctx.cancelled() => {
                        // Flush remaining items.
                        if !batch.is_empty() {
                            let items = std::mem::take(&mut batch);
                            let _ = send_batch(
                                &client, &cfg, &semaphore, items,
                            ).await;
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
                                    let _ = send_batch(
                                        &client, &cfg, &semaphore, items,
                                    ).await;
                                }
                            }
                            None => return, // Channel closed.
                        }
                    }

                    _ = interval.tick() => {
                        if !batch.is_empty() {
                            let items = std::mem::replace(
                                &mut batch,
                                Vec::with_capacity(batch_size),
                            );
                            let _ = send_batch(
                                &client, &cfg, &semaphore, items,
                            ).await;
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

        // Convert all metrics to JSON items and enqueue.
        for m in &batch.latency {
            let json = Self::latency_to_json(m, &batch.metadata);
            // Non-blocking send; drops if queue full.
            if tx.try_send(json).is_err() {
                tracing::warn!("HTTP export queue full, dropping item");
            }
        }

        for m in &batch.counter {
            let json = Self::counter_to_json(m, &batch.metadata);
            if tx.try_send(json).is_err() {
                tracing::warn!("HTTP export queue full, dropping item");
            }
        }

        for m in &batch.gauge {
            let json = Self::gauge_to_json(m, &batch.metadata);
            if tx.try_send(json).is_err() {
                tracing::warn!("HTTP export queue full, dropping item");
            }
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

/// Sends a batch of items via HTTP with semaphore-limited concurrency.
async fn send_batch(
    client: &reqwest::Client,
    cfg: &HttpExportConfig,
    semaphore: &Arc<Semaphore>,
    items: Vec<AggregatedMetricJson>,
) -> Result<()> {
    if items.is_empty() {
        return Ok(());
    }

    // Acquire a worker slot.
    let _permit = semaphore
        .acquire()
        .await
        .context("acquiring semaphore permit")?;

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
    use super::*;

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
            metric_type: "syscall_read".to_string(),
            updated_date_time: "2024-01-01 00:00:00.000".to_string(),
            window_start: "2024-01-01 00:00:00.000".to_string(),
            interval_ms: 1000,
            wallclock_slot: 42,
            wallclock_slot_start_date_time: "2024-01-01 00:00:00.000".to_string(),
            pid: 123,
            client_type: "geth".to_string(),
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
            local_port: 0,
            direction: String::new(),
            device_id: 0,
            rw: String::new(),
            meta_client_name: "test-node".to_string(),
            meta_network_name: "mainnet".to_string(),
        };

        let json_str = serde_json::to_string(&metric).expect("serialize");
        assert!(json_str.contains("syscall_read"));
        assert!(json_str.contains("geth"));
        // Zero-value optional fields should be skipped.
        assert!(!json_str.contains("local_port"));
        assert!(!json_str.contains("direction"));
        assert!(!json_str.contains("device_id"));
    }
}
