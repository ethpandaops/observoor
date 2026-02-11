use std::sync::Arc;
use std::time::SystemTime;

use crate::tracer::event::ClientType;

/// Sampling mode describing how a metric stream was reduced before aggregation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SamplingMode {
    /// No sampling was applied; all events were retained.
    None,
    /// Probabilistic sampling retained events at `sampling_rate`.
    Probability,
    /// Every Nth event was retained (`sampling_rate` is 1/N).
    Nth,
}

impl SamplingMode {
    /// Returns the canonical string representation for storage/export.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Probability => "probability",
            Self::Nth => "nth",
        }
    }
}

/// Metadata common to all metric batches.
#[derive(Debug, Clone)]
pub struct BatchMetadata {
    /// Observoor instance name.
    pub client_name: Arc<str>,
    /// Ethereum network name.
    pub network_name: Arc<str>,
    /// Time when this batch was collected.
    pub updated_time: SystemTime,
}

/// Time window information for an aggregation period.
#[derive(Debug, Clone, Copy)]
pub struct WindowInfo {
    /// Start of the aggregation window.
    pub start: SystemTime,
    /// Window duration in milliseconds.
    pub interval_ms: u16,
}

/// Ethereum slot information.
#[derive(Debug, Clone, Copy)]
pub struct SlotInfo {
    /// Slot number.
    pub number: u32,
    /// Slot start time.
    pub start_time: SystemTime,
}

/// A latency metric with histogram data.
#[derive(Debug, Clone)]
pub struct LatencyMetric {
    /// Table name (e.g., "syscall_read", "disk_latency").
    pub metric_type: &'static str,
    pub window: WindowInfo,
    pub slot: SlotInfo,
    pub pid: u32,
    pub client_type: ClientType,
    /// Block device ID (disk metrics only).
    pub device_id: Option<u32>,
    /// Read/write direction string (disk metrics only).
    pub rw: Option<&'static str>,
    pub sampling_mode: SamplingMode,
    pub sampling_rate: f32,
    pub sum: i64,
    pub count: u32,
    pub min: i64,
    pub max: i64,
    /// 10-bucket histogram counts.
    pub histogram: [u32; 10],
}

/// A counter metric (events, bytes, etc.).
#[derive(Debug, Clone)]
pub struct CounterMetric {
    /// Table name (e.g., "page_fault_major", "net_io").
    pub metric_type: &'static str,
    pub window: WindowInfo,
    pub slot: SlotInfo,
    pub pid: u32,
    pub client_type: ClientType,
    /// Block device ID (disk metrics only).
    pub device_id: Option<u32>,
    /// Read/write direction string (disk metrics only).
    pub rw: Option<&'static str>,
    /// Port label string (network metrics only).
    pub port_label: Option<&'static str>,
    /// Direction string "tx"/"rx" (network metrics only).
    pub direction: Option<&'static str>,
    pub sampling_mode: SamplingMode,
    pub sampling_rate: f32,
    pub sum: i64,
    pub count: u32,
}

/// A gauge metric with min/max (TCP RTT, CWND, queue depth).
#[derive(Debug, Clone)]
pub struct GaugeMetric {
    /// Table name (e.g., "tcp_rtt", "disk_queue_depth").
    pub metric_type: &'static str,
    pub window: WindowInfo,
    pub slot: SlotInfo,
    pub pid: u32,
    pub client_type: ClientType,
    /// Block device ID (disk metrics only).
    pub device_id: Option<u32>,
    /// Read/write direction string (disk metrics only).
    pub rw: Option<&'static str>,
    /// Port label string (TCP metrics only).
    pub port_label: Option<&'static str>,
    pub sampling_mode: SamplingMode,
    pub sampling_rate: f32,
    pub sum: i64,
    pub count: u32,
    pub min: i64,
    pub max: i64,
}

/// CPU utilization summary metric (per process, per window).
#[derive(Debug, Clone)]
pub struct CpuUtilMetric {
    pub metric_type: &'static str,
    pub window: WindowInfo,
    pub slot: SlotInfo,
    pub pid: u32,
    pub client_type: ClientType,
    pub sampling_mode: SamplingMode,
    pub sampling_rate: f32,
    pub total_on_cpu_ns: i64,
    pub event_count: u32,
    pub active_cores: u16,
    pub system_cores: u16,
    pub max_core_on_cpu_ns: i64,
    pub max_core_id: u32,
    pub mean_core_pct: f32,
    pub min_core_pct: f32,
    pub max_core_pct: f32,
}

/// Process memory usage snapshot metric (per process, per window).
#[cfg(feature = "bpf")]
#[derive(Debug, Clone)]
pub struct MemoryUsageMetric {
    pub metric_type: &'static str,
    pub window: WindowInfo,
    pub slot: SlotInfo,
    pub pid: u32,
    pub client_type: ClientType,
    pub sampling_mode: SamplingMode,
    pub sampling_rate: f32,
    pub vm_size_bytes: u64,
    pub vm_rss_bytes: u64,
    pub rss_anon_bytes: u64,
    pub rss_file_bytes: u64,
    pub rss_shmem_bytes: u64,
    pub vm_swap_bytes: u64,
}

/// A batch of collected metrics ready for export.
#[derive(Debug, Clone)]
pub struct MetricBatch {
    pub metadata: BatchMetadata,
    pub latency: Vec<LatencyMetric>,
    pub counter: Vec<CounterMetric>,
    pub gauge: Vec<GaugeMetric>,
    pub cpu_util: Vec<CpuUtilMetric>,
    #[cfg(feature = "bpf")]
    pub memory_usage: Vec<MemoryUsageMetric>,
}

impl MetricBatch {
    /// Total number of metrics in this batch.
    pub fn len(&self) -> usize {
        #[cfg(not(feature = "bpf"))]
        let total =
            self.latency.len() + self.counter.len() + self.gauge.len() + self.cpu_util.len();
        #[cfg(feature = "bpf")]
        let mut total =
            self.latency.len() + self.counter.len() + self.gauge.len() + self.cpu_util.len();
        #[cfg(feature = "bpf")]
        {
            total += self.memory_usage.len();
        }
        total
    }

    /// Whether the batch contains no metrics.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
