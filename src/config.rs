use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::Path;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::Deserialize;

use crate::sink::aggregated::collector::ALL_METRIC_NAMES;
use crate::tracer::event::EventType;

/// Identifies a group of BPF programs that are loaded/attached as a unit.
///
/// Each variant maps 1:1 to a BPF attachment unit (enter/exit pair, kprobe/kretprobe
/// pair, or single program). Disabling a probe group prevents the corresponding BPF
/// programs from being loaded — zero kernel overhead.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProbeGroup {
    SyscallRead,
    SyscallWrite,
    SyscallFutex,
    SyscallMmap,
    SyscallEpollWait,
    SyscallFsync,
    SyscallFdatasync,
    SyscallPwrite,
    FdOpen,
    FdClose,
    DiskIo,
    BlockMerge,
    TcpSend,
    TcpRecv,
    UdpSend,
    UdpRecv,
    TcpRetransmit,
    TcpState,
    Scheduler,
    SchedulerWakeup,
    PageFault,
    MemReclaim,
    MemCompaction,
    SwapIn,
    SwapOut,
    OomKill,
    ProcessExit,
}

impl ProbeGroup {
    /// Returns the canonical snake_case config key.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SyscallRead => "syscall_read",
            Self::SyscallWrite => "syscall_write",
            Self::SyscallFutex => "syscall_futex",
            Self::SyscallMmap => "syscall_mmap",
            Self::SyscallEpollWait => "syscall_epoll_wait",
            Self::SyscallFsync => "syscall_fsync",
            Self::SyscallFdatasync => "syscall_fdatasync",
            Self::SyscallPwrite => "syscall_pwrite",
            Self::FdOpen => "fd_open",
            Self::FdClose => "fd_close",
            Self::DiskIo => "disk_io",
            Self::BlockMerge => "block_merge",
            Self::TcpSend => "tcp_send",
            Self::TcpRecv => "tcp_recv",
            Self::UdpSend => "udp_send",
            Self::UdpRecv => "udp_recv",
            Self::TcpRetransmit => "tcp_retransmit",
            Self::TcpState => "tcp_state",
            Self::Scheduler => "scheduler",
            Self::SchedulerWakeup => "scheduler_wakeup",
            Self::PageFault => "page_fault",
            Self::MemReclaim => "mem_reclaim",
            Self::MemCompaction => "mem_compaction",
            Self::SwapIn => "swap_in",
            Self::SwapOut => "swap_out",
            Self::OomKill => "oom_kill",
            Self::ProcessExit => "process_exit",
        }
    }

    /// Parse from a config key string.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "syscall_read" => Some(Self::SyscallRead),
            "syscall_write" => Some(Self::SyscallWrite),
            "syscall_futex" => Some(Self::SyscallFutex),
            "syscall_mmap" => Some(Self::SyscallMmap),
            "syscall_epoll_wait" => Some(Self::SyscallEpollWait),
            "syscall_fsync" => Some(Self::SyscallFsync),
            "syscall_fdatasync" => Some(Self::SyscallFdatasync),
            "syscall_pwrite" => Some(Self::SyscallPwrite),
            "fd_open" => Some(Self::FdOpen),
            "fd_close" => Some(Self::FdClose),
            "disk_io" => Some(Self::DiskIo),
            "block_merge" => Some(Self::BlockMerge),
            "tcp_send" => Some(Self::TcpSend),
            "tcp_recv" => Some(Self::TcpRecv),
            "udp_send" => Some(Self::UdpSend),
            "udp_recv" => Some(Self::UdpRecv),
            "tcp_retransmit" => Some(Self::TcpRetransmit),
            "tcp_state" => Some(Self::TcpState),
            "scheduler" => Some(Self::Scheduler),
            "scheduler_wakeup" => Some(Self::SchedulerWakeup),
            "page_fault" => Some(Self::PageFault),
            "mem_reclaim" => Some(Self::MemReclaim),
            "mem_compaction" => Some(Self::MemCompaction),
            "swap_in" => Some(Self::SwapIn),
            "swap_out" => Some(Self::SwapOut),
            "oom_kill" => Some(Self::OomKill),
            "process_exit" => Some(Self::ProcessExit),
            _ => None,
        }
    }

    /// All probe groups in definition order.
    pub fn all() -> &'static [Self] {
        &[
            Self::SyscallRead,
            Self::SyscallWrite,
            Self::SyscallFutex,
            Self::SyscallMmap,
            Self::SyscallEpollWait,
            Self::SyscallFsync,
            Self::SyscallFdatasync,
            Self::SyscallPwrite,
            Self::FdOpen,
            Self::FdClose,
            Self::DiskIo,
            Self::BlockMerge,
            Self::TcpSend,
            Self::TcpRecv,
            Self::UdpSend,
            Self::UdpRecv,
            Self::TcpRetransmit,
            Self::TcpState,
            Self::Scheduler,
            Self::SchedulerWakeup,
            Self::PageFault,
            Self::MemReclaim,
            Self::MemCompaction,
            Self::SwapIn,
            Self::SwapOut,
            Self::OomKill,
            Self::ProcessExit,
        ]
    }

    /// Event types produced by this probe group.
    pub fn event_types(self) -> &'static [EventType] {
        match self {
            Self::SyscallRead => &[EventType::SyscallRead],
            Self::SyscallWrite => &[EventType::SyscallWrite],
            Self::SyscallFutex => &[EventType::SyscallFutex],
            Self::SyscallMmap => &[EventType::SyscallMmap],
            Self::SyscallEpollWait => &[EventType::SyscallEpollWait],
            Self::SyscallFsync => &[EventType::SyscallFsync],
            Self::SyscallFdatasync => &[EventType::SyscallFdatasync],
            Self::SyscallPwrite => &[EventType::SyscallPwrite],
            Self::FdOpen => &[EventType::FDOpen],
            Self::FdClose => &[EventType::FDClose],
            Self::DiskIo => &[EventType::DiskIO],
            Self::BlockMerge => &[EventType::BlockMerge],
            Self::TcpSend => &[EventType::NetTX],
            Self::TcpRecv => &[EventType::NetRX],
            Self::UdpSend => &[EventType::NetTX],
            Self::UdpRecv => &[EventType::NetRX],
            Self::TcpRetransmit => &[EventType::TcpRetransmit],
            Self::TcpState => &[EventType::TcpState],
            Self::Scheduler => &[EventType::SchedSwitch, EventType::SchedRunqueue],
            Self::SchedulerWakeup => &[], // auxiliary, improves runqueue data
            Self::PageFault => &[EventType::PageFault],
            Self::MemReclaim => &[EventType::MemReclaim],
            Self::MemCompaction => &[EventType::MemCompaction],
            Self::SwapIn => &[EventType::SwapIn],
            Self::SwapOut => &[EventType::SwapOut],
            Self::OomKill => &[EventType::OOMKill],
            Self::ProcessExit => &[EventType::ProcessExit],
        }
    }
}

impl fmt::Display for ProbeGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Per-probe-group configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct ProbeConfig {
    /// Whether this probe group is enabled. Default: true.
    #[serde(default = "default_true")]
    pub enabled: bool,
}

/// Top-level probe group configuration, keyed by probe group name.
#[derive(Debug, Default, Clone, Deserialize)]
pub struct ProbesConfig {
    #[serde(flatten)]
    pub entries: HashMap<String, ProbeConfig>,
}

impl ProbesConfig {
    /// Returns the set of disabled probe groups after validating all keys.
    pub fn disabled_set(&self) -> Result<HashSet<ProbeGroup>> {
        let mut disabled = HashSet::new();
        for (key, cfg) in &self.entries {
            let group = ProbeGroup::from_name(key)
                .ok_or_else(|| anyhow::anyhow!("unknown probe group in config: {key}"))?;
            if !cfg.enabled {
                disabled.insert(group);
            }
        }
        Ok(disabled)
    }
}

/// Top-level configuration for the observoor agent.
#[derive(Debug, Deserialize)]
pub struct Config {
    /// Logging verbosity (debug, info, warn, error). Default: "info".
    #[serde(default = "default_log_level")]
    #[allow(dead_code)]
    pub log_level: String,

    /// Beacon node connection configuration.
    #[serde(default)]
    pub beacon: BeaconConfig,

    /// Process discovery configuration.
    #[serde(default)]
    pub pid: PidConfig,

    /// Data export sink configuration.
    #[serde(default)]
    pub sinks: SinksConfig,

    /// Prometheus health metrics server configuration.
    #[serde(default)]
    pub health: HealthConfig,

    /// How often to poll the beacon node for sync state. Default: 30s.
    #[serde(default = "default_sync_poll_interval", with = "humantime_serde")]
    pub sync_poll_interval: Duration,

    /// BPF ring buffer size in bytes. Default: 4MB.
    #[serde(default = "default_ring_buffer_size")]
    pub ring_buffer_size: usize,

    /// Identifies this observoor instance in exported data.
    #[serde(default)]
    pub meta_client_name: String,

    /// Identifies the Ethereum network (e.g., mainnet, holesky).
    #[serde(default)]
    pub meta_network_name: String,

    /// Per-probe-group enable/disable configuration.
    #[serde(default)]
    pub probes: ProbesConfig,
}

/// Beacon node connection configuration.
#[derive(Debug, Deserialize)]
pub struct BeaconConfig {
    /// Beacon node HTTP endpoint (e.g., "http://localhost:5052").
    #[serde(default)]
    pub endpoint: String,

    /// Request timeout. Default: 10s.
    #[serde(default = "default_beacon_timeout", with = "humantime_serde")]
    pub timeout: Duration,
}

/// Process discovery configuration.
#[derive(Debug, Default, Deserialize)]
pub struct PidConfig {
    /// Process names to discover by scanning /proc.
    #[serde(default)]
    pub process_names: Vec<String>,

    /// Cgroup v2 path containing target processes.
    #[serde(default)]
    pub cgroup_path: String,
}

/// Data export sink configuration.
#[derive(Debug, Default, Deserialize)]
pub struct SinksConfig {
    /// Aggregated metrics sink configuration.
    #[serde(default)]
    pub aggregated: AggregatedSinkConfig,
}

/// Aggregated metrics sink configuration.
#[derive(Debug, Default, Clone, Deserialize)]
pub struct AggregatedSinkConfig {
    /// Enable the aggregated metrics sink.
    #[serde(default)]
    pub enabled: bool,

    /// Aggregation time window configuration.
    #[serde(default)]
    pub resolution: ResolutionConfig,

    /// Dimension inclusion configuration.
    #[serde(default)]
    pub dimensions: DimensionsConfig,

    /// Per-event sampling configuration applied in the eBPF layer.
    #[serde(default)]
    pub sampling: SamplingConfig,

    /// ClickHouse connection configuration.
    #[serde(default)]
    pub clickhouse: ClickHouseConfig,

    /// HTTP export configuration (e.g., to Vector).
    #[serde(default)]
    pub http: HttpExportConfig,
}

/// Aggregation time window configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct ResolutionConfig {
    /// Aggregation window duration. Default: 1s.
    #[serde(default = "default_resolution_interval", with = "humantime_serde")]
    pub interval: Duration,

    /// Reset aggregation windows at slot boundaries. Default: true.
    #[serde(default = "default_true")]
    pub slot_aligned: bool,

    /// Interval for writing sync state. Default: 12s.
    #[serde(default = "default_sync_state_poll_interval", with = "humantime_serde")]
    #[allow(dead_code)]
    pub sync_state_poll_interval: Duration,

    /// Interval for writing host specs snapshots. Default: 24h.
    #[serde(default = "default_host_specs_poll_interval", with = "humantime_serde")]
    pub host_specs_poll_interval: Duration,

    /// Per-metric interval overrides for lower-priority metric families.
    #[serde(default)]
    pub overrides: Vec<IntervalOverride>,
}

/// Sampling configuration for eBPF event emission.
#[derive(Debug, Clone, Deserialize)]
pub struct SamplingConfig {
    /// Default sampling policy for all events.
    #[serde(default)]
    pub default: EventSamplingRule,

    /// Per-event sampling overrides keyed by EventType label (e.g. "net_tx").
    #[serde(default = "default_sampling_event_rules")]
    pub events: HashMap<String, EventSamplingRule>,
}

impl Default for SamplingConfig {
    fn default() -> Self {
        Self {
            default: EventSamplingRule::default(),
            events: default_sampling_event_rules(),
        }
    }
}

/// Sampling policy for a single event stream.
#[derive(Debug, Clone, Copy, Deserialize)]
pub struct EventSamplingRule {
    /// Sampling mode.
    #[serde(default)]
    pub mode: EventSamplingMode,
    /// Effective retain rate in (0,1], depending on mode semantics.
    #[serde(default = "default_sampling_rate")]
    pub rate: f32,
}

impl Default for EventSamplingRule {
    fn default() -> Self {
        Self {
            mode: EventSamplingMode::None,
            rate: default_sampling_rate(),
        }
    }
}

/// Sampling modes supported by the eBPF layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventSamplingMode {
    None,
    Probability,
    Nth,
}

impl Default for EventSamplingMode {
    fn default() -> Self {
        Self::None
    }
}

/// Canonical sampling rule after validation/normalization.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ResolvedSamplingRule {
    pub mode: EventSamplingMode,
    /// Effective retain rate in (0,1].
    pub rate: f32,
    /// N value used in nth mode (1 for non-nth modes).
    pub nth: u32,
}

impl ResolvedSamplingRule {
    pub const fn none() -> Self {
        Self {
            mode: EventSamplingMode::None,
            rate: 1.0,
            nth: 1,
        }
    }
}

/// Per-metric resolution override.
#[derive(Debug, Clone, Deserialize)]
pub struct IntervalOverride {
    /// Metric names to assign to this interval.
    pub metrics: Vec<String>,
    /// Override interval duration (must be an exact multiple of base interval).
    #[serde(with = "humantime_serde")]
    pub interval: Duration,
}

/// Dimension inclusion configuration.
#[derive(Debug, Default, Clone, Deserialize)]
pub struct DimensionsConfig {
    /// Network metric dimensions.
    #[serde(default)]
    pub network: NetworkDimensionsConfig,

    /// Disk metric dimensions.
    #[serde(default)]
    pub disk: DiskDimensionsConfig,
}

/// Network metric dimension configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct NetworkDimensionsConfig {
    /// Include port label in network metrics. Default: true.
    #[serde(default = "default_true")]
    pub include_port: bool,

    /// Include TX/RX direction in network metrics. Default: true.
    #[serde(default = "default_true")]
    pub include_direction: bool,

    /// Runtime port-to-label map (not configurable via YAML).
    #[serde(skip)]
    pub port_label_map: Option<crate::agent::ports::PortLabelMap>,
}

/// Disk metric dimension configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct DiskDimensionsConfig {
    /// Include block device ID in disk metrics. Default: true.
    #[serde(default = "default_true")]
    pub include_device: bool,

    /// Include read/write breakdown in disk metrics. Default: true.
    #[serde(default = "default_true")]
    pub include_rw: bool,
}

/// ClickHouse connection configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct ClickHouseConfig {
    /// Enable the ClickHouse exporter. Default: false.
    #[serde(default)]
    pub enabled: bool,

    /// ClickHouse native protocol address (host:port).
    #[serde(default)]
    pub endpoint: String,

    /// Target database name. Default: "default".
    #[serde(default = "default_database")]
    pub database: String,

    /// Target table name. Default: "aggregated_metrics".
    #[serde(default = "default_table")]
    #[allow(dead_code)]
    pub table: String,

    /// Number of events per batch insert. Default: 10000.
    #[serde(default = "default_batch_size")]
    #[allow(dead_code)]
    pub batch_size: usize,

    /// Maximum time between flushes. Default: 1s.
    #[serde(default = "default_flush_interval", with = "humantime_serde")]
    #[allow(dead_code)]
    pub flush_interval: Duration,

    /// ClickHouse username.
    #[serde(default)]
    pub username: String,

    /// ClickHouse password.
    #[serde(default)]
    pub password: String,

    /// Schema migration configuration.
    #[serde(default)]
    pub migrations: MigrationsConfig,
}

/// Schema migration behavior configuration.
#[derive(Debug, Default, Clone, Deserialize)]
pub struct MigrationsConfig {
    /// Run migrations on startup. Default: false.
    #[serde(default)]
    pub enabled: bool,
}

/// HTTP export configuration (e.g., for Vector).
#[derive(Debug, Clone, Deserialize)]
pub struct HttpExportConfig {
    /// Enable the HTTP exporter. Default: false.
    #[serde(default)]
    pub enabled: bool,

    /// HTTP endpoint to send data to.
    #[serde(default)]
    pub address: String,

    /// Additional HTTP headers.
    #[serde(default)]
    pub headers: HashMap<String, String>,

    /// Compression algorithm (none, gzip, zstd, zlib, snappy). Default: gzip.
    #[serde(default = "default_compression")]
    pub compression: String,

    /// Maximum items per batch. Default: 512.
    #[serde(default = "default_http_batch_size")]
    pub batch_size: usize,

    /// Maximum wait before sending a batch. Default: 5s.
    #[serde(default = "default_http_batch_timeout", with = "humantime_serde")]
    pub batch_timeout: Duration,

    /// Maximum duration for an export operation. Default: 30s.
    #[serde(default = "default_http_export_timeout", with = "humantime_serde")]
    pub export_timeout: Duration,

    /// Maximum items to queue (dropped if full). Default: 8192.
    #[serde(default = "default_http_max_queue_size")]
    pub max_queue_size: usize,

    /// Number of concurrent workers. Default: 1.
    #[serde(default = "default_http_workers")]
    pub workers: usize,

    /// Enable HTTP keep-alive connections. Default: true.
    #[serde(default = "default_true")]
    pub keep_alive: bool,
}

/// Prometheus health metrics server configuration.
#[derive(Debug, Deserialize)]
pub struct HealthConfig {
    /// Listen address. Default: ":9090".
    #[serde(default = "default_health_addr")]
    pub addr: String,
}

// --- Default value functions ---

fn default_log_level() -> String {
    "info".to_string()
}

fn default_sync_poll_interval() -> Duration {
    Duration::from_secs(30)
}

fn default_ring_buffer_size() -> usize {
    4 * 1024 * 1024 // 4MB
}

fn default_beacon_timeout() -> Duration {
    Duration::from_secs(10)
}

fn default_true() -> bool {
    true
}

fn default_sampling_rate() -> f32 {
    1.0
}

fn default_sampling_event_rules() -> HashMap<String, EventSamplingRule> {
    HashMap::new()
}

fn default_resolution_interval() -> Duration {
    Duration::from_secs(1)
}

fn default_sync_state_poll_interval() -> Duration {
    Duration::from_secs(12)
}

fn default_host_specs_poll_interval() -> Duration {
    Duration::from_secs(24 * 60 * 60)
}

fn default_database() -> String {
    "default".to_string()
}

fn default_table() -> String {
    "aggregated_metrics".to_string()
}

fn default_batch_size() -> usize {
    10000
}

fn default_flush_interval() -> Duration {
    Duration::from_secs(1)
}

fn default_compression() -> String {
    "gzip".to_string()
}

fn default_http_batch_size() -> usize {
    512
}

fn default_http_batch_timeout() -> Duration {
    Duration::from_secs(5)
}

fn default_http_export_timeout() -> Duration {
    Duration::from_secs(30)
}

fn default_http_max_queue_size() -> usize {
    8192
}

fn default_http_workers() -> usize {
    1
}

fn default_health_addr() -> String {
    ":9090".to_string()
}

// --- Default trait impls ---

impl Default for Config {
    fn default() -> Self {
        Self {
            log_level: default_log_level(),
            beacon: BeaconConfig::default(),
            pid: PidConfig::default(),
            sinks: SinksConfig::default(),
            health: HealthConfig::default(),
            sync_poll_interval: default_sync_poll_interval(),
            ring_buffer_size: default_ring_buffer_size(),
            meta_client_name: String::new(),
            meta_network_name: String::new(),
            probes: ProbesConfig::default(),
        }
    }
}

impl Default for BeaconConfig {
    fn default() -> Self {
        Self {
            endpoint: String::new(),
            timeout: default_beacon_timeout(),
        }
    }
}

impl Default for ResolutionConfig {
    fn default() -> Self {
        Self {
            interval: default_resolution_interval(),
            slot_aligned: true,
            sync_state_poll_interval: default_sync_state_poll_interval(),
            host_specs_poll_interval: default_host_specs_poll_interval(),
            overrides: Vec::new(),
        }
    }
}

impl Default for NetworkDimensionsConfig {
    fn default() -> Self {
        Self {
            include_port: true,
            include_direction: true,
            port_label_map: None,
        }
    }
}

impl Default for DiskDimensionsConfig {
    fn default() -> Self {
        Self {
            include_device: true,
            include_rw: true,
        }
    }
}

impl Default for ClickHouseConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: String::new(),
            database: default_database(),
            table: default_table(),
            batch_size: default_batch_size(),
            flush_interval: default_flush_interval(),
            username: String::new(),
            password: String::new(),
            migrations: MigrationsConfig::default(),
        }
    }
}

impl Default for HttpExportConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            address: String::new(),
            headers: HashMap::new(),
            compression: default_compression(),
            batch_size: default_http_batch_size(),
            batch_timeout: default_http_batch_timeout(),
            export_timeout: default_http_export_timeout(),
            max_queue_size: default_http_max_queue_size(),
            workers: default_http_workers(),
            keep_alive: true,
        }
    }
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            addr: default_health_addr(),
        }
    }
}

// --- Validation and loading ---

impl Config {
    /// Load configuration from a YAML file.
    pub fn load(path: &Path) -> Result<Self> {
        let data = std::fs::read_to_string(path)
            .with_context(|| format!("reading config file {}", path.display()))?;

        let cfg: Config = serde_yaml::from_str(&data)
            .with_context(|| format!("parsing config file {}", path.display()))?;

        cfg.validate()?;

        Ok(cfg)
    }

    /// Validate the configuration for required fields and consistency.
    pub fn validate(&self) -> Result<()> {
        if self.beacon.endpoint.is_empty() {
            bail!("beacon.endpoint is required");
        }

        if self.meta_client_name.is_empty() {
            bail!("meta_client_name is required");
        }

        if self.meta_network_name.is_empty() {
            bail!("meta_network_name is required");
        }

        if self.ring_buffer_size == 0 {
            bail!("ring_buffer_size must be positive");
        }

        if !self.sinks.aggregated.enabled {
            bail!("sinks.aggregated.enabled must be true");
        }

        let base_interval = self.sinks.aggregated.resolution.interval;
        if base_interval.is_zero() {
            bail!("sinks.aggregated.resolution.interval must be positive");
        }
        if self
            .sinks
            .aggregated
            .resolution
            .sync_state_poll_interval
            .is_zero()
        {
            bail!("sinks.aggregated.resolution.sync_state_poll_interval must be positive");
        }
        if self
            .sinks
            .aggregated
            .resolution
            .host_specs_poll_interval
            .is_zero()
        {
            bail!("sinks.aggregated.resolution.host_specs_poll_interval must be positive");
        }

        let base_interval_ms = base_interval.as_millis();
        let valid_metric_names: HashSet<&str> = ALL_METRIC_NAMES.iter().copied().collect();
        let mut metrics_with_override = HashSet::new();

        for interval_override in &self.sinks.aggregated.resolution.overrides {
            if interval_override.interval <= base_interval {
                bail!(
                    "override interval {:?} must be greater than base interval {:?}",
                    interval_override.interval,
                    base_interval
                );
            }

            let override_ms = interval_override.interval.as_millis();
            if override_ms % base_interval_ms != 0 {
                bail!(
                    "override interval {:?} must be an exact multiple of base interval {:?}",
                    interval_override.interval,
                    base_interval
                );
            }

            for metric_name in &interval_override.metrics {
                if !valid_metric_names.contains(metric_name.as_str()) {
                    bail!("unknown metric in resolution override: {metric_name}");
                }

                if !metrics_with_override.insert(metric_name.clone()) {
                    bail!("metric appears in more than one override: {metric_name}");
                }
            }
        }

        for event_name in self.sinks.aggregated.sampling.events.keys() {
            if EventType::from_name(event_name).is_none() {
                bail!("unknown event in sampling config: {event_name}");
            }
        }

        for event_type in EventType::all() {
            self.sinks
                .aggregated
                .sampling
                .resolved_rule_for_event(*event_type)
                .with_context(|| format!("invalid sampling rule for {}", event_type.as_str()))?;
        }

        if !self.sinks.aggregated.dimensions.network.include_direction {
            let tx_rule = self
                .sinks
                .aggregated
                .sampling
                .resolved_rule_for_event(EventType::NetTX)
                .context("invalid sampling rule for net_tx")?;
            let rx_rule = self
                .sinks
                .aggregated
                .sampling
                .resolved_rule_for_event(EventType::NetRX)
                .context("invalid sampling rule for net_rx")?;
            if tx_rule != rx_rule {
                bail!("net_tx and net_rx sampling rules must match when network.include_direction=false");
            }
        }

        // Validate probe group config.
        let disabled_probes = self.probes.disabled_set()?;

        // Warn on nonsensical but harmless combinations.
        if disabled_probes.contains(&ProbeGroup::Scheduler)
            && !disabled_probes.contains(&ProbeGroup::SchedulerWakeup)
            && self.probes.entries.contains_key("scheduler_wakeup")
        {
            tracing::warn!(
                "scheduler_wakeup is enabled but scheduler is disabled — wakeup data has no effect without sched_switch"
            );
        }
        if disabled_probes.contains(&ProbeGroup::DiskIo)
            && !disabled_probes.contains(&ProbeGroup::BlockMerge)
            && self.probes.entries.contains_key("block_merge")
        {
            tracing::warn!(
                "block_merge is enabled but disk_io is disabled — merge data has limited value without disk I/O"
            );
        }
        {
            let all_net_disabled = disabled_probes.contains(&ProbeGroup::TcpSend)
                && disabled_probes.contains(&ProbeGroup::TcpRecv)
                && disabled_probes.contains(&ProbeGroup::UdpSend)
                && disabled_probes.contains(&ProbeGroup::UdpRecv);
            if all_net_disabled {
                if !disabled_probes.contains(&ProbeGroup::TcpRetransmit)
                    && self.probes.entries.contains_key("tcp_retransmit")
                {
                    tracing::warn!("tcp_retransmit is enabled but all network probes are disabled");
                }
                if !disabled_probes.contains(&ProbeGroup::TcpState)
                    && self.probes.entries.contains_key("tcp_state")
                {
                    tracing::warn!("tcp_state is enabled but all network probes are disabled");
                }
            }
        }

        // Validate HTTP export config if enabled.
        if self.sinks.aggregated.http.enabled {
            if self.sinks.aggregated.http.address.is_empty() {
                bail!("http address is required when enabled");
            }

            if self.sinks.aggregated.http.max_queue_size == 0 {
                bail!("http max_queue_size must be positive when enabled");
            }
            if self.sinks.aggregated.http.batch_size == 0 {
                bail!("http batch_size must be positive when enabled");
            }
            if self.sinks.aggregated.http.workers == 0 {
                bail!("http workers must be positive when enabled");
            }

            let compression = &self.sinks.aggregated.http.compression;
            match compression.as_str() {
                "none" | "gzip" | "zstd" | "zlib" | "snappy" => {}
                _ => bail!("invalid compression type: {compression}"),
            }
        }

        Ok(())
    }
}

impl SamplingConfig {
    /// Returns the canonical sampling rule for the given event type.
    pub fn resolved_rule_for_event(&self, event_type: EventType) -> Result<ResolvedSamplingRule> {
        let rule = self
            .events
            .get(event_type.as_str())
            .copied()
            .unwrap_or(self.default);
        resolve_sampling_rule(rule)
    }
}

fn resolve_sampling_rule(rule: EventSamplingRule) -> Result<ResolvedSamplingRule> {
    match rule.mode {
        EventSamplingMode::None => {
            if !approx_eq(rule.rate, 1.0) {
                bail!("sampling mode 'none' requires rate=1.0");
            }
            Ok(ResolvedSamplingRule::none())
        }
        EventSamplingMode::Probability => {
            if !(rule.rate > 0.0 && rule.rate <= 1.0) {
                bail!("sampling mode 'probability' requires 0 < rate <= 1");
            }
            Ok(ResolvedSamplingRule {
                mode: EventSamplingMode::Probability,
                rate: rule.rate,
                nth: 1,
            })
        }
        EventSamplingMode::Nth => {
            if !(rule.rate > 0.0 && rule.rate <= 1.0) {
                bail!("sampling mode 'nth' requires 0 < rate <= 1");
            }

            let n_float = 1.0f64 / f64::from(rule.rate);
            let n_rounded = n_float.round();
            if (n_float - n_rounded).abs() > 1e-6 {
                bail!("sampling mode 'nth' requires rate to be 1/N (e.g. 0.5, 0.25, 0.1)");
            }

            let n_u64 = n_rounded as u64;
            if n_u64 == 0 || n_u64 > u64::from(u32::MAX) {
                bail!("sampling mode 'nth' produced invalid N value");
            }
            let n = n_u64 as u32;

            Ok(ResolvedSamplingRule {
                mode: EventSamplingMode::Nth,
                rate: 1.0 / (n as f32),
                nth: n,
            })
        }
    }
}

fn approx_eq(a: f32, b: f32) -> bool {
    (a - b).abs() <= 1e-6
}

impl NetworkDimensionsConfig {
    /// Resolves a raw port number to a `PortLabel` discriminant (`u8`).
    ///
    /// Returns `PortLabel::Unknown as u8` if the port is not in the label map.
    pub fn resolve_port_label(&self, port: u16) -> u8 {
        self.resolve_tcp_port_label(crate::tracer::event::ClientType::Unknown, port, port)
    }

    /// Resolves TCP traffic to a semantic `PortLabel` discriminant (`u8`).
    ///
    /// Resolution is client-aware and checks `primary_port` first, then `secondary_port`.
    pub fn resolve_tcp_port_label(
        &self,
        client_type: crate::tracer::event::ClientType,
        primary_port: u16,
        secondary_port: u16,
    ) -> u8 {
        match &self.port_label_map {
            Some(map) => map.resolve_tcp(client_type, primary_port, secondary_port) as u8,
            None => crate::agent::ports::PortLabel::Unknown as u8,
        }
    }

    /// Resolves UDP traffic to a semantic `PortLabel` discriminant (`u8`).
    ///
    /// Resolution is client-aware and checks `primary_port` first, then `secondary_port`.
    pub fn resolve_udp_port_label(
        &self,
        client_type: crate::tracer::event::ClientType,
        primary_port: u16,
        secondary_port: u16,
    ) -> u8 {
        match &self.port_label_map {
            Some(map) => map.resolve_udp(client_type, primary_port, secondary_port) as u8,
            None => crate::agent::ports::PortLabel::Unknown as u8,
        }
    }

    /// Set the runtime port-to-label map.
    pub fn set_port_label_map(&mut self, map: crate::agent::ports::PortLabelMap) {
        self.port_label_map = Some(map);
    }
}

impl ClickHouseConfig {
    /// Build a ClickHouse DSN string (clickhouse://user:pass@endpoint/database).
    #[allow(dead_code)]
    pub fn dsn(&self) -> String {
        let mut dsn = "clickhouse://".to_string();

        if !self.username.is_empty() {
            dsn.push_str(&self.username);
            if !self.password.is_empty() {
                dsn.push(':');
                dsn.push_str(&self.password);
            }
            dsn.push('@');
        }

        dsn.push_str(&self.endpoint);
        dsn.push('/');
        dsn.push_str(&self.database);

        dsn
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_config() -> Config {
        Config {
            beacon: BeaconConfig {
                endpoint: "http://localhost:5052".to_string(),
                ..Default::default()
            },
            sinks: SinksConfig {
                aggregated: AggregatedSinkConfig {
                    enabled: true,
                    ..Default::default()
                },
            },
            meta_client_name: "test-node".to_string(),
            meta_network_name: "testnet".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn test_default_config_values() {
        let cfg = Config::default();
        assert_eq!(cfg.log_level, "info");
        assert_eq!(cfg.sync_poll_interval, Duration::from_secs(30));
        assert_eq!(cfg.ring_buffer_size, 4 * 1024 * 1024);
        assert_eq!(cfg.health.addr, ":9090");
    }

    #[test]
    fn test_clickhouse_dsn_with_auth() {
        let cfg = ClickHouseConfig {
            endpoint: "localhost:9000".to_string(),
            database: "default".to_string(),
            username: "user".to_string(),
            password: "pass".to_string(),
            ..Default::default()
        };
        assert_eq!(cfg.dsn(), "clickhouse://user:pass@localhost:9000/default");
    }

    #[test]
    fn test_clickhouse_dsn_without_auth() {
        let cfg = ClickHouseConfig {
            endpoint: "localhost:9000".to_string(),
            database: "mydb".to_string(),
            ..Default::default()
        };
        assert_eq!(cfg.dsn(), "clickhouse://localhost:9000/mydb");
    }

    #[test]
    fn test_resolve_port_label_with_map() {
        use crate::agent::ports::{PortLabel, PortLabelMap};
        use crate::tracer::event::ClientType;

        let mut cfg = NetworkDimensionsConfig::default();
        let mut map = PortLabelMap::default();
        map.insert(ClientType::Geth, 8545, PortLabel::ElJsonRpc);
        map.insert(ClientType::Geth, 30303, PortLabel::ElP2PTcp);
        cfg.set_port_label_map(map);

        assert_eq!(cfg.resolve_port_label(8545), PortLabel::ElJsonRpc as u8);
        assert_eq!(
            cfg.resolve_tcp_port_label(ClientType::Geth, 30303, 45000),
            PortLabel::ElP2PTcp as u8
        );
        assert_eq!(
            cfg.resolve_tcp_port_label(ClientType::Geth, 45000, 30303),
            PortLabel::ElP2PTcp as u8
        );
        assert_eq!(
            cfg.resolve_tcp_port_label(ClientType::Geth, 9999, 9998),
            PortLabel::Unknown as u8
        );
    }

    #[test]
    fn test_resolve_tcp_port_label_ignores_udp_labels() {
        use crate::agent::ports::{PortLabel, PortLabelMap};
        use crate::tracer::event::ClientType;

        let mut cfg = NetworkDimensionsConfig::default();
        let mut map = PortLabelMap::default();
        map.insert(ClientType::Prysm, 13000, PortLabel::ClP2PTcp);
        map.insert(ClientType::Prysm, 13000, PortLabel::ClDiscovery);
        cfg.set_port_label_map(map);

        assert_eq!(
            cfg.resolve_tcp_port_label(ClientType::Prysm, 13000, 45000),
            PortLabel::ClP2PTcp as u8
        );
        assert_eq!(
            cfg.resolve_udp_port_label(ClientType::Prysm, 13000, 45000),
            PortLabel::ClDiscovery as u8
        );
    }

    #[test]
    fn test_resolve_port_label_without_map() {
        let cfg = NetworkDimensionsConfig::default();
        assert_eq!(
            cfg.resolve_port_label(8545),
            crate::agent::ports::PortLabel::Unknown as u8
        );
    }

    #[test]
    fn test_validation_missing_beacon() {
        let cfg = Config {
            sinks: SinksConfig {
                aggregated: AggregatedSinkConfig {
                    enabled: true,
                    ..Default::default()
                },
            },
            meta_client_name: "test".to_string(),
            meta_network_name: "testnet".to_string(),
            ..Default::default()
        };
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("beacon.endpoint"));
    }

    #[test]
    fn test_validation_missing_meta_client_name() {
        let cfg = Config {
            beacon: BeaconConfig {
                endpoint: "http://localhost:5052".to_string(),
                ..Default::default()
            },
            sinks: SinksConfig {
                aggregated: AggregatedSinkConfig {
                    enabled: true,
                    ..Default::default()
                },
            },
            meta_network_name: "testnet".to_string(),
            ..Default::default()
        };
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("meta_client_name"));
    }

    #[test]
    fn test_validation_http_max_queue_size_zero() {
        let mut cfg = Config {
            beacon: BeaconConfig {
                endpoint: "http://localhost:5052".to_string(),
                ..Default::default()
            },
            sinks: SinksConfig {
                aggregated: AggregatedSinkConfig {
                    enabled: true,
                    http: HttpExportConfig {
                        enabled: true,
                        address: "http://localhost:8686".to_string(),
                        max_queue_size: 0,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            },
            meta_client_name: "test".to_string(),
            meta_network_name: "testnet".to_string(),
            ..Default::default()
        };

        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("max_queue_size"));

        cfg.sinks.aggregated.http.max_queue_size = 1;
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_validation_http_batch_size_zero() {
        let cfg = Config {
            beacon: BeaconConfig {
                endpoint: "http://localhost:5052".to_string(),
                ..Default::default()
            },
            sinks: SinksConfig {
                aggregated: AggregatedSinkConfig {
                    enabled: true,
                    http: HttpExportConfig {
                        enabled: true,
                        address: "http://localhost:8686".to_string(),
                        batch_size: 0,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            },
            meta_client_name: "test".to_string(),
            meta_network_name: "testnet".to_string(),
            ..Default::default()
        };

        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("batch_size"));
    }

    #[test]
    fn test_validation_http_workers_zero() {
        let cfg = Config {
            beacon: BeaconConfig {
                endpoint: "http://localhost:5052".to_string(),
                ..Default::default()
            },
            sinks: SinksConfig {
                aggregated: AggregatedSinkConfig {
                    enabled: true,
                    http: HttpExportConfig {
                        enabled: true,
                        address: "http://localhost:8686".to_string(),
                        workers: 0,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            },
            meta_client_name: "test".to_string(),
            meta_network_name: "testnet".to_string(),
            ..Default::default()
        };

        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("workers"));
    }

    #[test]
    fn test_validation_override_interval_must_be_greater_than_base() {
        let mut cfg = valid_config();
        cfg.sinks.aggregated.resolution.interval = Duration::from_millis(100);
        cfg.sinks.aggregated.resolution.overrides = vec![IntervalOverride {
            metrics: vec!["syscall_futex".to_string()],
            interval: Duration::from_millis(100),
        }];

        let err = cfg.validate().unwrap_err();
        assert!(err
            .to_string()
            .contains("must be greater than base interval"));
    }

    #[test]
    fn test_validation_override_interval_must_be_exact_multiple() {
        let mut cfg = valid_config();
        cfg.sinks.aggregated.resolution.interval = Duration::from_millis(100);
        cfg.sinks.aggregated.resolution.overrides = vec![IntervalOverride {
            metrics: vec!["syscall_futex".to_string()],
            interval: Duration::from_millis(750),
        }];

        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("exact multiple"));
    }

    #[test]
    fn test_validation_override_metric_must_exist() {
        let mut cfg = valid_config();
        cfg.sinks.aggregated.resolution.interval = Duration::from_millis(100);
        cfg.sinks.aggregated.resolution.overrides = vec![IntervalOverride {
            metrics: vec!["not_a_metric".to_string()],
            interval: Duration::from_millis(500),
        }];

        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("unknown metric"));
    }

    #[test]
    fn test_validation_override_metric_must_not_repeat() {
        let mut cfg = valid_config();
        cfg.sinks.aggregated.resolution.interval = Duration::from_millis(100);
        cfg.sinks.aggregated.resolution.overrides = vec![
            IntervalOverride {
                metrics: vec!["syscall_futex".to_string()],
                interval: Duration::from_millis(500),
            },
            IntervalOverride {
                metrics: vec!["syscall_futex".to_string()],
                interval: Duration::from_secs(1),
            },
        ];

        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("more than one override"));
    }

    #[test]
    fn test_validation_override_accepts_valid_configuration() {
        let mut cfg = valid_config();
        cfg.sinks.aggregated.resolution.interval = Duration::from_millis(100);
        cfg.sinks.aggregated.resolution.overrides = vec![
            IntervalOverride {
                metrics: vec![
                    "syscall_futex".to_string(),
                    "sched_runqueue".to_string(),
                    "mem_reclaim".to_string(),
                ],
                interval: Duration::from_millis(500),
            },
            IntervalOverride {
                metrics: vec!["page_fault_major".to_string(), "fd_open".to_string()],
                interval: Duration::from_secs(1),
            },
        ];

        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_sampling_default_profile_rules() {
        let cfg = valid_config();
        let futex = cfg
            .sinks
            .aggregated
            .sampling
            .resolved_rule_for_event(EventType::SyscallFutex)
            .expect("sampling should resolve");
        assert_eq!(futex, ResolvedSamplingRule::none());

        let net_tx = cfg
            .sinks
            .aggregated
            .sampling
            .resolved_rule_for_event(EventType::NetTX)
            .expect("sampling should resolve");
        assert_eq!(net_tx, ResolvedSamplingRule::none());

        let disk = cfg
            .sinks
            .aggregated
            .sampling
            .resolved_rule_for_event(EventType::DiskIO)
            .expect("sampling should resolve");
        assert_eq!(disk, ResolvedSamplingRule::none());
    }

    #[test]
    fn test_sampling_probability_accepts_valid_rate() {
        let mut cfg = valid_config();
        cfg.sinks.aggregated.sampling.events.insert(
            "syscall_read".to_string(),
            EventSamplingRule {
                mode: EventSamplingMode::Probability,
                rate: 0.2,
            },
        );
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_sampling_nth_requires_reciprocal_rate() {
        let mut cfg = valid_config();
        cfg.sinks.aggregated.sampling.events.insert(
            "syscall_read".to_string(),
            EventSamplingRule {
                mode: EventSamplingMode::Nth,
                rate: 0.3,
            },
        );

        let err = cfg.validate().unwrap_err();
        assert!(err
            .to_string()
            .contains("invalid sampling rule for syscall_read"));
    }

    #[test]
    fn test_sampling_unknown_event_name_rejected() {
        let mut cfg = valid_config();
        cfg.sinks.aggregated.sampling.events.insert(
            "not_an_event".to_string(),
            EventSamplingRule {
                mode: EventSamplingMode::Probability,
                rate: 0.5,
            },
        );

        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("unknown event in sampling config"));
    }

    #[test]
    fn test_sampling_net_tx_rx_must_match_without_direction() {
        let mut cfg = valid_config();
        cfg.sinks.aggregated.dimensions.network.include_direction = false;
        cfg.sinks.aggregated.sampling.events.insert(
            "net_tx".to_string(),
            EventSamplingRule {
                mode: EventSamplingMode::Probability,
                rate: 0.5,
            },
        );
        cfg.sinks.aggregated.sampling.events.insert(
            "net_rx".to_string(),
            EventSamplingRule {
                mode: EventSamplingMode::Probability,
                rate: 0.25,
            },
        );

        let err = cfg.validate().unwrap_err();
        assert!(err
            .to_string()
            .contains("net_tx and net_rx sampling rules must match"));
    }

    #[test]
    fn test_validation_host_specs_poll_interval_must_be_positive() {
        let mut cfg = valid_config();
        cfg.sinks.aggregated.resolution.host_specs_poll_interval = Duration::ZERO;
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("host_specs_poll_interval"));
    }

    // --- ProbeGroup tests ---

    #[test]
    fn test_probe_group_roundtrip() {
        for group in ProbeGroup::all() {
            let name = group.as_str();
            let parsed = ProbeGroup::from_name(name);
            assert_eq!(parsed, Some(*group), "roundtrip failed for {name}");
        }
    }

    #[test]
    fn test_probe_group_all_count() {
        assert_eq!(ProbeGroup::all().len(), 27);
    }

    #[test]
    fn test_probe_group_from_name_unknown() {
        assert!(ProbeGroup::from_name("not_a_probe").is_none());
        assert!(ProbeGroup::from_name("").is_none());
    }

    #[test]
    fn test_probe_group_display() {
        assert_eq!(ProbeGroup::SyscallRead.to_string(), "syscall_read");
        assert_eq!(ProbeGroup::Scheduler.to_string(), "scheduler");
        assert_eq!(ProbeGroup::OomKill.to_string(), "oom_kill");
    }

    #[test]
    fn test_probe_group_event_types() {
        assert_eq!(
            ProbeGroup::SyscallRead.event_types(),
            &[EventType::SyscallRead]
        );
        assert_eq!(
            ProbeGroup::Scheduler.event_types(),
            &[EventType::SchedSwitch, EventType::SchedRunqueue]
        );
        assert!(ProbeGroup::SchedulerWakeup.event_types().is_empty());
        assert_eq!(ProbeGroup::TcpSend.event_types(), &[EventType::NetTX]);
        assert_eq!(ProbeGroup::UdpSend.event_types(), &[EventType::NetTX]);
    }

    #[test]
    fn test_probes_config_disabled_set_empty() {
        let cfg = ProbesConfig::default();
        let disabled = cfg.disabled_set().expect("should parse");
        assert!(disabled.is_empty());
    }

    #[test]
    fn test_probes_config_disabled_set_with_disabled() {
        let mut entries = HashMap::new();
        entries.insert("syscall_futex".to_string(), ProbeConfig { enabled: false });
        entries.insert("scheduler".to_string(), ProbeConfig { enabled: false });
        entries.insert("disk_io".to_string(), ProbeConfig { enabled: true });

        let cfg = ProbesConfig { entries };
        let disabled = cfg.disabled_set().expect("should parse");
        assert_eq!(disabled.len(), 2);
        assert!(disabled.contains(&ProbeGroup::SyscallFutex));
        assert!(disabled.contains(&ProbeGroup::Scheduler));
        assert!(!disabled.contains(&ProbeGroup::DiskIo));
    }

    #[test]
    fn test_probes_config_disabled_set_rejects_unknown() {
        let mut entries = HashMap::new();
        entries.insert("not_a_probe".to_string(), ProbeConfig { enabled: false });

        let cfg = ProbesConfig { entries };
        let err = cfg.disabled_set().unwrap_err();
        assert!(err.to_string().contains("unknown probe group"));
    }

    #[test]
    fn test_validation_unknown_probe_group_rejected() {
        let mut cfg = valid_config();
        cfg.probes
            .entries
            .insert("bogus_probe".to_string(), ProbeConfig { enabled: false });

        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("unknown probe group"));
    }

    #[test]
    fn test_validation_valid_probe_config_accepted() {
        let mut cfg = valid_config();
        cfg.probes
            .entries
            .insert("syscall_futex".to_string(), ProbeConfig { enabled: false });
        cfg.probes
            .entries
            .insert("scheduler".to_string(), ProbeConfig { enabled: false });
        assert!(cfg.validate().is_ok());
    }
}
