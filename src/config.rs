use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::Deserialize;

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
    /// Include local port in network metrics. Default: true.
    #[serde(default = "default_true")]
    pub include_port: bool,

    /// Include TX/RX direction in network metrics. Default: true.
    #[serde(default = "default_true")]
    pub include_direction: bool,

    /// Runtime port whitelist (not configurable via YAML).
    #[serde(skip)]
    pub port_whitelist: Option<std::collections::HashSet<u16>>,
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

    /// Maximum items to queue (dropped if full). Default: 51200.
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

fn default_resolution_interval() -> Duration {
    Duration::from_secs(1)
}

fn default_sync_state_poll_interval() -> Duration {
    Duration::from_secs(12)
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
    51200
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
        }
    }
}

impl Default for NetworkDimensionsConfig {
    fn default() -> Self {
        Self {
            include_port: true,
            include_direction: true,
            port_whitelist: None,
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

        // Validate HTTP export config if enabled.
        if self.sinks.aggregated.http.enabled {
            if self.sinks.aggregated.http.address.is_empty() {
                bail!("http address is required when enabled");
            }

            if self.sinks.aggregated.http.max_queue_size == 0 {
                bail!("http max_queue_size must be positive when enabled");
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

impl NetworkDimensionsConfig {
    /// Filter a port through the whitelist. Returns 0 if not whitelisted.
    pub fn filter_port(&self, port: u16) -> u16 {
        match &self.port_whitelist {
            Some(whitelist) if !whitelist.is_empty() => {
                if whitelist.contains(&port) {
                    port
                } else {
                    0
                }
            }
            _ => port,
        }
    }

    /// Set the runtime port whitelist.
    pub fn set_port_whitelist(&mut self, ports: std::collections::HashSet<u16>) {
        self.port_whitelist = Some(ports);
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
    fn test_port_filter_with_whitelist() {
        let mut cfg = NetworkDimensionsConfig::default();
        let mut whitelist = std::collections::HashSet::new();
        whitelist.insert(8545);
        whitelist.insert(30303);
        cfg.set_port_whitelist(whitelist);

        assert_eq!(cfg.filter_port(8545), 8545);
        assert_eq!(cfg.filter_port(30303), 30303);
        assert_eq!(cfg.filter_port(9999), 0);
    }

    #[test]
    fn test_port_filter_without_whitelist() {
        let cfg = NetworkDimensionsConfig::default();
        assert_eq!(cfg.filter_port(8545), 8545);
        assert_eq!(cfg.filter_port(12345), 12345);
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
}
