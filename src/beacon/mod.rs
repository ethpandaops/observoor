use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use tracing::debug;

use crate::config::BeaconConfig;

/// Beacon node sync status.
#[derive(Debug, Clone, Copy, Default)]
pub struct SyncStatus {
    pub is_syncing: bool,
    pub head_slot: u64,
    pub sync_distance: u64,
    pub is_optimistic: bool,
    pub el_offline: bool,
}

/// Beacon genesis information.
#[derive(Debug, Clone)]
pub struct GenesisResponse {
    pub genesis_time: SystemTime,
}

/// Beacon chain spec.
#[derive(Debug, Clone, Copy)]
pub struct SpecResponse {
    pub seconds_per_slot: u64,
    pub slots_per_epoch: u64,
}

/// Callback type for recording beacon request metrics.
pub type MetricsCallback = Box<dyn Fn(&str, &str, Duration) + Send + Sync>;

/// Beacon node API client trait.
pub trait BeaconClient: Send + Sync {
    /// Fetch genesis information from the beacon node.
    fn fetch_genesis(&self) -> impl std::future::Future<Output = Result<GenesisResponse>> + Send;

    /// Fetch chain spec parameters from the beacon node.
    fn fetch_spec(&self) -> impl std::future::Future<Output = Result<SpecResponse>> + Send;

    /// Fetch sync status from the beacon node.
    fn fetch_sync_status(&self) -> impl std::future::Future<Output = Result<SyncStatus>> + Send;
}

/// HTTP-based beacon node API client.
pub struct Client {
    http: reqwest::Client,
    endpoint: String,
    metrics: Option<MetricsCallback>,
}

impl Client {
    /// Create a new beacon node client.
    pub fn new(cfg: &BeaconConfig) -> Result<Self> {
        let timeout = if cfg.timeout.is_zero() {
            Duration::from_secs(10)
        } else {
            cfg.timeout
        };

        let http = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .context("building HTTP client")?;

        Ok(Self {
            http,
            endpoint: cfg.endpoint.clone(),
            metrics: None,
        })
    }

    /// Set a metrics callback for recording request stats.
    /// The callback receives (endpoint_name, status, duration).
    pub fn with_metrics(mut self, cb: MetricsCallback) -> Self {
        self.metrics = Some(cb);
        self
    }

    /// Record a request metric.
    fn record_request(&self, endpoint: &str, status: &str, duration: Duration) {
        if let Some(ref cb) = self.metrics {
            cb(endpoint, status, duration);
        }
    }

    /// Perform a GET request and deserialize the JSON response.
    async fn get_json<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T> {
        let start = Instant::now();
        let endpoint = endpoint_from_path(path);
        let url = format!("{}{}", self.endpoint, path);

        let response = self
            .http
            .get(&url)
            .header("Accept", "application/json")
            .send()
            .await
            .with_context(|| format!("requesting {path}"))?;

        let status_code = response.status();

        if !status_code.is_success() {
            let body = response.text().await.unwrap_or_default();
            self.record_request(endpoint, "error", start.elapsed());
            bail!("unexpected status {} from {}: {}", status_code, path, body);
        }

        let result: T = response
            .json()
            .await
            .with_context(|| format!("decoding response from {path}"))?;

        self.record_request(endpoint, "success", start.elapsed());

        Ok(result)
    }
}

/// Extract a short endpoint name from an API path.
fn endpoint_from_path(path: &str) -> &'static str {
    match path {
        "/eth/v1/beacon/genesis" => "genesis",
        "/eth/v1/config/spec" => "spec",
        "/eth/v1/node/syncing" => "syncing",
        _ => "other",
    }
}

// --- JSON response structures ---

#[derive(Deserialize)]
struct GenesisApiResponse {
    data: GenesisData,
}

#[derive(Deserialize)]
struct GenesisData {
    genesis_time: String,
}

#[derive(Deserialize)]
struct SpecApiResponse {
    data: HashMap<String, serde_json::Value>,
}

#[derive(Deserialize)]
struct SyncApiResponse {
    data: SyncData,
}

#[derive(Deserialize)]
struct SyncData {
    is_syncing: bool,
    head_slot: String,
    sync_distance: String,
    #[serde(default)]
    is_optimistic: bool,
    #[serde(default)]
    el_offline: bool,
}

impl BeaconClient for Client {
    async fn fetch_genesis(&self) -> Result<GenesisResponse> {
        debug!("fetching beacon genesis");

        let resp: GenesisApiResponse = self
            .get_json("/eth/v1/beacon/genesis")
            .await
            .context("fetching genesis")?;

        let genesis_unix: i64 = resp
            .data
            .genesis_time
            .parse()
            .with_context(|| format!("parsing genesis time {:?}", resp.data.genesis_time))?;

        let genesis_time = UNIX_EPOCH + Duration::from_secs(genesis_unix as u64);

        Ok(GenesisResponse { genesis_time })
    }

    async fn fetch_spec(&self) -> Result<SpecResponse> {
        debug!("fetching beacon spec");

        let resp: SpecApiResponse = self
            .get_json("/eth/v1/config/spec")
            .await
            .context("fetching spec")?;

        let seconds_per_slot = spec_uint64(&resp.data, "SECONDS_PER_SLOT")?;
        let slots_per_epoch = spec_uint64(&resp.data, "SLOTS_PER_EPOCH")?;

        Ok(SpecResponse {
            seconds_per_slot,
            slots_per_epoch,
        })
    }

    async fn fetch_sync_status(&self) -> Result<SyncStatus> {
        debug!("fetching beacon sync status");

        let resp: SyncApiResponse = self
            .get_json("/eth/v1/node/syncing")
            .await
            .context("fetching sync status")?;

        let head_slot: u64 = resp
            .data
            .head_slot
            .parse()
            .with_context(|| format!("parsing head_slot {:?}", resp.data.head_slot))?;

        let sync_distance: u64 = resp
            .data
            .sync_distance
            .parse()
            .with_context(|| format!("parsing sync_distance {:?}", resp.data.sync_distance))?;

        Ok(SyncStatus {
            is_syncing: resp.data.is_syncing,
            head_slot,
            sync_distance,
            is_optimistic: resp.data.is_optimistic,
            el_offline: resp.data.el_offline,
        })
    }
}

/// Extract a string-encoded u64 from a spec data map.
fn spec_uint64(data: &HashMap<String, serde_json::Value>, key: &str) -> Result<u64> {
    let value = data
        .get(key)
        .with_context(|| format!("spec missing required key {key:?}"))?;

    let s = value
        .as_str()
        .with_context(|| format!("spec key {key:?} is not a string"))?;

    s.parse::<u64>()
        .with_context(|| format!("parsing {key} value {s:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_endpoint_from_path() {
        assert_eq!(endpoint_from_path("/eth/v1/beacon/genesis"), "genesis");
        assert_eq!(endpoint_from_path("/eth/v1/config/spec"), "spec");
        assert_eq!(endpoint_from_path("/eth/v1/node/syncing"), "syncing");
        assert_eq!(endpoint_from_path("/some/other/path"), "other");
    }

    #[test]
    fn test_spec_uint64_valid() {
        let mut data = HashMap::new();
        data.insert(
            "SECONDS_PER_SLOT".to_string(),
            serde_json::Value::String("12".to_string()),
        );

        let result = spec_uint64(&data, "SECONDS_PER_SLOT");
        assert!(result.is_ok());
        assert_eq!(result.expect("should parse"), 12);
    }

    #[test]
    fn test_spec_uint64_missing_key() {
        let data = HashMap::new();
        let result = spec_uint64(&data, "MISSING_KEY");
        assert!(result.is_err());
        assert!(result
            .expect_err("should fail")
            .to_string()
            .contains("missing required key"));
    }

    #[test]
    fn test_spec_uint64_non_string() {
        let mut data = HashMap::new();
        data.insert(
            "BLOB_SCHEDULE".to_string(),
            serde_json::json!([{"BLOB_COUNT": 6}]),
        );

        let result = spec_uint64(&data, "BLOB_SCHEDULE");
        assert!(result.is_err());
        assert!(result
            .expect_err("should fail")
            .to_string()
            .contains("not a string"));
    }

    #[test]
    fn test_spec_uint64_invalid_number() {
        let mut data = HashMap::new();
        data.insert(
            "BAD_VALUE".to_string(),
            serde_json::Value::String("not_a_number".to_string()),
        );

        let result = spec_uint64(&data, "BAD_VALUE");
        assert!(result.is_err());
    }

    #[test]
    fn test_sync_status_default() {
        let status = SyncStatus::default();
        assert!(!status.is_syncing);
        assert_eq!(status.head_slot, 0);
        assert_eq!(status.sync_distance, 0);
        assert!(!status.is_optimistic);
        assert!(!status.el_offline);
    }
}
