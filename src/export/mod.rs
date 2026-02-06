pub mod health;

use anyhow::{Context, Result};
use clickhouse_rs::Pool;

use crate::config::ClickHouseConfig;

/// Manages a ClickHouse native TCP connection pool.
///
/// Wraps `clickhouse-rs` Pool with LZ4 compression and pool sizing
/// matching the Go implementation (min=2, max=5).
pub struct ClickHouseWriter {
    cfg: ClickHouseConfig,
    pool: Option<Pool>,
}

impl ClickHouseWriter {
    /// Creates a new writer with the given configuration.
    pub fn new(cfg: ClickHouseConfig) -> Self {
        Self { cfg, pool: None }
    }

    /// Opens the connection pool and verifies connectivity with a ping.
    pub async fn start(&mut self) -> Result<()> {
        let dsn = self.build_dsn();
        let pool = Pool::new(dsn);

        let mut handle = pool
            .get_handle()
            .await
            .context("opening ClickHouse connection")?;

        handle.ping().await.context("pinging ClickHouse")?;

        tracing::info!(endpoint = %self.cfg.endpoint, "ClickHouse writer connected");

        self.pool = Some(pool);

        Ok(())
    }

    /// Returns the connection pool, if started.
    pub fn pool(&self) -> Option<&Pool> {
        self.pool.as_ref()
    }

    /// Returns the writer configuration.
    pub fn config(&self) -> &ClickHouseConfig {
        &self.cfg
    }

    /// Closes the connection pool.
    pub async fn stop(&mut self) -> Result<()> {
        self.pool.take();
        Ok(())
    }

    /// Builds a clickhouse-rs compatible TCP DSN from configuration.
    ///
    /// Format: `tcp://[user[:pass]@]host:port/database?options`
    fn build_dsn(&self) -> String {
        let mut dsn = "tcp://".to_string();

        if !self.cfg.username.is_empty() {
            dsn.push_str(&self.cfg.username);
            if !self.cfg.password.is_empty() {
                dsn.push(':');
                dsn.push_str(&self.cfg.password);
            }
            dsn.push('@');
        }

        dsn.push_str(&self.cfg.endpoint);
        dsn.push('/');
        dsn.push_str(&self.cfg.database);
        dsn.push_str("?compression=lz4&pool_min=2&pool_max=5");

        dsn
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_dsn_with_auth() {
        let cfg = ClickHouseConfig {
            endpoint: "localhost:9000".to_string(),
            database: "default".to_string(),
            username: "user".to_string(),
            password: "pass".to_string(),
            ..Default::default()
        };
        let writer = ClickHouseWriter::new(cfg);
        assert_eq!(
            writer.build_dsn(),
            "tcp://user:pass@localhost:9000/default?compression=lz4&pool_min=2&pool_max=5"
        );
    }

    #[test]
    fn test_build_dsn_without_auth() {
        let cfg = ClickHouseConfig {
            endpoint: "localhost:9000".to_string(),
            database: "mydb".to_string(),
            ..Default::default()
        };
        let writer = ClickHouseWriter::new(cfg);
        assert_eq!(
            writer.build_dsn(),
            "tcp://localhost:9000/mydb?compression=lz4&pool_min=2&pool_max=5"
        );
    }

    #[test]
    fn test_build_dsn_username_without_password() {
        let cfg = ClickHouseConfig {
            endpoint: "ch:9000".to_string(),
            database: "db".to_string(),
            username: "admin".to_string(),
            ..Default::default()
        };
        let writer = ClickHouseWriter::new(cfg);
        assert_eq!(
            writer.build_dsn(),
            "tcp://admin@ch:9000/db?compression=lz4&pool_min=2&pool_max=5"
        );
    }

    #[test]
    fn test_pool_none_before_start() {
        let cfg = ClickHouseConfig::default();
        let writer = ClickHouseWriter::new(cfg);
        assert!(writer.pool().is_none());
    }
}
