use anyhow::Result;
use tokio_util::sync::CancellationToken;

use super::clickhouse::ClickHouseExporter;
use super::http::HttpExporter;
use super::metric::MetricBatch;

/// Exporter dispatches metric batches to ClickHouse or HTTP backends.
///
/// Uses enum dispatch rather than trait objects for zero-cost async dispatch
/// (avoids `Pin<Box<dyn Future>>` overhead on every export call).
pub enum Exporter {
    ClickHouse(ClickHouseExporter),
    Http(HttpExporter),
}

impl Exporter {
    /// Returns the exporter name for logging.
    pub fn name(&self) -> &str {
        match self {
            Self::ClickHouse(e) => e.name(),
            Self::Http(e) => e.name(),
        }
    }

    /// Initialize the exporter.
    pub async fn start(&mut self, ctx: CancellationToken) -> Result<()> {
        match self {
            Self::ClickHouse(e) => e.start(ctx).await,
            Self::Http(e) => e.start(ctx).await,
        }
    }

    /// Export a batch of metrics.
    pub async fn export(&self, batch: &MetricBatch) -> Result<()> {
        match self {
            Self::ClickHouse(e) => e.export(batch).await,
            Self::Http(e) => e.export(batch).await,
        }
    }

    /// Shut down the exporter.
    pub async fn stop(&mut self) -> Result<()> {
        match self {
            Self::ClickHouse(e) => e.stop().await,
            Self::Http(e) => e.stop().await,
        }
    }
}
