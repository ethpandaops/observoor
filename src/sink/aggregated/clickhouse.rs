use std::collections::HashMap;
use std::fmt::Write;
use std::sync::Arc;
use std::time::SystemTime;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use clickhouse_rs::Pool;

use crate::export::health::HealthMetrics;

use super::metric::{BatchMetadata, CounterMetric, GaugeMetric, LatencyMetric, MetricBatch};

/// ClickHouse batch exporter for aggregated metrics.
///
/// Groups metrics by table name and inserts each group with schema-appropriate
/// columns. Detects table variants (disk, network, TCP dimensions) by name.
pub struct ClickHouseExporter {
    pool: Pool,
    database: String,
    health: Option<Arc<HealthMetrics>>,
}

impl ClickHouseExporter {
    /// Creates a new ClickHouse exporter.
    pub fn new(pool: Pool, database: String, health: Option<Arc<HealthMetrics>>) -> Self {
        Self {
            pool,
            database,
            health,
        }
    }

    /// Groups latency metrics by table name.
    fn group_latency_by_table(metrics: &[LatencyMetric]) -> HashMap<&str, Vec<&LatencyMetric>> {
        let mut result: HashMap<&str, Vec<&LatencyMetric>> = HashMap::with_capacity(16);
        for m in metrics {
            result.entry(m.metric_type).or_default().push(m);
        }
        result
    }

    /// Groups counter metrics by table name.
    fn group_counter_by_table(metrics: &[CounterMetric]) -> HashMap<&str, Vec<&CounterMetric>> {
        let mut result: HashMap<&str, Vec<&CounterMetric>> = HashMap::with_capacity(16);
        for m in metrics {
            result.entry(m.metric_type).or_default().push(m);
        }
        result
    }

    /// Groups gauge metrics by table name.
    fn group_gauge_by_table(metrics: &[GaugeMetric]) -> HashMap<&str, Vec<&GaugeMetric>> {
        let mut result: HashMap<&str, Vec<&GaugeMetric>> = HashMap::with_capacity(4);
        for m in metrics {
            result.entry(m.metric_type).or_default().push(m);
        }
        result
    }

    /// Inserts latency metrics into a specific table.
    async fn export_latency_table(
        &self,
        table_name: &str,
        metrics: &[&LatencyMetric],
        meta: &BatchMetadata,
    ) -> Result<()> {
        let Some(first) = metrics.first() else {
            return Ok(());
        };

        let table = format!("{}.{}", self.database, table_name);
        let has_disk_dimensions = table_name == "disk_latency";

        let columns = if has_disk_dimensions {
            "updated_date_time, window_start, interval_ms, wallclock_slot, wallclock_slot_start_date_time, \
             pid, client_type, device_id, rw, sum, count, min, max, histogram, \
             meta_client_name, meta_network_name"
        } else {
            "updated_date_time, window_start, interval_ms, wallclock_slot, wallclock_slot_start_date_time, \
             pid, client_type, sum, count, min, max, histogram, \
             meta_client_name, meta_network_name"
        };

        let updated = format_datetime(meta.updated_time);
        let window_start = format_datetime(first.window.start);
        let slot_start = format_datetime(first.slot.start_time);
        let client_name = escape_sql(&meta.client_name);
        let network_name = escape_sql(&meta.network_name);
        let mut sql =
            String::with_capacity(128 + table.len() + columns.len() + metrics.len() * 256);
        let _ = write!(sql, "INSERT INTO {table} ({columns}) VALUES ");

        for (idx, m) in metrics.iter().enumerate() {
            if idx > 0 {
                sql.push_str(", ");
            }

            if has_disk_dimensions {
                let device_id = m.device_id.unwrap_or(0);
                let rw = m.rw.unwrap_or("read");
                let _ = write!(
                    sql,
                    "({updated}, {window_start}, {}, {}, {slot_start}, {}, '{}', \
                     {device_id}, '{rw}', {}, {}, {}, {}, ",
                    m.window.interval_ms,
                    m.slot.number,
                    m.pid,
                    m.client_type.as_str(),
                    m.sum,
                    m.count,
                    m.min,
                    m.max,
                );
                append_histogram(&mut sql, &m.histogram);
                let _ = write!(sql, ", '{client_name}', '{network_name}')");
            } else {
                let _ = write!(
                    sql,
                    "({updated}, {window_start}, {}, {}, {slot_start}, {}, '{}', \
                     {}, {}, {}, {}, ",
                    m.window.interval_ms,
                    m.slot.number,
                    m.pid,
                    m.client_type.as_str(),
                    m.sum,
                    m.count,
                    m.min,
                    m.max,
                );
                append_histogram(&mut sql, &m.histogram);
                let _ = write!(sql, ", '{client_name}', '{network_name}')");
            }
        }

        let mut handle = self
            .pool
            .get_handle()
            .await
            .context("getting handle for latency insert")?;

        if let Err(e) = handle.execute(sql.as_str()).await {
            self.record_batch_error(table_name);
            return Err(e).with_context(|| format!("sending {table_name} batch"));
        }

        Ok(())
    }

    /// Inserts counter metrics into a specific table.
    async fn export_counter_table(
        &self,
        table_name: &str,
        metrics: &[&CounterMetric],
        meta: &BatchMetadata,
    ) -> Result<()> {
        let Some(first) = metrics.first() else {
            return Ok(());
        };

        let table = format!("{}.{}", self.database, table_name);
        let has_network_dimensions = table_name == "net_io" || table_name == "tcp_retransmit";
        let has_disk_dimensions = table_name == "disk_bytes" || table_name == "block_merge";

        let columns = if has_network_dimensions {
            "updated_date_time, window_start, interval_ms, wallclock_slot, wallclock_slot_start_date_time, \
             pid, client_type, local_port, direction, sum, count, \
             meta_client_name, meta_network_name"
        } else if has_disk_dimensions {
            "updated_date_time, window_start, interval_ms, wallclock_slot, wallclock_slot_start_date_time, \
             pid, client_type, device_id, rw, sum, count, \
             meta_client_name, meta_network_name"
        } else {
            "updated_date_time, window_start, interval_ms, wallclock_slot, wallclock_slot_start_date_time, \
             pid, client_type, sum, count, \
             meta_client_name, meta_network_name"
        };

        let updated = format_datetime(meta.updated_time);
        let window_start = format_datetime(first.window.start);
        let slot_start = format_datetime(first.slot.start_time);
        let client_name = escape_sql(&meta.client_name);
        let network_name = escape_sql(&meta.network_name);
        let mut sql =
            String::with_capacity(128 + table.len() + columns.len() + metrics.len() * 192);
        let _ = write!(sql, "INSERT INTO {table} ({columns}) VALUES ");

        for (idx, m) in metrics.iter().enumerate() {
            if idx > 0 {
                sql.push_str(", ");
            }

            if has_network_dimensions {
                let local_port = m.local_port.unwrap_or(0);
                let direction = m.direction.unwrap_or("tx");
                let _ = write!(
                    sql,
                    "({updated}, {window_start}, {}, {}, {slot_start}, {}, '{}', \
                     {local_port}, '{direction}', {}, {}, '{client_name}', '{network_name}')",
                    m.window.interval_ms,
                    m.slot.number,
                    m.pid,
                    m.client_type.as_str(),
                    m.sum,
                    m.count,
                );
            } else if has_disk_dimensions {
                let device_id = m.device_id.unwrap_or(0);
                let rw = m.rw.unwrap_or("read");
                let _ = write!(
                    sql,
                    "({updated}, {window_start}, {}, {}, {slot_start}, {}, '{}', \
                     {device_id}, '{rw}', {}, {}, '{client_name}', '{network_name}')",
                    m.window.interval_ms,
                    m.slot.number,
                    m.pid,
                    m.client_type.as_str(),
                    m.sum,
                    m.count,
                );
            } else {
                let _ = write!(
                    sql,
                    "({updated}, {window_start}, {}, {}, {slot_start}, {}, '{}', \
                     {}, {}, '{client_name}', '{network_name}')",
                    m.window.interval_ms,
                    m.slot.number,
                    m.pid,
                    m.client_type.as_str(),
                    m.sum,
                    m.count,
                );
            }
        }

        let mut handle = self
            .pool
            .get_handle()
            .await
            .context("getting handle for counter insert")?;

        if let Err(e) = handle.execute(sql.as_str()).await {
            self.record_batch_error(table_name);
            return Err(e).with_context(|| format!("sending {table_name} batch"));
        }

        Ok(())
    }

    /// Inserts gauge metrics into a specific table.
    async fn export_gauge_table(
        &self,
        table_name: &str,
        metrics: &[&GaugeMetric],
        meta: &BatchMetadata,
    ) -> Result<()> {
        let Some(first) = metrics.first() else {
            return Ok(());
        };

        let table = format!("{}.{}", self.database, table_name);
        let has_tcp_dimensions = table_name == "tcp_rtt" || table_name == "tcp_cwnd";
        let has_disk_dimensions = table_name == "disk_queue_depth";

        let columns = if has_tcp_dimensions {
            "updated_date_time, window_start, interval_ms, wallclock_slot, wallclock_slot_start_date_time, \
             pid, client_type, local_port, sum, count, min, max, \
             meta_client_name, meta_network_name"
        } else if has_disk_dimensions {
            "updated_date_time, window_start, interval_ms, wallclock_slot, wallclock_slot_start_date_time, \
             pid, client_type, device_id, rw, sum, count, min, max, \
             meta_client_name, meta_network_name"
        } else {
            "updated_date_time, window_start, interval_ms, wallclock_slot, wallclock_slot_start_date_time, \
             pid, client_type, sum, count, min, max, \
             meta_client_name, meta_network_name"
        };

        let updated = format_datetime(meta.updated_time);
        let window_start = format_datetime(first.window.start);
        let slot_start = format_datetime(first.slot.start_time);
        let client_name = escape_sql(&meta.client_name);
        let network_name = escape_sql(&meta.network_name);
        let mut sql =
            String::with_capacity(128 + table.len() + columns.len() + metrics.len() * 200);
        let _ = write!(sql, "INSERT INTO {table} ({columns}) VALUES ");

        for (idx, m) in metrics.iter().enumerate() {
            if idx > 0 {
                sql.push_str(", ");
            }

            if has_tcp_dimensions {
                let local_port = m.local_port.unwrap_or(0);
                let _ = write!(
                    sql,
                    "({updated}, {window_start}, {}, {}, {slot_start}, {}, '{}', \
                     {local_port}, {}, {}, {}, {}, '{client_name}', '{network_name}')",
                    m.window.interval_ms,
                    m.slot.number,
                    m.pid,
                    m.client_type.as_str(),
                    m.sum,
                    m.count,
                    m.min,
                    m.max,
                );
            } else if has_disk_dimensions {
                let device_id = m.device_id.unwrap_or(0);
                let rw = m.rw.unwrap_or("read");
                let _ = write!(
                    sql,
                    "({updated}, {window_start}, {}, {}, {slot_start}, {}, '{}', \
                     {device_id}, '{rw}', {}, {}, {}, {}, '{client_name}', '{network_name}')",
                    m.window.interval_ms,
                    m.slot.number,
                    m.pid,
                    m.client_type.as_str(),
                    m.sum,
                    m.count,
                    m.min,
                    m.max,
                );
            } else {
                let _ = write!(
                    sql,
                    "({updated}, {window_start}, {}, {}, {slot_start}, {}, '{}', \
                     {}, {}, {}, {}, '{client_name}', '{network_name}')",
                    m.window.interval_ms,
                    m.slot.number,
                    m.pid,
                    m.client_type.as_str(),
                    m.sum,
                    m.count,
                    m.min,
                    m.max,
                );
            }
        }

        let mut handle = self
            .pool
            .get_handle()
            .await
            .context("getting handle for gauge insert")?;

        if let Err(e) = handle.execute(sql.as_str()).await {
            self.record_batch_error(table_name);
            return Err(e).with_context(|| format!("sending {table_name} batch"));
        }

        Ok(())
    }

    /// Records a batch error in health metrics.
    fn record_batch_error(&self, table: &str) {
        if let Some(health) = &self.health {
            health
                .export_batch_errors
                .with_label_values(&["aggregated", table])
                .inc();
        }
    }
}

// --- Exporter interface (called by Exporter enum dispatch) ---

impl ClickHouseExporter {
    /// Returns the exporter name for logging.
    pub fn name(&self) -> &str {
        "clickhouse"
    }

    /// Initialize the exporter. Writer is started separately; no-op here.
    pub async fn start(&mut self, _ctx: tokio_util::sync::CancellationToken) -> Result<()> {
        Ok(())
    }

    /// Export a batch of metrics grouped by table.
    pub async fn export(&self, batch: &MetricBatch) -> Result<()> {
        let mut total_rows = 0;

        // Export latency metrics grouped by table.
        let latency_by_table = Self::group_latency_by_table(&batch.latency);
        for (table, metrics) in &latency_by_table {
            self.export_latency_table(table, metrics, &batch.metadata)
                .await?;
            total_rows += metrics.len();
        }

        // Export counter metrics grouped by table.
        let counter_by_table = Self::group_counter_by_table(&batch.counter);
        for (table, metrics) in &counter_by_table {
            self.export_counter_table(table, metrics, &batch.metadata)
                .await?;
            total_rows += metrics.len();
        }

        // Export gauge metrics grouped by table.
        let gauge_by_table = Self::group_gauge_by_table(&batch.gauge);
        for (table, metrics) in &gauge_by_table {
            self.export_gauge_table(table, metrics, &batch.metadata)
                .await?;
            total_rows += metrics.len();
        }

        if total_rows > 0 {
            if let Some(health) = &self.health {
                health
                    .sink_batch_size
                    .with_label_values(&["aggregated"])
                    .observe(total_rows as f64);
            }

            tracing::debug!(rows = total_rows, "flushed aggregated metrics");
        }

        Ok(())
    }

    /// Shut down the exporter. Writer is stopped separately; no-op here.
    pub async fn stop(&mut self) -> Result<()> {
        Ok(())
    }
}

/// Sync state row for the sync_state table.
#[allow(dead_code)]
pub struct SyncStateRow {
    pub updated_date_time: SystemTime,
    pub event_time: SystemTime,
    pub wallclock_slot: u32,
    pub wallclock_slot_start_date_time: SystemTime,
    pub cl_syncing: bool,
    pub el_optimistic: bool,
    pub el_offline: bool,
}

impl ClickHouseExporter {
    /// Writes a sync state row to the sync_state table.
    #[allow(dead_code)]
    pub async fn export_sync_state(&self, row: &SyncStateRow, meta: &BatchMetadata) -> Result<()> {
        let table = format!("{}.sync_state", self.database);

        let updated = format_datetime(row.updated_date_time);
        let event_time = format_datetime(row.event_time);
        let slot_start = format_datetime(row.wallclock_slot_start_date_time);
        let client_name = escape_sql(&meta.client_name);
        let network_name = escape_sql(&meta.network_name);
        let cl_syncing = if row.cl_syncing { 1 } else { 0 };
        let el_optimistic = if row.el_optimistic { 1 } else { 0 };
        let el_offline = if row.el_offline { 1 } else { 0 };

        let sql = format!(
            "INSERT INTO {table} (\
             updated_date_time, event_time, wallclock_slot, wallclock_slot_start_date_time, \
             cl_syncing, el_optimistic, el_offline, \
             meta_client_name, meta_network_name\
             ) VALUES (\
             {updated}, {event_time}, {}, {slot_start}, \
             {cl_syncing}, {el_optimistic}, {el_offline}, \
             '{client_name}', '{network_name}'\
             )",
            row.wallclock_slot,
        );

        let mut handle = self
            .pool
            .get_handle()
            .await
            .context("getting handle for sync_state insert")?;

        if let Err(e) = handle.execute(sql.as_str()).await {
            self.record_batch_error("sync_state");
            return Err(e).context("sending sync_state batch");
        }

        Ok(())
    }
}

// --- SQL formatting helpers ---

/// Formats a SystemTime as a ClickHouse DateTime64(3) literal.
fn format_datetime(t: SystemTime) -> String {
    let dt: DateTime<Utc> = t.into();
    format!("'{}'", dt.format("%Y-%m-%d %H:%M:%S%.3f"))
}

/// Escapes a string value for SQL insertion (single-quote escaping).
fn escape_sql(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\'', "\\'")
}

fn append_histogram(buf: &mut String, h: &[u32]) {
    let get = |i: usize| h.get(i).copied().unwrap_or(0);
    let _ = write!(
        buf,
        "({}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
        get(0),
        get(1),
        get(2),
        get(3),
        get(4),
        get(5),
        get(6),
        get(7),
        get(8),
        get(9),
    );
}

/// Formats a histogram Vec<u32> as a ClickHouse Tuple literal.
#[cfg(test)]
fn format_histogram(h: &[u32]) -> String {
    let mut out = String::with_capacity(64);
    append_histogram(&mut out, h);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tracer::event::ClientType;

    #[test]
    fn test_format_datetime() {
        let t = SystemTime::UNIX_EPOCH;
        let formatted = format_datetime(t);
        assert_eq!(formatted, "'1970-01-01 00:00:00.000'");
    }

    #[test]
    fn test_escape_sql() {
        assert_eq!(escape_sql("hello"), "hello");
        assert_eq!(escape_sql("it's"), "it\\'s");
        assert_eq!(escape_sql("back\\slash"), "back\\\\slash");
    }

    #[test]
    fn test_format_histogram_full() {
        let h = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        assert_eq!(format_histogram(&h), "(1, 2, 3, 4, 5, 6, 7, 8, 9, 10)");
    }

    #[test]
    fn test_format_histogram_short() {
        let h = vec![1, 2, 3];
        assert_eq!(format_histogram(&h), "(1, 2, 3, 0, 0, 0, 0, 0, 0, 0)");
    }

    #[test]
    fn test_format_histogram_empty() {
        let h: Vec<u32> = vec![];
        assert_eq!(format_histogram(&h), "(0, 0, 0, 0, 0, 0, 0, 0, 0, 0)");
    }

    #[test]
    fn test_group_latency_by_table() {
        use crate::sink::aggregated::metric::{SlotInfo, WindowInfo};

        let now = SystemTime::now();
        let metrics = vec![
            LatencyMetric {
                metric_type: "syscall_read",
                window: WindowInfo {
                    start: now,
                    interval_ms: 1000,
                },
                slot: SlotInfo {
                    number: 1,
                    start_time: now,
                },
                pid: 1,
                client_type: ClientType::Geth,
                device_id: None,
                rw: None,
                sum: 100,
                count: 10,
                min: 5,
                max: 20,
                histogram: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
            },
            LatencyMetric {
                metric_type: "syscall_read",
                window: WindowInfo {
                    start: now,
                    interval_ms: 1000,
                },
                slot: SlotInfo {
                    number: 1,
                    start_time: now,
                },
                pid: 2,
                client_type: ClientType::Reth,
                device_id: None,
                rw: None,
                sum: 200,
                count: 20,
                min: 10,
                max: 40,
                histogram: [2, 4, 6, 8, 10, 12, 14, 16, 18, 20],
            },
            LatencyMetric {
                metric_type: "disk_latency",
                window: WindowInfo {
                    start: now,
                    interval_ms: 1000,
                },
                slot: SlotInfo {
                    number: 1,
                    start_time: now,
                },
                pid: 1,
                client_type: ClientType::Geth,
                device_id: Some(259),
                rw: Some("write"),
                sum: 50000,
                count: 5,
                min: 1000,
                max: 20000,
                histogram: [0, 0, 1, 2, 1, 1, 0, 0, 0, 0],
            },
        ];

        let grouped = ClickHouseExporter::group_latency_by_table(&metrics);
        assert_eq!(grouped.len(), 2);
        assert_eq!(grouped.get("syscall_read").map(|v| v.len()), Some(2));
        assert_eq!(grouped.get("disk_latency").map(|v| v.len()), Some(1));
    }
}
