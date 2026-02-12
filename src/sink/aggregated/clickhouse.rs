use std::fmt::Write;
use std::sync::Arc;
use std::time::SystemTime;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use clickhouse_rs::Pool;

use crate::export::health::HealthMetrics;

use super::metric::{
    BatchMetadata, CounterMetric, CpuUtilMetric, GaugeMetric, LatencyMetric, MetricBatch,
};
#[cfg(feature = "bpf")]
use super::metric::{
    MemoryUsageMetric, ProcessFDUsageMetric, ProcessIOUsageMetric, ProcessSchedUsageMetric,
};

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

    /// Inserts CPU utilization metrics into the cpu_utilization table.
    async fn export_cpu_util_table(
        &self,
        metrics: &[CpuUtilMetric],
        meta: &BatchMetadata,
    ) -> Result<()> {
        let Some(first) = metrics.first() else {
            return Ok(());
        };

        let table = format!("{}.cpu_utilization", self.database);
        let columns = "updated_date_time, window_start, interval_ms, wallclock_slot, wallclock_slot_start_date_time, \
             pid, client_type, sampling_mode, sampling_rate, total_on_cpu_ns, event_count, active_cores, system_cores, \
             max_core_on_cpu_ns, max_core_id, mean_core_pct, min_core_pct, max_core_pct, \
             meta_client_name, meta_network_name";

        let updated = format_datetime(meta.updated_time);
        let window_start = format_datetime(first.window.start);
        let slot_start = format_datetime(first.slot.start_time);
        let client_name = escape_sql(&meta.client_name);
        let network_name = escape_sql(&meta.network_name);
        let mut sql =
            String::with_capacity(160 + table.len() + columns.len() + metrics.len() * 240);
        let _ = write!(sql, "INSERT INTO {table} ({columns}) VALUES ");

        for (idx, m) in metrics.iter().enumerate() {
            if idx > 0 {
                sql.push_str(", ");
            }

            let total_on_cpu_ns = m.total_on_cpu_ns as f32;
            let max_core_on_cpu_ns = m.max_core_on_cpu_ns as f32;
            let _ = write!(
                sql,
                "({updated}, {window_start}, {}, {}, {slot_start}, {}, '{}', \
                 '{}', {}, {total_on_cpu_ns}, {}, {}, {}, {max_core_on_cpu_ns}, {}, {}, {}, {}, \
                 '{client_name}', '{network_name}')",
                m.window.interval_ms,
                m.slot.number,
                m.pid,
                m.client_type.as_str(),
                m.sampling_mode.as_str(),
                m.sampling_rate,
                m.event_count,
                m.active_cores,
                m.system_cores,
                m.max_core_id,
                m.mean_core_pct,
                m.min_core_pct,
                m.max_core_pct,
            );
        }

        let mut handle = self
            .pool
            .get_handle()
            .await
            .context("getting handle for cpu utilization insert")?;

        if let Err(e) = handle.execute(sql.as_str()).await {
            self.record_batch_error("cpu_utilization");
            return Err(e).context("sending cpu_utilization batch");
        }

        Ok(())
    }

    /// Inserts process memory usage metrics into the memory_usage table.
    #[cfg(feature = "bpf")]
    async fn export_memory_usage_table(
        &self,
        metrics: &[MemoryUsageMetric],
        meta: &BatchMetadata,
    ) -> Result<()> {
        let Some(first) = metrics.first() else {
            return Ok(());
        };

        let table = format!("{}.memory_usage", self.database);
        let columns = "updated_date_time, window_start, interval_ms, wallclock_slot, wallclock_slot_start_date_time, \
             pid, client_type, sampling_mode, sampling_rate, vm_size_bytes, vm_rss_bytes, \
             rss_anon_bytes, rss_file_bytes, rss_shmem_bytes, vm_swap_bytes, \
             meta_client_name, meta_network_name";

        let updated = format_datetime(meta.updated_time);
        let window_start = format_datetime(first.window.start);
        let slot_start = format_datetime(first.slot.start_time);
        let client_name = escape_sql(&meta.client_name);
        let network_name = escape_sql(&meta.network_name);
        let mut sql =
            String::with_capacity(160 + table.len() + columns.len() + metrics.len() * 220);
        let _ = write!(sql, "INSERT INTO {table} ({columns}) VALUES ");

        for (idx, m) in metrics.iter().enumerate() {
            if idx > 0 {
                sql.push_str(", ");
            }

            let _ = write!(
                sql,
                "({updated}, {window_start}, {}, {}, {slot_start}, {}, '{}', '{}', {}, \
                 {}, {}, {}, {}, {}, {}, '{client_name}', '{network_name}')",
                m.window.interval_ms,
                m.slot.number,
                m.pid,
                m.client_type.as_str(),
                m.sampling_mode.as_str(),
                m.sampling_rate,
                m.vm_size_bytes,
                m.vm_rss_bytes,
                m.rss_anon_bytes,
                m.rss_file_bytes,
                m.rss_shmem_bytes,
                m.vm_swap_bytes,
            );
        }

        let mut handle = self
            .pool
            .get_handle()
            .await
            .context("getting handle for memory usage insert")?;

        if let Err(e) = handle.execute(sql.as_str()).await {
            self.record_batch_error("memory_usage");
            return Err(e).context("sending memory_usage batch");
        }

        Ok(())
    }

    /// Inserts process I/O usage metrics into the process_io_usage table.
    #[cfg(feature = "bpf")]
    async fn export_process_io_usage_table(
        &self,
        metrics: &[ProcessIOUsageMetric],
        meta: &BatchMetadata,
    ) -> Result<()> {
        let Some(first) = metrics.first() else {
            return Ok(());
        };

        let table = format!("{}.process_io_usage", self.database);
        let columns = "updated_date_time, window_start, interval_ms, wallclock_slot, wallclock_slot_start_date_time, \
             pid, client_type, sampling_mode, sampling_rate, rchar_bytes, wchar_bytes, \
             syscr, syscw, read_bytes, write_bytes, cancelled_write_bytes, \
             meta_client_name, meta_network_name";

        let updated = format_datetime(meta.updated_time);
        let window_start = format_datetime(first.window.start);
        let slot_start = format_datetime(first.slot.start_time);
        let client_name = escape_sql(&meta.client_name);
        let network_name = escape_sql(&meta.network_name);
        let mut sql =
            String::with_capacity(160 + table.len() + columns.len() + metrics.len() * 240);
        let _ = write!(sql, "INSERT INTO {table} ({columns}) VALUES ");

        for (idx, m) in metrics.iter().enumerate() {
            if idx > 0 {
                sql.push_str(", ");
            }

            let _ = write!(
                sql,
                "({updated}, {window_start}, {}, {}, {slot_start}, {}, '{}', '{}', {}, \
                 {}, {}, {}, {}, {}, {}, {}, '{client_name}', '{network_name}')",
                m.window.interval_ms,
                m.slot.number,
                m.pid,
                m.client_type.as_str(),
                m.sampling_mode.as_str(),
                m.sampling_rate,
                m.rchar_bytes,
                m.wchar_bytes,
                m.syscr,
                m.syscw,
                m.read_bytes,
                m.write_bytes,
                m.cancelled_write_bytes,
            );
        }

        let mut handle = self
            .pool
            .get_handle()
            .await
            .context("getting handle for process_io_usage insert")?;

        if let Err(e) = handle.execute(sql.as_str()).await {
            self.record_batch_error("process_io_usage");
            return Err(e).context("sending process_io_usage batch");
        }

        Ok(())
    }

    /// Inserts process file descriptor usage metrics into the process_fd_usage table.
    #[cfg(feature = "bpf")]
    async fn export_process_fd_usage_table(
        &self,
        metrics: &[ProcessFDUsageMetric],
        meta: &BatchMetadata,
    ) -> Result<()> {
        let Some(first) = metrics.first() else {
            return Ok(());
        };

        let table = format!("{}.process_fd_usage", self.database);
        let columns = "updated_date_time, window_start, interval_ms, wallclock_slot, wallclock_slot_start_date_time, \
             pid, client_type, sampling_mode, sampling_rate, open_fds, fd_limit_soft, fd_limit_hard, \
             meta_client_name, meta_network_name";

        let updated = format_datetime(meta.updated_time);
        let window_start = format_datetime(first.window.start);
        let slot_start = format_datetime(first.slot.start_time);
        let client_name = escape_sql(&meta.client_name);
        let network_name = escape_sql(&meta.network_name);
        let mut sql =
            String::with_capacity(160 + table.len() + columns.len() + metrics.len() * 200);
        let _ = write!(sql, "INSERT INTO {table} ({columns}) VALUES ");

        for (idx, m) in metrics.iter().enumerate() {
            if idx > 0 {
                sql.push_str(", ");
            }

            let _ = write!(
                sql,
                "({updated}, {window_start}, {}, {}, {slot_start}, {}, '{}', '{}', {}, \
                 {}, {}, {}, '{client_name}', '{network_name}')",
                m.window.interval_ms,
                m.slot.number,
                m.pid,
                m.client_type.as_str(),
                m.sampling_mode.as_str(),
                m.sampling_rate,
                m.open_fds,
                m.fd_limit_soft,
                m.fd_limit_hard,
            );
        }

        let mut handle = self
            .pool
            .get_handle()
            .await
            .context("getting handle for process_fd_usage insert")?;

        if let Err(e) = handle.execute(sql.as_str()).await {
            self.record_batch_error("process_fd_usage");
            return Err(e).context("sending process_fd_usage batch");
        }

        Ok(())
    }

    /// Inserts process scheduler snapshot metrics into the process_sched_usage table.
    #[cfg(feature = "bpf")]
    async fn export_process_sched_usage_table(
        &self,
        metrics: &[ProcessSchedUsageMetric],
        meta: &BatchMetadata,
    ) -> Result<()> {
        let Some(first) = metrics.first() else {
            return Ok(());
        };

        let table = format!("{}.process_sched_usage", self.database);
        let columns = "updated_date_time, window_start, interval_ms, wallclock_slot, wallclock_slot_start_date_time, \
             pid, client_type, sampling_mode, sampling_rate, threads, voluntary_ctxt_switches, nonvoluntary_ctxt_switches, \
             meta_client_name, meta_network_name";

        let updated = format_datetime(meta.updated_time);
        let window_start = format_datetime(first.window.start);
        let slot_start = format_datetime(first.slot.start_time);
        let client_name = escape_sql(&meta.client_name);
        let network_name = escape_sql(&meta.network_name);
        let mut sql =
            String::with_capacity(160 + table.len() + columns.len() + metrics.len() * 210);
        let _ = write!(sql, "INSERT INTO {table} ({columns}) VALUES ");

        for (idx, m) in metrics.iter().enumerate() {
            if idx > 0 {
                sql.push_str(", ");
            }

            let _ = write!(
                sql,
                "({updated}, {window_start}, {}, {}, {slot_start}, {}, '{}', '{}', {}, \
                 {}, {}, {}, '{client_name}', '{network_name}')",
                m.window.interval_ms,
                m.slot.number,
                m.pid,
                m.client_type.as_str(),
                m.sampling_mode.as_str(),
                m.sampling_rate,
                m.threads,
                m.voluntary_ctxt_switches,
                m.nonvoluntary_ctxt_switches,
            );
        }

        let mut handle = self
            .pool
            .get_handle()
            .await
            .context("getting handle for process_sched_usage insert")?;

        if let Err(e) = handle.execute(sql.as_str()).await {
            self.record_batch_error("process_sched_usage");
            return Err(e).context("sending process_sched_usage batch");
        }

        Ok(())
    }

    /// Inserts latency metrics into a specific table.
    async fn export_latency_table(
        &self,
        table_name: &str,
        metrics: &[LatencyMetric],
        meta: &BatchMetadata,
    ) -> Result<()> {
        let Some(first) = metrics.first() else {
            return Ok(());
        };

        let table = format!("{}.{}", self.database, table_name);
        let has_disk_dimensions = table_name == "disk_latency";

        let columns = if has_disk_dimensions {
            "updated_date_time, window_start, interval_ms, wallclock_slot, wallclock_slot_start_date_time, \
             pid, client_type, sampling_mode, sampling_rate, device_id, rw, sum, count, min, max, histogram, \
             meta_client_name, meta_network_name"
        } else {
            "updated_date_time, window_start, interval_ms, wallclock_slot, wallclock_slot_start_date_time, \
             pid, client_type, sampling_mode, sampling_rate, sum, count, min, max, histogram, \
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
                    "({updated}, {window_start}, {}, {}, {slot_start}, {}, '{}', '{}', {}, \
                     {device_id}, '{rw}', {}, {}, {}, {}, ",
                    m.window.interval_ms,
                    m.slot.number,
                    m.pid,
                    m.client_type.as_str(),
                    m.sampling_mode.as_str(),
                    m.sampling_rate,
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
                    "({updated}, {window_start}, {}, {}, {slot_start}, {}, '{}', '{}', {}, \
                     {}, {}, {}, {}, ",
                    m.window.interval_ms,
                    m.slot.number,
                    m.pid,
                    m.client_type.as_str(),
                    m.sampling_mode.as_str(),
                    m.sampling_rate,
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
        metrics: &[CounterMetric],
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
             pid, client_type, sampling_mode, sampling_rate, port_label, direction, sum, count, \
             meta_client_name, meta_network_name"
        } else if has_disk_dimensions {
            "updated_date_time, window_start, interval_ms, wallclock_slot, wallclock_slot_start_date_time, \
             pid, client_type, sampling_mode, sampling_rate, device_id, rw, sum, count, \
             meta_client_name, meta_network_name"
        } else {
            "updated_date_time, window_start, interval_ms, wallclock_slot, wallclock_slot_start_date_time, \
             pid, client_type, sampling_mode, sampling_rate, sum, count, \
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
                let port_label = m.port_label.unwrap_or("unknown");
                let direction = m.direction.unwrap_or("tx");
                let _ = write!(
                    sql,
                    "({updated}, {window_start}, {}, {}, {slot_start}, {}, '{}', '{}', {}, \
                     '{port_label}', '{direction}', {}, {}, '{client_name}', '{network_name}')",
                    m.window.interval_ms,
                    m.slot.number,
                    m.pid,
                    m.client_type.as_str(),
                    m.sampling_mode.as_str(),
                    m.sampling_rate,
                    m.sum,
                    m.count,
                );
            } else if has_disk_dimensions {
                let device_id = m.device_id.unwrap_or(0);
                let rw = m.rw.unwrap_or("read");
                let _ = write!(
                    sql,
                    "({updated}, {window_start}, {}, {}, {slot_start}, {}, '{}', '{}', {}, \
                     {device_id}, '{rw}', {}, {}, '{client_name}', '{network_name}')",
                    m.window.interval_ms,
                    m.slot.number,
                    m.pid,
                    m.client_type.as_str(),
                    m.sampling_mode.as_str(),
                    m.sampling_rate,
                    m.sum,
                    m.count,
                );
            } else {
                let _ = write!(
                    sql,
                    "({updated}, {window_start}, {}, {}, {slot_start}, {}, '{}', '{}', {}, \
                     {}, {}, '{client_name}', '{network_name}')",
                    m.window.interval_ms,
                    m.slot.number,
                    m.pid,
                    m.client_type.as_str(),
                    m.sampling_mode.as_str(),
                    m.sampling_rate,
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
        metrics: &[GaugeMetric],
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
             pid, client_type, sampling_mode, sampling_rate, port_label, sum, count, min, max, \
             meta_client_name, meta_network_name"
        } else if has_disk_dimensions {
            "updated_date_time, window_start, interval_ms, wallclock_slot, wallclock_slot_start_date_time, \
             pid, client_type, sampling_mode, sampling_rate, device_id, rw, sum, count, min, max, \
             meta_client_name, meta_network_name"
        } else {
            "updated_date_time, window_start, interval_ms, wallclock_slot, wallclock_slot_start_date_time, \
             pid, client_type, sampling_mode, sampling_rate, sum, count, min, max, \
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
                let port_label = m.port_label.unwrap_or("unknown");
                let _ = write!(
                    sql,
                    "({updated}, {window_start}, {}, {}, {slot_start}, {}, '{}', '{}', {}, \
                     '{port_label}', {}, {}, {}, {}, '{client_name}', '{network_name}')",
                    m.window.interval_ms,
                    m.slot.number,
                    m.pid,
                    m.client_type.as_str(),
                    m.sampling_mode.as_str(),
                    m.sampling_rate,
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
                    "({updated}, {window_start}, {}, {}, {slot_start}, {}, '{}', '{}', {}, \
                     {device_id}, '{rw}', {}, {}, {}, {}, '{client_name}', '{network_name}')",
                    m.window.interval_ms,
                    m.slot.number,
                    m.pid,
                    m.client_type.as_str(),
                    m.sampling_mode.as_str(),
                    m.sampling_rate,
                    m.sum,
                    m.count,
                    m.min,
                    m.max,
                );
            } else {
                let _ = write!(
                    sql,
                    "({updated}, {window_start}, {}, {}, {slot_start}, {}, '{}', '{}', {}, \
                     {}, {}, {}, {}, '{client_name}', '{network_name}')",
                    m.window.interval_ms,
                    m.slot.number,
                    m.pid,
                    m.client_type.as_str(),
                    m.sampling_mode.as_str(),
                    m.sampling_rate,
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

        // Export latency metrics grouped by contiguous table spans.
        let mut latency_remaining = batch.latency.as_slice();
        while let Some(first) = latency_remaining.first() {
            let table = first.metric_type;
            let group_len = latency_remaining
                .iter()
                .take_while(|m| m.metric_type == table)
                .count();
            let (group, rest) = latency_remaining.split_at(group_len);
            self.export_latency_table(table, group, &batch.metadata)
                .await?;
            total_rows += group.len();
            latency_remaining = rest;
        }

        // Export counter metrics grouped by contiguous table spans.
        let mut counter_remaining = batch.counter.as_slice();
        while let Some(first) = counter_remaining.first() {
            let table = first.metric_type;
            let group_len = counter_remaining
                .iter()
                .take_while(|m| m.metric_type == table)
                .count();
            let (group, rest) = counter_remaining.split_at(group_len);
            self.export_counter_table(table, group, &batch.metadata)
                .await?;
            total_rows += group.len();
            counter_remaining = rest;
        }

        // Export gauge metrics grouped by contiguous table spans.
        let mut gauge_remaining = batch.gauge.as_slice();
        while let Some(first) = gauge_remaining.first() {
            let table = first.metric_type;
            let group_len = gauge_remaining
                .iter()
                .take_while(|m| m.metric_type == table)
                .count();
            let (group, rest) = gauge_remaining.split_at(group_len);
            self.export_gauge_table(table, group, &batch.metadata)
                .await?;
            total_rows += group.len();
            gauge_remaining = rest;
        }

        // Export CPU utilization summary metrics.
        if !batch.cpu_util.is_empty() {
            self.export_cpu_util_table(&batch.cpu_util, &batch.metadata)
                .await?;
            total_rows += batch.cpu_util.len();
        }

        #[cfg(feature = "bpf")]
        {
            // Export memory usage snapshot metrics.
            if !batch.memory_usage.is_empty() {
                self.export_memory_usage_table(&batch.memory_usage, &batch.metadata)
                    .await?;
                total_rows += batch.memory_usage.len();
            }

            if !batch.process_io_usage.is_empty() {
                self.export_process_io_usage_table(&batch.process_io_usage, &batch.metadata)
                    .await?;
                total_rows += batch.process_io_usage.len();
            }

            if !batch.process_fd_usage.is_empty() {
                self.export_process_fd_usage_table(&batch.process_fd_usage, &batch.metadata)
                    .await?;
                total_rows += batch.process_fd_usage.len();
            }

            if !batch.process_sched_usage.is_empty() {
                self.export_process_sched_usage_table(&batch.process_sched_usage, &batch.metadata)
                    .await?;
                total_rows += batch.process_sched_usage.len();
            }
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

/// Host specs row for the host_specs table.
#[allow(dead_code)]
pub struct HostSpecsRow {
    pub updated_date_time: SystemTime,
    pub event_time: SystemTime,
    pub wallclock_slot: u32,
    pub wallclock_slot_start_date_time: SystemTime,
    pub host_id: String,
    pub kernel_release: String,
    pub os_name: String,
    pub architecture: String,
    pub cpu_model: String,
    pub cpu_vendor: String,
    pub cpu_online_cores: u16,
    pub cpu_logical_cores: u16,
    pub cpu_physical_cores: u16,
    pub cpu_performance_cores: u16,
    pub cpu_efficiency_cores: u16,
    pub cpu_unknown_type_cores: u16,
    pub cpu_logical_ids: Vec<u16>,
    pub cpu_core_ids: Vec<i32>,
    pub cpu_package_ids: Vec<i32>,
    pub cpu_die_ids: Vec<i32>,
    pub cpu_cluster_ids: Vec<i32>,
    pub cpu_core_types: Vec<u8>,
    pub cpu_core_type_labels: Vec<String>,
    pub cpu_online_flags: Vec<u8>,
    pub cpu_max_freq_khz: Vec<u64>,
    pub cpu_base_freq_khz: Vec<u64>,
    pub memory_total_bytes: u64,
    pub memory_type: String,
    pub memory_speed_mts: u32,
    pub memory_dimm_count: u16,
    pub memory_dimm_sizes_bytes: Vec<u64>,
    pub memory_dimm_types: Vec<String>,
    pub memory_dimm_speeds_mts: Vec<u32>,
    pub memory_dimm_configured_speeds_mts: Vec<u32>,
    pub memory_dimm_locators: Vec<String>,
    pub memory_dimm_bank_locators: Vec<String>,
    pub memory_dimm_manufacturers: Vec<String>,
    pub memory_dimm_part_numbers: Vec<String>,
    pub memory_dimm_serials: Vec<String>,
    pub disk_count: u16,
    pub disk_total_bytes: u64,
    pub disk_names: Vec<String>,
    pub disk_models: Vec<String>,
    pub disk_vendors: Vec<String>,
    pub disk_serials: Vec<String>,
    pub disk_sizes_bytes: Vec<u64>,
    pub disk_rotational: Vec<u8>,
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

    /// Writes a host specs row to the host_specs table.
    #[allow(dead_code)]
    pub async fn export_host_specs(&self, row: &HostSpecsRow, meta: &BatchMetadata) -> Result<()> {
        let table = format!("{}.host_specs", self.database);

        let updated = format_datetime(row.updated_date_time);
        let event_time = format_datetime(row.event_time);
        let slot_start = format_datetime(row.wallclock_slot_start_date_time);
        let host_id = escape_sql(&row.host_id);
        let kernel_release = escape_sql(&row.kernel_release);
        let os_name = escape_sql(&row.os_name);
        let architecture = escape_sql(&row.architecture);
        let cpu_model = escape_sql(&row.cpu_model);
        let cpu_vendor = escape_sql(&row.cpu_vendor);
        let cpu_logical_ids = format_u16_array(&row.cpu_logical_ids);
        let cpu_core_ids = format_i32_array(&row.cpu_core_ids);
        let cpu_package_ids = format_i32_array(&row.cpu_package_ids);
        let cpu_die_ids = format_i32_array(&row.cpu_die_ids);
        let cpu_cluster_ids = format_i32_array(&row.cpu_cluster_ids);
        let cpu_core_types = format_u8_array(&row.cpu_core_types);
        let cpu_core_type_labels = format_string_array(&row.cpu_core_type_labels);
        let cpu_online_flags = format_u8_array(&row.cpu_online_flags);
        let cpu_max_freq_khz = format_u64_array(&row.cpu_max_freq_khz);
        let cpu_base_freq_khz = format_u64_array(&row.cpu_base_freq_khz);
        let memory_type = escape_sql(&row.memory_type);
        let memory_dimm_sizes_bytes = format_u64_array(&row.memory_dimm_sizes_bytes);
        let memory_dimm_types = format_string_array(&row.memory_dimm_types);
        let memory_dimm_speeds_mts = format_u32_array(&row.memory_dimm_speeds_mts);
        let memory_dimm_configured_speeds_mts =
            format_u32_array(&row.memory_dimm_configured_speeds_mts);
        let memory_dimm_locators = format_string_array(&row.memory_dimm_locators);
        let memory_dimm_bank_locators = format_string_array(&row.memory_dimm_bank_locators);
        let memory_dimm_manufacturers = format_string_array(&row.memory_dimm_manufacturers);
        let memory_dimm_part_numbers = format_string_array(&row.memory_dimm_part_numbers);
        let memory_dimm_serials = format_string_array(&row.memory_dimm_serials);
        let disk_names = format_string_array(&row.disk_names);
        let disk_models = format_string_array(&row.disk_models);
        let disk_vendors = format_string_array(&row.disk_vendors);
        let disk_serials = format_string_array(&row.disk_serials);
        let disk_sizes_bytes = format_u64_array(&row.disk_sizes_bytes);
        let disk_rotational = format_u8_array(&row.disk_rotational);
        let client_name = escape_sql(&meta.client_name);
        let network_name = escape_sql(&meta.network_name);

        let sql = format!(
            "INSERT INTO {table} (\
             updated_date_time, event_time, wallclock_slot, wallclock_slot_start_date_time, \
             host_id, kernel_release, os_name, architecture, \
             cpu_model, cpu_vendor, cpu_online_cores, cpu_logical_cores, \
             cpu_physical_cores, cpu_performance_cores, cpu_efficiency_cores, cpu_unknown_type_cores, \
             cpu_logical_ids, cpu_core_ids, cpu_package_ids, cpu_die_ids, cpu_cluster_ids, \
             cpu_core_types, cpu_core_type_labels, cpu_online_flags, cpu_max_freq_khz, cpu_base_freq_khz, \
             memory_total_bytes, memory_type, memory_speed_mts, memory_dimm_count, \
             memory_dimm_sizes_bytes, memory_dimm_types, memory_dimm_speeds_mts, \
             memory_dimm_configured_speeds_mts, memory_dimm_locators, memory_dimm_bank_locators, \
             memory_dimm_manufacturers, memory_dimm_part_numbers, memory_dimm_serials, \
             disk_count, disk_total_bytes, \
             disk_names, disk_models, disk_vendors, disk_serials, disk_sizes_bytes, disk_rotational, \
             meta_client_name, meta_network_name\
             ) VALUES (\
             {updated}, {event_time}, {}, {slot_start}, \
             '{host_id}', '{kernel_release}', '{os_name}', '{architecture}', \
             '{cpu_model}', '{cpu_vendor}', {}, {}, {}, {}, {}, {}, \
             {cpu_logical_ids}, {cpu_core_ids}, {cpu_package_ids}, {cpu_die_ids}, {cpu_cluster_ids}, \
             {cpu_core_types}, {cpu_core_type_labels}, {cpu_online_flags}, {cpu_max_freq_khz}, {cpu_base_freq_khz}, \
             {}, '{memory_type}', {}, {}, \
             {memory_dimm_sizes_bytes}, {memory_dimm_types}, {memory_dimm_speeds_mts}, \
             {memory_dimm_configured_speeds_mts}, {memory_dimm_locators}, {memory_dimm_bank_locators}, \
             {memory_dimm_manufacturers}, {memory_dimm_part_numbers}, {memory_dimm_serials}, \
             {}, {}, {disk_names}, {disk_models}, {disk_vendors}, {disk_serials}, {disk_sizes_bytes}, {disk_rotational}, \
             '{client_name}', '{network_name}'\
             )",
            row.wallclock_slot,
            row.cpu_online_cores,
            row.cpu_logical_cores,
            row.cpu_physical_cores,
            row.cpu_performance_cores,
            row.cpu_efficiency_cores,
            row.cpu_unknown_type_cores,
            row.memory_total_bytes,
            row.memory_speed_mts,
            row.memory_dimm_count,
            row.disk_count,
            row.disk_total_bytes,
        );

        let mut handle = self
            .pool
            .get_handle()
            .await
            .context("getting handle for host_specs insert")?;

        if let Err(e) = handle.execute(sql.as_str()).await {
            self.record_batch_error("host_specs");
            return Err(e).context("sending host_specs batch");
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

fn format_string_array(values: &[String]) -> String {
    if values.is_empty() {
        return "[]".to_string();
    }

    let mut out = String::with_capacity(values.len() * 16 + 2);
    out.push('[');
    for (idx, value) in values.iter().enumerate() {
        if idx > 0 {
            out.push_str(", ");
        }
        let escaped = escape_sql(value);
        let _ = write!(out, "'{escaped}'");
    }
    out.push(']');
    out
}

fn format_u64_array(values: &[u64]) -> String {
    if values.is_empty() {
        return "[]".to_string();
    }

    let mut out = String::with_capacity(values.len() * 8 + 2);
    out.push('[');
    for (idx, value) in values.iter().enumerate() {
        if idx > 0 {
            out.push_str(", ");
        }
        let _ = write!(out, "{value}");
    }
    out.push(']');
    out
}

fn format_u32_array(values: &[u32]) -> String {
    if values.is_empty() {
        return "[]".to_string();
    }

    let mut out = String::with_capacity(values.len() * 6 + 2);
    out.push('[');
    for (idx, value) in values.iter().enumerate() {
        if idx > 0 {
            out.push_str(", ");
        }
        let _ = write!(out, "{value}");
    }
    out.push(']');
    out
}

fn format_u16_array(values: &[u16]) -> String {
    if values.is_empty() {
        return "[]".to_string();
    }

    let mut out = String::with_capacity(values.len() * 4 + 2);
    out.push('[');
    for (idx, value) in values.iter().enumerate() {
        if idx > 0 {
            out.push_str(", ");
        }
        let _ = write!(out, "{value}");
    }
    out.push(']');
    out
}

fn format_i32_array(values: &[i32]) -> String {
    if values.is_empty() {
        return "[]".to_string();
    }

    let mut out = String::with_capacity(values.len() * 6 + 2);
    out.push('[');
    for (idx, value) in values.iter().enumerate() {
        if idx > 0 {
            out.push_str(", ");
        }
        let _ = write!(out, "{value}");
    }
    out.push(']');
    out
}

fn format_u8_array(values: &[u8]) -> String {
    if values.is_empty() {
        return "[]".to_string();
    }

    let mut out = String::with_capacity(values.len() * 2 + 2);
    out.push('[');
    for (idx, value) in values.iter().enumerate() {
        if idx > 0 {
            out.push_str(", ");
        }
        let _ = write!(out, "{value}");
    }
    out.push(']');
    out
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
    fn test_format_string_array() {
        let values = vec!["nvme0n1".to_string(), "disk's model".to_string()];
        assert_eq!(
            format_string_array(&values),
            "['nvme0n1', 'disk\\'s model']"
        );
        assert_eq!(format_string_array(&[]), "[]");
    }

    #[test]
    fn test_format_u64_array() {
        assert_eq!(format_u64_array(&[1, 42, 1000]), "[1, 42, 1000]");
        assert_eq!(format_u64_array(&[]), "[]");
    }

    #[test]
    fn test_format_u32_array() {
        assert_eq!(format_u32_array(&[1, 42, 1000]), "[1, 42, 1000]");
        assert_eq!(format_u32_array(&[]), "[]");
    }

    #[test]
    fn test_format_u16_array() {
        assert_eq!(format_u16_array(&[1, 42, 1000]), "[1, 42, 1000]");
        assert_eq!(format_u16_array(&[]), "[]");
    }

    #[test]
    fn test_format_i32_array() {
        assert_eq!(format_i32_array(&[-1, 0, 42]), "[-1, 0, 42]");
        assert_eq!(format_i32_array(&[]), "[]");
    }

    #[test]
    fn test_format_u8_array() {
        assert_eq!(format_u8_array(&[0, 1, 1]), "[0, 1, 1]");
        assert_eq!(format_u8_array(&[]), "[]");
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
}
