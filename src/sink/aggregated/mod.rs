pub mod aggregate;
pub mod buffer;
pub mod collector;
pub mod config;
pub mod dimension;
pub mod exporter;
pub mod flush;
pub mod histogram;
pub mod metric;

pub mod clickhouse;
pub mod http;

use std::sync::atomic::{AtomicI64, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use anyhow::Result;
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::beacon::SyncStatus;
use crate::config::{AggregatedSinkConfig, DimensionsConfig};
use crate::sink::Sink;
use crate::tracer::event::{Direction, EventType, NetIOEvent, ParsedEvent, TypedEvent};

use self::buffer::Buffer;
use self::clickhouse::SyncStateRow;
use self::collector::Collector;
use self::dimension::{BasicDimension, DiskDimension, NetworkDimension, TCPMetricsDimension};
use self::exporter::Exporter;
use self::flush::TieredFlushController;
use self::metric::{BatchMetadata, MetricBatch};

/// Shared atomic state that can be safely sent to a spawned task.
struct SharedState {
    /// Current slot number.
    current_slot: AtomicU64,
    /// Current slot start time as nanos since epoch.
    current_slot_start: AtomicI64,
    /// Sync state fields (0=false, 1=true).
    cl_syncing: AtomicU32,
    el_optimistic: AtomicU32,
    el_offline: AtomicU32,
    /// Number of online CPU cores.
    system_cores: AtomicU32,
}

impl SharedState {
    fn new() -> Self {
        Self {
            current_slot: AtomicU64::new(0),
            current_slot_start: AtomicI64::new(0),
            cl_syncing: AtomicU32::new(0),
            el_optimistic: AtomicU32::new(0),
            el_offline: AtomicU32::new(0),
            system_cores: AtomicU32::new(0),
        }
    }

    fn slot_start_time(&self) -> SystemTime {
        let ns = self.current_slot_start.load(Ordering::Relaxed);
        SystemTime::UNIX_EPOCH + std::time::Duration::from_nanos(ns as u64)
    }
}

/// Aggregated metrics sink that provides configurable time-resolution
/// aggregation with dimensional breakdown.
pub struct AggregatedSink {
    cfg: AggregatedSinkConfig,
    meta_client_name: Arc<str>,
    meta_network_name: Arc<str>,
    #[allow(dead_code)]
    collector: Collector,
    exporters: Vec<Exporter>,

    /// Event channel sender for the processing loop.
    event_tx: mpsc::Sender<ParsedEvent>,
    /// Event channel receiver, taken by `start`.
    event_rx: Option<mpsc::Receiver<ParsedEvent>>,

    /// Queue of slot-rotation buffers waiting to be flushed.
    rotation_tx: mpsc::UnboundedSender<Arc<Buffer>>,
    /// Queue receiver, taken by `start`.
    rotation_rx: Option<mpsc::UnboundedReceiver<Arc<Buffer>>>,

    /// Atomic buffer pointer for lock-free rotation.
    buffer: Arc<atomic_buffer::AtomicBuffer>,

    /// Shared atomic state, cloned into the spawned task.
    state: Arc<SharedState>,

    /// Handle for the sink run task.
    run_task: Arc<tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>>,
}

impl AggregatedSink {
    /// Creates a new aggregated metrics sink.
    pub fn new(
        cfg: AggregatedSinkConfig,
        meta_client_name: String,
        meta_network_name: String,
    ) -> Self {
        let (event_tx, event_rx) = mpsc::channel(65536);
        let (rotation_tx, rotation_rx) = mpsc::unbounded_channel();

        Self {
            collector: Collector::new(cfg.resolution.interval, &cfg.sampling),
            cfg,
            meta_client_name: Arc::from(meta_client_name),
            meta_network_name: Arc::from(meta_network_name),
            exporters: Vec::with_capacity(2),
            event_tx,
            event_rx: Some(event_rx),
            rotation_tx,
            rotation_rx: Some(rotation_rx),
            buffer: Arc::new(atomic_buffer::AtomicBuffer::new()),
            state: Arc::new(SharedState::new()),
            run_task: Arc::new(tokio::sync::Mutex::new(None)),
        }
    }

    /// Registers a metric exporter.
    pub fn add_exporter(&mut self, exporter: Exporter) {
        self.exporters.push(exporter);
    }

    /// Waits for the sink run task to finish.
    pub async fn wait_for_shutdown(&self) {
        let run_task = { self.run_task.lock().await.take() };
        if let Some(run_task) = run_task {
            if let Err(e) = run_task.await {
                warn!(error = %e, "aggregated sink task join failed");
            }
        }
    }

    /// Sets the port-to-label map for network dimensions.
    pub fn set_port_label_map(
        &mut self,
        map: std::collections::HashMap<u16, crate::agent::ports::PortLabel>,
    ) {
        self.cfg.dimensions.network.set_port_label_map(map);
    }

    /// Creates a new buffer with current sync state.
    fn new_buffer_from_state(state: &SharedState, now: SystemTime, slot: u64) -> Buffer {
        let system_cores =
            u16::try_from(state.system_cores.load(Ordering::Relaxed)).unwrap_or(u16::MAX);
        Buffer::new(
            now,
            slot,
            state.slot_start_time(),
            state.cl_syncing.load(Ordering::Relaxed) == 1,
            state.el_optimistic.load(Ordering::Relaxed) == 1,
            state.el_offline.load(Ordering::Relaxed) == 1,
            system_cores,
        )
    }

    /// Builds a sync-state row from current shared state.
    fn new_sync_state_row(state: &SharedState, now: SystemTime) -> SyncStateRow {
        SyncStateRow {
            updated_date_time: now,
            event_time: now,
            wallclock_slot: u32::try_from(state.current_slot.load(Ordering::Relaxed))
                .unwrap_or(u32::MAX),
            wallclock_slot_start_date_time: state.slot_start_time(),
            cl_syncing: state.cl_syncing.load(Ordering::Relaxed) == 1,
            el_optimistic: state.el_optimistic.load(Ordering::Relaxed) == 1,
            el_offline: state.el_offline.load(Ordering::Relaxed) == 1,
        }
    }

    /// Routes a parsed event to the appropriate buffer aggregator.
    fn process_event(buf: &Buffer, event: &ParsedEvent, dimensions: &DimensionsConfig) {
        let basic_dim = BasicDimension {
            pid: event.raw.pid,
            client_type: event.raw.client_type as u8,
        };

        match &event.typed {
            TypedEvent::Syscall(e) => {
                buf.add_syscall(event.raw.event_type, basic_dim, e.latency_ns);
            }

            TypedEvent::NetIO(e) => {
                let net_dim = build_network_dimension(
                    event.raw.pid,
                    event.raw.client_type as u8,
                    e,
                    dimensions,
                );
                buf.add_net_io(net_dim, i64::from(e.bytes));

                // Extract inline TCP metrics from merged net_tx events.
                if e.has_metrics {
                    let tcp_dim = build_tcp_metrics_dim_from_net_io(
                        event.raw.pid,
                        event.raw.client_type as u8,
                        e,
                        dimensions,
                    );
                    buf.add_tcp_metrics(tcp_dim, e.srtt_us, e.cwnd);
                }
            }

            TypedEvent::TcpRetransmit(e) => {
                let net_dim = build_network_dimension_from_tcp_retransmit(
                    event.raw.pid,
                    event.raw.client_type as u8,
                    e.src_port,
                    dimensions,
                );
                buf.add_tcp_retransmit(net_dim, i64::from(e.bytes));
            }

            TypedEvent::TcpState(_) => {
                buf.add_tcp_state_change(basic_dim);
            }

            TypedEvent::DiskIO(e) => {
                let disk_dim = build_disk_dimension(
                    event.raw.pid,
                    event.raw.client_type as u8,
                    e.device_id,
                    e.rw,
                    dimensions,
                );
                buf.add_disk_io(disk_dim, e.latency_ns, e.bytes, e.queue_depth);
            }

            TypedEvent::BlockMerge(e) => {
                let disk_dim = build_disk_dimension(
                    event.raw.pid,
                    event.raw.client_type as u8,
                    0,
                    e.rw,
                    dimensions,
                );
                buf.add_block_merge(disk_dim, e.bytes);
            }

            TypedEvent::Sched(e) => {
                buf.add_sched_switch(basic_dim, e.on_cpu_ns, e.cpu_id);
            }

            TypedEvent::SchedRunqueue(e) => {
                buf.add_sched_runqueue(basic_dim, e.runqueue_ns, e.off_cpu_ns);
            }

            TypedEvent::PageFault(e) => {
                buf.add_page_fault(basic_dim, e.major);
            }

            TypedEvent::FD(_) => {
                if event.raw.event_type == EventType::FDOpen {
                    buf.add_fd_open(basic_dim);
                } else {
                    buf.add_fd_close(basic_dim);
                }
            }

            TypedEvent::MemLatency(e) => {
                if event.raw.event_type == EventType::MemReclaim {
                    buf.add_mem_reclaim(basic_dim, e.duration_ns);
                } else {
                    buf.add_mem_compaction(basic_dim, e.duration_ns);
                }
            }

            TypedEvent::Swap(e) => {
                if event.raw.event_type == EventType::SwapIn {
                    buf.add_swap_in(basic_dim, e.pages);
                } else {
                    buf.add_swap_out(basic_dim, e.pages);
                }
            }

            TypedEvent::OOMKill(_) => {
                buf.add_oom_kill(basic_dim);
            }

            TypedEvent::ProcessExit(_) => {
                buf.add_process_exit(basic_dim);
            }
        }
    }
}

impl Sink for AggregatedSink {
    fn name(&self) -> &str {
        "aggregated"
    }

    async fn start(&mut self, ctx: tokio_util::sync::CancellationToken) -> Result<()> {
        let system_cores = parse_cpu_online();
        self.state
            .system_cores
            .store(system_cores, Ordering::Relaxed);
        if system_cores == 0 {
            warn!("failed to detect online CPU cores from /sys/devices/system/cpu/online");
        } else {
            info!(system_cores, "detected online CPU cores");
        }

        // Initialize first buffer.
        let now = SystemTime::now();
        let initial_buf = Self::new_buffer_from_state(&self.state, now, 0);
        self.buffer.store(initial_buf);

        // Take the receivers out of self for the run loop.
        let mut event_rx = self.event_rx.take().expect("start called more than once");
        let mut rotation_rx = self
            .rotation_rx
            .take()
            .expect("start called more than once");

        // Take exporters and start them.
        let mut exporters = std::mem::take(&mut self.exporters);
        for exporter in &mut exporters {
            exporter.start(ctx.clone()).await?;
            info!(exporter = exporter.name(), "exporter started");
        }

        let buffer = Arc::clone(&self.buffer);
        let state = Arc::clone(&self.state);
        let dimensions = self.cfg.dimensions.clone();
        let interval = self.cfg.resolution.interval;
        let sync_state_interval = self.cfg.resolution.sync_state_poll_interval;
        let resolution_overrides = self.cfg.resolution.overrides.clone();
        let sampling_cfg = self.cfg.sampling.clone();
        let collector = Collector::new_with_memory_usage(interval, &sampling_cfg, true);
        let mut flush_controller = TieredFlushController::new(interval, &resolution_overrides);
        let meta_client_name = Arc::clone(&self.meta_client_name);
        let meta_network_name = Arc::clone(&self.meta_network_name);

        let run_task = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut sync_state_ticker = tokio::time::interval(sync_state_interval);
            sync_state_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut reusable_batch = MetricBatch {
                metadata: BatchMetadata {
                    client_name: Arc::clone(&meta_client_name),
                    network_name: Arc::clone(&meta_network_name),
                    updated_time: SystemTime::UNIX_EPOCH,
                },
                latency: Vec::new(),
                counter: Vec::new(),
                gauge: Vec::new(),
                cpu_util: Vec::new(),
                memory_usage: Vec::new(),
            };

            const BATCH_SIZE: usize = 256;

            loop {
                tokio::select! {
                    _ = ctx.cancelled() => {
                        // Flush pending slot-rotation buffers first.
                        while let Ok(rotated_buf) = rotation_rx.try_recv() {
                            reusable_batch.metadata.updated_time = SystemTime::now();
                            collector.collect_into(&rotated_buf, &mut reusable_batch);
                            flush_controller.force_flush_all(&mut reusable_batch);
                            if !reusable_batch.is_empty() {
                                for exporter in &exporters {
                                    if let Err(e) = exporter.export(&reusable_batch).await {
                                        tracing::error!(
                                            exporter = exporter.name(),
                                            error = %e,
                                            "final rotated-buffer export failed",
                                        );
                                    }
                                }
                            }
                        }

                        // Final flush.
                        if let Some(final_buf) = buffer.take() {
                            reusable_batch.metadata.updated_time = SystemTime::now();
                            collector.collect_into(&final_buf, &mut reusable_batch);
                            flush_controller.force_flush_all(&mut reusable_batch);
                            if !reusable_batch.is_empty() {
                                for exporter in &exporters {
                                    if let Err(e) = exporter.export(&reusable_batch).await {
                                        tracing::error!(
                                            exporter = exporter.name(),
                                            error = %e,
                                            "final export failed",
                                        );
                                    }
                                }
                                info!(
                                    latency = reusable_batch.latency.len(),
                                    counter = reusable_batch.counter.len(),
                                    gauge = reusable_batch.gauge.len(),
                                    cpu_util = reusable_batch.cpu_util.len(),
                                    memory_usage = reusable_batch.memory_usage.len(),
                                    "final flush"
                                );
                            }
                        }

                        // Stop all exporters.
                        for exporter in &mut exporters {
                            if let Err(e) = exporter.stop().await {
                                tracing::error!(
                                    exporter = exporter.name(),
                                    error = %e,
                                    "exporter stop failed",
                                );
                            }
                        }

                        return;
                    }

                    Some(event) = event_rx.recv() => {
                        // Process the first event.
                        if let Some(buf) = buffer.load() {
                            AggregatedSink::process_event(&buf, &event, &dimensions);

                            // Drain up to BATCH_SIZE-1 more events without blocking.
                            for _ in 0..BATCH_SIZE - 1 {
                                match event_rx.try_recv() {
                                    Ok(event) => {
                                        AggregatedSink::process_event(
                                            &buf, &event, &dimensions,
                                        );
                                    }
                                    Err(_) => break,
                                }
                            }
                        }
                    }

                    Some(rotated_buf) = rotation_rx.recv() => {
                        reusable_batch.metadata.updated_time = SystemTime::now();
                        collector.collect_into(&rotated_buf, &mut reusable_batch);
                        flush_controller.force_flush_all(&mut reusable_batch);
                        if !reusable_batch.is_empty() {
                            for exporter in &exporters {
                                if let Err(e) = exporter.export(&reusable_batch).await {
                                    tracing::error!(
                                        exporter = exporter.name(),
                                        error = %e,
                                        "slot-aligned export failed",
                                    );
                                }
                            }
                            tracing::debug!(
                                latency = reusable_batch.latency.len(),
                                counter = reusable_batch.counter.len(),
                                gauge = reusable_batch.gauge.len(),
                                cpu_util = reusable_batch.cpu_util.len(),
                                memory_usage = reusable_batch.memory_usage.len(),
                                "slot-aligned buffer flushed"
                            );
                        }
                    }

                    _ = ticker.tick() => {
                        let now = SystemTime::now();
                        let slot = state.current_slot.load(Ordering::Relaxed);
                        let new_buf = AggregatedSink::new_buffer_from_state(
                            &state, now, slot,
                        );

                        if let Some(old_buf) = buffer.swap(new_buf) {
                            reusable_batch.metadata.updated_time = SystemTime::now();
                            collector.collect_into(&old_buf, &mut reusable_batch);
                            flush_controller.process_tick(&mut reusable_batch);
                            if !reusable_batch.is_empty() {
                                for exporter in &exporters {
                                    if let Err(e) = exporter.export(&reusable_batch).await {
                                        tracing::error!(
                                            exporter = exporter.name(),
                                            error = %e,
                                            "export failed",
                                        );
                                    }
                                }
                                tracing::debug!(
                                    latency = reusable_batch.latency.len(),
                                    counter = reusable_batch.counter.len(),
                                    gauge = reusable_batch.gauge.len(),
                                    cpu_util = reusable_batch.cpu_util.len(),
                                    memory_usage = reusable_batch.memory_usage.len(),
                                    "buffer flushed"
                                );
                            }
                        }
                    }

                    _ = sync_state_ticker.tick() => {
                        let now = SystemTime::now();
                        let row = AggregatedSink::new_sync_state_row(&state, now);
                        let meta = BatchMetadata {
                            client_name: Arc::clone(&meta_client_name),
                            network_name: Arc::clone(&meta_network_name),
                            updated_time: now,
                        };

                        for exporter in &exporters {
                            if let Err(e) = exporter.export_sync_state(&row, &meta).await {
                                tracing::error!(
                                    exporter = exporter.name(),
                                    error = %e,
                                    "sync state export failed",
                                );
                            }
                        }
                    }
                }
            }
        });
        *self.run_task.lock().await = Some(run_task);

        info!(
            interval = ?self.cfg.resolution.interval,
            slot_aligned = self.cfg.resolution.slot_aligned,
            tier_overrides = self.cfg.resolution.overrides.len(),
            "aggregated sink started"
        );

        Ok(())
    }

    async fn stop(&mut self) -> Result<()> {
        // Final flush handled in the spawned task via cancellation token.
        Ok(())
    }

    fn handle_event(&self, event: ParsedEvent) {
        if self.event_tx.try_send(event).is_err() {
            warn!("aggregated sink event channel full, dropping event");
        }
    }

    fn on_slot_changed(&self, new_slot: u64, slot_start: SystemTime) {
        self.state.current_slot.store(new_slot, Ordering::Relaxed);
        let nanos = slot_start
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as i64;
        self.state
            .current_slot_start
            .store(nanos, Ordering::Relaxed);

        if self.cfg.resolution.slot_aligned {
            let now = SystemTime::now();
            let new_buf = Self::new_buffer_from_state(&self.state, now, new_slot);
            if let Some(old_buf) = self.buffer.swap(new_buf) {
                if self.rotation_tx.send(old_buf).is_err() {
                    warn!(
                        slot = new_slot,
                        "slot-aligned buffer rotation queue closed, dropping flush"
                    );
                } else {
                    tracing::debug!(slot = new_slot, "slot-aligned buffer rotation");
                }
            }
        }
    }

    fn set_sync_state(&self, status: SyncStatus) {
        self.state
            .cl_syncing
            .store(u32::from(status.is_syncing), Ordering::Relaxed);
        self.state
            .el_optimistic
            .store(u32::from(status.is_optimistic), Ordering::Relaxed);
        self.state
            .el_offline
            .store(u32::from(status.el_offline), Ordering::Relaxed);
    }
}

fn parse_cpu_online() -> u32 {
    let Ok(raw) = std::fs::read_to_string("/sys/devices/system/cpu/online") else {
        return 0;
    };
    parse_cpu_online_text(raw.trim()).unwrap_or(0)
}

fn parse_cpu_online_text(text: &str) -> Option<u32> {
    if text.is_empty() {
        return None;
    }

    let mut total = 0u32;
    for part in text.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }

        if let Some((start, end)) = part.split_once('-') {
            let start = start.trim().parse::<u32>().ok()?;
            let end = end.trim().parse::<u32>().ok()?;
            if end < start {
                return None;
            }
            total = total.saturating_add(end.saturating_sub(start).saturating_add(1));
        } else {
            let _ = part.parse::<u32>().ok()?;
            total = total.saturating_add(1);
        }
    }

    if total == 0 {
        None
    } else {
        Some(total)
    }
}

// --- Dimension builder helpers ---

/// Creates a NetworkDimension based on config.
fn build_network_dimension(
    pid: u32,
    client_type: u8,
    e: &NetIOEvent,
    dims: &DimensionsConfig,
) -> NetworkDimension {
    let mut dim = NetworkDimension {
        pid,
        client_type,
        port_label: 0,
        direction: 0,
    };

    if dims.network.include_direction {
        dim.direction = e.direction as u8;
    }

    if dims.network.include_port {
        let port = local_port(e);
        dim.port_label = dims.network.resolve_port_label(port);
    }

    dim
}

/// Creates a NetworkDimension for TCP retransmit events.
fn build_network_dimension_from_tcp_retransmit(
    pid: u32,
    client_type: u8,
    src_port: u16,
    dims: &DimensionsConfig,
) -> NetworkDimension {
    let mut dim = NetworkDimension {
        pid,
        client_type,
        port_label: 0,
        direction: 0, // Retransmits are always TX.
    };

    if dims.network.include_port {
        dim.port_label = dims.network.resolve_port_label(src_port);
    }

    dim
}

/// Creates a TCPMetricsDimension from a merged NetIOEvent.
fn build_tcp_metrics_dim_from_net_io(
    pid: u32,
    client_type: u8,
    e: &NetIOEvent,
    dims: &DimensionsConfig,
) -> TCPMetricsDimension {
    let mut dim = TCPMetricsDimension {
        pid,
        client_type,
        port_label: 0,
    };

    if dims.network.include_port {
        let port = local_port(e);
        dim.port_label = dims.network.resolve_port_label(port);
    }

    dim
}

/// Creates a DiskDimension based on config.
fn build_disk_dimension(
    pid: u32,
    client_type: u8,
    device_id: u32,
    rw: u8,
    dims: &DimensionsConfig,
) -> DiskDimension {
    let mut dim = DiskDimension {
        pid,
        client_type,
        device_id: 0,
        rw: 0,
    };

    if dims.disk.include_device {
        dim.device_id = device_id;
    }

    if dims.disk.include_rw {
        dim.rw = rw;
    }

    dim
}

/// Extracts the local port from a network event.
/// For TX (outbound), source is local. For RX (inbound), dest is local.
fn local_port(e: &NetIOEvent) -> u16 {
    if e.direction == Direction::TX {
        e.src_port
    } else {
        e.dst_port
    }
}

/// Atomic buffer wrapper using `Arc<Buffer>` with lock-free swap.
mod atomic_buffer {
    use arc_swap::ArcSwapOption;
    use std::sync::Arc;

    use super::Buffer;

    /// Thread-safe atomic buffer holder.
    /// Uses lock-free atomic loads/swaps for the hot event-processing path.
    pub struct AtomicBuffer {
        inner: ArcSwapOption<Buffer>,
    }

    impl AtomicBuffer {
        pub fn new() -> Self {
            Self {
                inner: ArcSwapOption::empty(),
            }
        }

        /// Stores a new buffer.
        pub fn store(&self, buf: Buffer) {
            self.inner.store(Some(Arc::new(buf)));
        }

        /// Loads the current buffer, returning a clone of the Arc.
        pub fn load(&self) -> Option<Arc<Buffer>> {
            self.inner.load_full()
        }

        /// Swaps in a new buffer, returning the old one.
        pub fn swap(&self, new_buf: Buffer) -> Option<Arc<Buffer>> {
            self.inner.swap(Some(Arc::new(new_buf)))
        }

        /// Takes the buffer out, leaving None.
        pub fn take(&self) -> Option<Arc<Buffer>> {
            self.inner.swap(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tracer::event::*;

    fn make_event(event_type: EventType, typed: TypedEvent) -> ParsedEvent {
        ParsedEvent {
            raw: Event {
                timestamp_ns: 0,
                pid: 123,
                tid: 123,
                event_type,
                client_type: ClientType::Geth,
            },
            typed,
        }
    }

    #[test]
    fn test_process_event_syscall() {
        let buf = Buffer::new(
            SystemTime::now(),
            0,
            SystemTime::now(),
            false,
            false,
            false,
            8,
        );
        let dims = DimensionsConfig::default();

        let event = make_event(
            EventType::SyscallRead,
            TypedEvent::Syscall(SyscallEvent {
                event: Event {
                    timestamp_ns: 0,
                    pid: 123,
                    tid: 123,
                    event_type: EventType::SyscallRead,
                    client_type: ClientType::Geth,
                },
                latency_ns: 5_000,
                ret: 0,
                syscall_nr: 0,
                fd: 0,
            }),
        );

        AggregatedSink::process_event(&buf, &event, &dims);

        let dim = BasicDimension {
            pid: 123,
            client_type: 1,
        };
        let entry = buf.syscall_read.get(&dim).expect("entry exists");
        assert_eq!(entry.snapshot().count, 1);
    }

    #[test]
    fn test_process_event_net_io() {
        let buf = Buffer::new(
            SystemTime::now(),
            0,
            SystemTime::now(),
            false,
            false,
            false,
            8,
        );
        let dims = DimensionsConfig::default();

        let event = make_event(
            EventType::NetTX,
            TypedEvent::NetIO(NetIOEvent {
                event: Event {
                    timestamp_ns: 0,
                    pid: 123,
                    tid: 123,
                    event_type: EventType::NetTX,
                    client_type: ClientType::Geth,
                },
                bytes: 1024,
                src_port: 8545,
                dst_port: 30303,
                direction: Direction::TX,
                has_metrics: true,
                srtt_us: 100,
                cwnd: 65535,
            }),
        );

        AggregatedSink::process_event(&buf, &event, &dims);

        // Check net_io was recorded.
        assert!(!buf.net_io.is_empty());

        // Check TCP metrics were recorded (has_metrics = true).
        assert!(!buf.tcp_rtt.is_empty());
        assert!(!buf.tcp_cwnd.is_empty());
    }

    #[test]
    fn test_process_event_disk_io() {
        let buf = Buffer::new(
            SystemTime::now(),
            0,
            SystemTime::now(),
            false,
            false,
            false,
            8,
        );
        let dims = DimensionsConfig::default();

        let event = make_event(
            EventType::DiskIO,
            TypedEvent::DiskIO(DiskIOEvent {
                event: Event {
                    timestamp_ns: 0,
                    pid: 123,
                    tid: 123,
                    event_type: EventType::DiskIO,
                    client_type: ClientType::Geth,
                },
                latency_ns: 50_000,
                bytes: 4096,
                rw: 1,
                queue_depth: 3,
                device_id: 259,
            }),
        );

        AggregatedSink::process_event(&buf, &event, &dims);

        assert!(!buf.disk_latency.is_empty());
        assert!(!buf.disk_bytes.is_empty());
        assert!(!buf.disk_queue_depth.is_empty());
    }

    #[test]
    fn test_process_event_fd_open_close() {
        let buf = Buffer::new(
            SystemTime::now(),
            0,
            SystemTime::now(),
            false,
            false,
            false,
            8,
        );
        let dims = DimensionsConfig::default();

        let open_event = make_event(
            EventType::FDOpen,
            TypedEvent::FD(FDEvent {
                event: Event {
                    timestamp_ns: 0,
                    pid: 123,
                    tid: 123,
                    event_type: EventType::FDOpen,
                    client_type: ClientType::Geth,
                },
                fd: 5,
                filename: "/tmp/test".to_string(),
            }),
        );

        let close_event = make_event(
            EventType::FDClose,
            TypedEvent::FD(FDEvent {
                event: Event {
                    timestamp_ns: 0,
                    pid: 123,
                    tid: 123,
                    event_type: EventType::FDClose,
                    client_type: ClientType::Geth,
                },
                fd: 5,
                filename: String::new(),
            }),
        );

        AggregatedSink::process_event(&buf, &open_event, &dims);
        AggregatedSink::process_event(&buf, &close_event, &dims);

        assert!(!buf.fd_open.is_empty());
        assert!(!buf.fd_close.is_empty());
    }

    #[test]
    fn test_process_event_all_types() {
        let buf = Buffer::new(
            SystemTime::now(),
            0,
            SystemTime::now(),
            false,
            false,
            false,
            8,
        );
        let dims = DimensionsConfig::default();

        // Sched switch
        let event = make_event(
            EventType::SchedSwitch,
            TypedEvent::Sched(SchedEvent {
                event: Event {
                    timestamp_ns: 0,
                    pid: 123,
                    tid: 123,
                    event_type: EventType::SchedSwitch,
                    client_type: ClientType::Geth,
                },
                on_cpu_ns: 1_000_000,
                voluntary: true,
                cpu_id: 3,
            }),
        );
        AggregatedSink::process_event(&buf, &event, &dims);
        assert!(!buf.sched_on_cpu.is_empty());
        assert!(!buf.cpu_on_core.is_empty());

        // Page fault
        let event = make_event(
            EventType::PageFault,
            TypedEvent::PageFault(PageFaultEvent {
                event: Event {
                    timestamp_ns: 0,
                    pid: 123,
                    tid: 123,
                    event_type: EventType::PageFault,
                    client_type: ClientType::Geth,
                },
                address: 0xdeadbeef,
                major: true,
            }),
        );
        AggregatedSink::process_event(&buf, &event, &dims);
        assert!(!buf.page_fault_major.is_empty());

        // OOM kill
        let event = make_event(
            EventType::OOMKill,
            TypedEvent::OOMKill(OOMKillEvent {
                event: Event {
                    timestamp_ns: 0,
                    pid: 123,
                    tid: 123,
                    event_type: EventType::OOMKill,
                    client_type: ClientType::Geth,
                },
                target_pid: 456,
            }),
        );
        AggregatedSink::process_event(&buf, &event, &dims);
        assert!(!buf.oom_kill.is_empty());

        // Process exit
        let event = make_event(
            EventType::ProcessExit,
            TypedEvent::ProcessExit(ProcessExitEvent {
                event: Event {
                    timestamp_ns: 0,
                    pid: 123,
                    tid: 123,
                    event_type: EventType::ProcessExit,
                    client_type: ClientType::Geth,
                },
                exit_code: 0,
            }),
        );
        AggregatedSink::process_event(&buf, &event, &dims);
        assert!(!buf.process_exit.is_empty());

        // Mem reclaim
        let event = make_event(
            EventType::MemReclaim,
            TypedEvent::MemLatency(MemLatencyEvent {
                event: Event {
                    timestamp_ns: 0,
                    pid: 123,
                    tid: 123,
                    event_type: EventType::MemReclaim,
                    client_type: ClientType::Geth,
                },
                duration_ns: 5_000,
            }),
        );
        AggregatedSink::process_event(&buf, &event, &dims);
        assert!(!buf.mem_reclaim.is_empty());

        // Swap in
        let event = make_event(
            EventType::SwapIn,
            TypedEvent::Swap(SwapEvent {
                event: Event {
                    timestamp_ns: 0,
                    pid: 123,
                    tid: 123,
                    event_type: EventType::SwapIn,
                    client_type: ClientType::Geth,
                },
                pages: 1,
            }),
        );
        AggregatedSink::process_event(&buf, &event, &dims);
        assert!(!buf.swap_in.is_empty());

        // TCP state
        let event = make_event(
            EventType::TcpState,
            TypedEvent::TcpState(TcpStateEvent {
                event: Event {
                    timestamp_ns: 0,
                    pid: 123,
                    tid: 123,
                    event_type: EventType::TcpState,
                    client_type: ClientType::Geth,
                },
                src_port: 8545,
                dst_port: 30303,
                new_state: 1,
                old_state: 0,
            }),
        );
        AggregatedSink::process_event(&buf, &event, &dims);
        assert!(!buf.tcp_state_change.is_empty());
    }

    #[test]
    fn test_local_port_tx_vs_rx() {
        let tx_event = NetIOEvent {
            event: Event {
                timestamp_ns: 0,
                pid: 1,
                tid: 1,
                event_type: EventType::NetTX,
                client_type: ClientType::Geth,
            },
            bytes: 100,
            src_port: 8545,
            dst_port: 30303,
            direction: Direction::TX,
            has_metrics: false,
            srtt_us: 0,
            cwnd: 0,
        };
        assert_eq!(local_port(&tx_event), 8545);

        let rx_event = NetIOEvent {
            event: Event {
                timestamp_ns: 0,
                pid: 1,
                tid: 1,
                event_type: EventType::NetRX,
                client_type: ClientType::Geth,
            },
            bytes: 100,
            src_port: 30303,
            dst_port: 8545,
            direction: Direction::RX,
            has_metrics: false,
            srtt_us: 0,
            cwnd: 0,
        };
        assert_eq!(local_port(&rx_event), 8545);
    }

    #[test]
    fn test_set_sync_state() {
        let cfg = AggregatedSinkConfig::default();
        let sink = AggregatedSink::new(cfg, "test".to_string(), "testnet".to_string());

        let status = SyncStatus {
            is_syncing: true,
            head_slot: 100,
            sync_distance: 10,
            is_optimistic: true,
            el_offline: false,
        };
        sink.set_sync_state(status);

        assert_eq!(sink.state.cl_syncing.load(Ordering::Relaxed), 1);
        assert_eq!(sink.state.el_optimistic.load(Ordering::Relaxed), 1);
        assert_eq!(sink.state.el_offline.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_dimension_builders_with_disabled_dimensions() {
        let mut dims = DimensionsConfig::default();
        dims.network.include_port = false;
        dims.network.include_direction = false;
        dims.disk.include_device = false;
        dims.disk.include_rw = false;

        let net_event = NetIOEvent {
            event: Event {
                timestamp_ns: 0,
                pid: 1,
                tid: 1,
                event_type: EventType::NetTX,
                client_type: ClientType::Geth,
            },
            bytes: 100,
            src_port: 8545,
            dst_port: 30303,
            direction: Direction::TX,
            has_metrics: false,
            srtt_us: 0,
            cwnd: 0,
        };

        let net_dim = build_network_dimension(1, 1, &net_event, &dims);
        assert_eq!(net_dim.port_label, 0);
        assert_eq!(net_dim.direction, 0);

        let disk_dim = build_disk_dimension(1, 1, 259, 1, &dims);
        assert_eq!(disk_dim.device_id, 0);
        assert_eq!(disk_dim.rw, 0);
    }

    #[test]
    fn test_parse_cpu_online_text() {
        assert_eq!(parse_cpu_online_text("0"), Some(1));
        assert_eq!(parse_cpu_online_text("0-3"), Some(4));
        assert_eq!(parse_cpu_online_text("0-3,8-11"), Some(8));
        assert_eq!(parse_cpu_online_text("0,2,4"), Some(3));
        assert_eq!(parse_cpu_online_text(""), None);
        assert_eq!(parse_cpu_online_text("3-1"), None);
        assert_eq!(parse_cpu_online_text("abc"), None);
    }
}
