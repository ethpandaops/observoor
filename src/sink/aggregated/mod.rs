pub mod aggregate;
pub mod buffer;
pub mod collector;
pub mod config;
pub mod dimension;
pub mod exporter;
pub mod flush;
pub mod histogram;
pub mod host_specs;
pub mod metric;

pub mod clickhouse;
pub mod http;

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use anyhow::Result;
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::beacon::SyncStatus;
use crate::config::{AggregatedSinkConfig, DimensionsConfig};
use crate::sink::Sink;
use crate::tracer::event::{
    ClientType, Direction, EventType, NetIOEvent, NetTransport, ParsedEvent, TypedEvent,
};

use self::buffer::Buffer;
use self::clickhouse::{HostSpecsRow, SyncStateRow};
use self::collector::Collector;
use self::dimension::{BasicDimension, DiskDimension, NetworkDimension, TCPMetricsDimension};
use self::exporter::Exporter;
use self::flush::TieredFlushController;
use self::host_specs::collect_host_specs;
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

#[derive(Clone, Copy)]
struct SlotRotation {
    new_slot: u64,
    slot_start: SystemTime,
}

#[derive(Clone, Copy, Debug)]
struct RunningThread {
    pid: u32,
    client_type: u8,
    cpu_id: u32,
    running_since_ns: u64,
}

#[derive(Default)]
struct SchedulerWindowState {
    running_by_tid: HashMap<u32, RunningThread>,
}

impl SchedulerWindowState {
    fn flush_running_to_boundary(&mut self, buf: &Buffer, boundary_ns: u64) {
        for running in self.running_by_tid.values_mut() {
            if boundary_ns <= running.running_since_ns {
                continue;
            }
            let delta_ns = boundary_ns - running.running_since_ns;
            buf.add_cpu_on_core(
                BasicDimension {
                    pid: running.pid,
                    client_type: running.client_type,
                },
                running.cpu_id,
                delta_ns,
            );
            running.running_since_ns = boundary_ns;
        }
    }

    fn handle_sched_switch(&mut self, buf: &Buffer, event: &ParsedEvent) {
        let TypedEvent::Sched(sched) = &event.typed else {
            return;
        };

        let dim = BasicDimension {
            pid: event.raw.pid,
            client_type: event.raw.client_type as u8,
        };
        buf.add_sched_on_cpu(dim, sched.on_cpu_ns);

        let timestamp_ns = event.raw.timestamp_ns;
        let tid = event.raw.tid;
        if let Some(running) = self.running_by_tid.get(&tid).copied() {
            if timestamp_ns > running.running_since_ns {
                buf.add_cpu_on_core(
                    BasicDimension {
                        pid: running.pid,
                        client_type: running.client_type,
                    },
                    running.cpu_id,
                    timestamp_ns - running.running_since_ns,
                );
                self.running_by_tid.remove(&tid);
                return;
            }

            // Zero-length runtime for this slice; consume the running state.
            if timestamp_ns == running.running_since_ns {
                self.running_by_tid.remove(&tid);
                return;
            }

            // Out-of-order switch-out for an older slice. Keep newer running state
            // and still account this event via raw fallback.
            buf.add_cpu_on_core(dim, sched.cpu_id, sched.on_cpu_ns);
            return;
        }

        // Fallback for missing switch-in state (startup, drops): use kernel-reported slice.
        buf.add_cpu_on_core(dim, sched.cpu_id, sched.on_cpu_ns);
    }

    fn handle_sched_runqueue(&mut self, buf: &Buffer, event: &ParsedEvent) {
        let TypedEvent::SchedRunqueue(rq) = &event.typed else {
            return;
        };

        let dim = BasicDimension {
            pid: event.raw.pid,
            client_type: event.raw.client_type as u8,
        };
        buf.add_sched_runqueue(dim, rq.runqueue_ns, rq.off_cpu_ns);

        let timestamp_ns = event.raw.timestamp_ns;
        let tid = event.raw.tid;
        if let Some(prev) = self.running_by_tid.get_mut(&tid) {
            if timestamp_ns > prev.running_since_ns {
                buf.add_cpu_on_core(
                    BasicDimension {
                        pid: prev.pid,
                        client_type: prev.client_type,
                    },
                    prev.cpu_id,
                    timestamp_ns - prev.running_since_ns,
                );
            }
            // Only move state forward (or replace at same instant).
            if timestamp_ns >= prev.running_since_ns {
                *prev = RunningThread {
                    pid: event.raw.pid,
                    client_type: event.raw.client_type as u8,
                    cpu_id: rq.cpu_id,
                    running_since_ns: timestamp_ns,
                };
            }
            return;
        }

        self.running_by_tid.insert(
            tid,
            RunningThread {
                pid: event.raw.pid,
                client_type: event.raw.client_type as u8,
                cpu_id: rq.cpu_id,
                running_since_ns: timestamp_ns,
            },
        );
    }

    fn handle_process_exit(&mut self, buf: &Buffer, event: &ParsedEvent) {
        let tid = event.raw.tid;
        let timestamp_ns = event.raw.timestamp_ns;
        if let Some(running) = self.running_by_tid.get(&tid).copied() {
            if timestamp_ns > running.running_since_ns {
                buf.add_cpu_on_core(
                    BasicDimension {
                        pid: running.pid,
                        client_type: running.client_type,
                    },
                    running.cpu_id,
                    timestamp_ns - running.running_since_ns,
                );
            }

            if timestamp_ns >= running.running_since_ns {
                self.running_by_tid.remove(&tid);
            }
        }
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

    /// Queue of slot changes consumed by the run loop.
    slot_rotation_tx: mpsc::UnboundedSender<SlotRotation>,
    /// Slot change receiver, taken by `start`.
    slot_rotation_rx: Option<mpsc::UnboundedReceiver<SlotRotation>>,

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
        let (slot_rotation_tx, slot_rotation_rx) = mpsc::unbounded_channel();

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
            slot_rotation_tx,
            slot_rotation_rx: Some(slot_rotation_rx),
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
    pub fn set_port_label_map(&mut self, map: crate::agent::ports::PortLabelMap) {
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

    /// Builds a host-specs row from current shared state and machine snapshot.
    fn new_host_specs_row(state: &SharedState, now: SystemTime) -> HostSpecsRow {
        let snapshot = collect_host_specs();

        HostSpecsRow {
            updated_date_time: now,
            event_time: now,
            wallclock_slot: u32::try_from(state.current_slot.load(Ordering::Relaxed))
                .unwrap_or(u32::MAX),
            wallclock_slot_start_date_time: state.slot_start_time(),
            host_id: snapshot.host_id,
            kernel_release: snapshot.kernel_release,
            os_name: snapshot.os_name,
            architecture: snapshot.architecture,
            cpu_model: snapshot.cpu_model,
            cpu_vendor: snapshot.cpu_vendor,
            cpu_online_cores: snapshot.cpu_online_cores,
            cpu_logical_cores: snapshot.cpu_logical_cores,
            cpu_physical_cores: snapshot.cpu_physical_cores,
            cpu_performance_cores: snapshot.cpu_performance_cores,
            cpu_efficiency_cores: snapshot.cpu_efficiency_cores,
            cpu_unknown_type_cores: snapshot.cpu_unknown_type_cores,
            cpu_logical_ids: snapshot.cpu_logical_ids,
            cpu_core_ids: snapshot.cpu_core_ids,
            cpu_package_ids: snapshot.cpu_package_ids,
            cpu_die_ids: snapshot.cpu_die_ids,
            cpu_cluster_ids: snapshot.cpu_cluster_ids,
            cpu_core_types: snapshot.cpu_core_types,
            cpu_core_type_labels: snapshot.cpu_core_type_labels,
            cpu_online_flags: snapshot.cpu_online_flags,
            cpu_max_freq_khz: snapshot.cpu_max_freq_khz,
            cpu_base_freq_khz: snapshot.cpu_base_freq_khz,
            memory_total_bytes: snapshot.memory_total_bytes,
            memory_type: snapshot.memory_type,
            memory_speed_mts: snapshot.memory_speed_mts,
            memory_dimm_count: snapshot.memory_dimm_count,
            memory_dimm_sizes_bytes: snapshot.memory_dimm_sizes_bytes,
            memory_dimm_types: snapshot.memory_dimm_types,
            memory_dimm_speeds_mts: snapshot.memory_dimm_speeds_mts,
            memory_dimm_configured_speeds_mts: snapshot.memory_dimm_configured_speeds_mts,
            memory_dimm_locators: snapshot.memory_dimm_locators,
            memory_dimm_bank_locators: snapshot.memory_dimm_bank_locators,
            memory_dimm_manufacturers: snapshot.memory_dimm_manufacturers,
            memory_dimm_part_numbers: snapshot.memory_dimm_part_numbers,
            memory_dimm_serials: snapshot.memory_dimm_serials,
            disk_count: snapshot.disk_count,
            disk_total_bytes: snapshot.disk_total_bytes,
            disk_names: snapshot.disk_names,
            disk_models: snapshot.disk_models,
            disk_vendors: snapshot.disk_vendors,
            disk_serials: snapshot.disk_serials,
            disk_sizes_bytes: snapshot.disk_sizes_bytes,
            disk_rotational: snapshot.disk_rotational,
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

                // Inline metrics are valid only for TCP net_tx events.
                if e.has_metrics && e.transport == NetTransport::Tcp {
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
                    e.dst_port,
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

    /// Routes a parsed event while maintaining carried scheduler state for
    /// exact per-core window accounting across buffer rotations.
    fn process_event_with_scheduler_state(
        buf: &Buffer,
        event: &ParsedEvent,
        dimensions: &DimensionsConfig,
        scheduler_state: &mut SchedulerWindowState,
    ) {
        let basic_dim = BasicDimension {
            pid: event.raw.pid,
            client_type: event.raw.client_type as u8,
        };

        match &event.typed {
            TypedEvent::Sched(_) => {
                scheduler_state.handle_sched_switch(buf, event);
            }

            TypedEvent::SchedRunqueue(_) => {
                scheduler_state.handle_sched_runqueue(buf, event);
            }

            TypedEvent::ProcessExit(_) => {
                buf.add_process_exit(basic_dim);
                scheduler_state.handle_process_exit(buf, event);
            }

            _ => Self::process_event(buf, event, dimensions),
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
        let mut slot_rotation_rx = self
            .slot_rotation_rx
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
        let host_specs_interval = self.cfg.resolution.host_specs_poll_interval;
        let resolution_overrides = self.cfg.resolution.overrides.clone();
        let sampling_cfg = self.cfg.sampling.clone();
        let collector = Collector::new_with_process_snapshots(interval, &sampling_cfg, true);
        let mut flush_controller = TieredFlushController::new(interval, &resolution_overrides);
        let meta_client_name = Arc::clone(&self.meta_client_name);
        let meta_network_name = Arc::clone(&self.meta_network_name);
        let rotation_tx = self.rotation_tx.clone();
        let slot_aligned = self.cfg.resolution.slot_aligned;

        let run_task = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut sync_state_ticker = tokio::time::interval(sync_state_interval);
            sync_state_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut host_specs_ticker = tokio::time::interval(host_specs_interval);
            host_specs_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
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
                #[cfg(feature = "bpf")]
                memory_usage: Vec::new(),
                #[cfg(feature = "bpf")]
                process_io_usage: Vec::new(),
                #[cfg(feature = "bpf")]
                process_fd_usage: Vec::new(),
                #[cfg(feature = "bpf")]
                process_sched_usage: Vec::new(),
            };
            let mut scheduler_state = SchedulerWindowState::default();

            const BATCH_SIZE: usize = 256;

            // Emit host specs once on startup, then on the configured ticker.
            {
                let now = SystemTime::now();
                let row = AggregatedSink::new_host_specs_row(&state, now);
                let meta = BatchMetadata {
                    client_name: Arc::clone(&meta_client_name),
                    network_name: Arc::clone(&meta_network_name),
                    updated_time: now,
                };

                for exporter in &exporters {
                    if let Err(e) = exporter.export_host_specs(&row, &meta).await {
                        tracing::error!(
                            exporter = exporter.name(),
                            error = %e,
                            "startup host specs export failed",
                        );
                    }
                }
            }
            // Consume the immediate first tick after startup export.
            host_specs_ticker.tick().await;

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
                            scheduler_state.flush_running_to_boundary(&final_buf, monotonic_ns());
                            reusable_batch.metadata.updated_time = SystemTime::now();
                            collector.collect_into(&final_buf, &mut reusable_batch);
                            flush_controller.force_flush_all(&mut reusable_batch);
                            if !reusable_batch.is_empty() {
                                #[cfg(feature = "bpf")]
                                let memory_usage = reusable_batch.memory_usage.len();
                                #[cfg(not(feature = "bpf"))]
                                let memory_usage = 0usize;
                                #[cfg(feature = "bpf")]
                                let process_io_usage = reusable_batch.process_io_usage.len();
                                #[cfg(not(feature = "bpf"))]
                                let process_io_usage = 0usize;
                                #[cfg(feature = "bpf")]
                                let process_fd_usage = reusable_batch.process_fd_usage.len();
                                #[cfg(not(feature = "bpf"))]
                                let process_fd_usage = 0usize;
                                #[cfg(feature = "bpf")]
                                let process_sched_usage = reusable_batch.process_sched_usage.len();
                                #[cfg(not(feature = "bpf"))]
                                let process_sched_usage = 0usize;
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
                                    memory_usage,
                                    process_io_usage,
                                    process_fd_usage,
                                    process_sched_usage,
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
                            AggregatedSink::process_event_with_scheduler_state(
                                &buf,
                                &event,
                                &dimensions,
                                &mut scheduler_state,
                            );

                            // Drain up to BATCH_SIZE-1 more events without blocking.
                            for _ in 0..BATCH_SIZE - 1 {
                                match event_rx.try_recv() {
                                    Ok(event) => {
                                        AggregatedSink::process_event_with_scheduler_state(
                                            &buf,
                                            &event,
                                            &dimensions,
                                            &mut scheduler_state,
                                        );
                                    }
                                    Err(_) => break,
                                }
                            }
                        }
                    }

                    Some(rotation) = slot_rotation_rx.recv() => {
                        state.current_slot.store(rotation.new_slot, Ordering::Relaxed);
                        let nanos = rotation
                            .slot_start
                            .duration_since(SystemTime::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_nanos() as i64;
                        state.current_slot_start.store(nanos, Ordering::Relaxed);

                        if slot_aligned {
                            // keep slot-aligned rotation behavior in run loop so scheduler carry
                            // can be applied exactly at the boundary.
                            if let Some(old_buf) = buffer.swap(AggregatedSink::new_buffer_from_state(
                                &state,
                                SystemTime::now(),
                                rotation.new_slot,
                            )) {
                                scheduler_state.flush_running_to_boundary(&old_buf, monotonic_ns());
                                if rotation_tx.send(old_buf).is_err() {
                                    warn!(
                                        slot = rotation.new_slot,
                                        "slot-aligned buffer rotation queue closed, dropping flush"
                                    );
                                } else {
                                    tracing::debug!(slot = rotation.new_slot, "slot-aligned buffer rotation");
                                }
                            }
                        }
                    }

                    Some(rotated_buf) = rotation_rx.recv() => {
                        reusable_batch.metadata.updated_time = SystemTime::now();
                        collector.collect_into(&rotated_buf, &mut reusable_batch);
                        flush_controller.force_flush_all(&mut reusable_batch);
                        if !reusable_batch.is_empty() {
                            #[cfg(feature = "bpf")]
                            let memory_usage = reusable_batch.memory_usage.len();
                            #[cfg(not(feature = "bpf"))]
                            let memory_usage = 0usize;
                            #[cfg(feature = "bpf")]
                            let process_io_usage = reusable_batch.process_io_usage.len();
                            #[cfg(not(feature = "bpf"))]
                            let process_io_usage = 0usize;
                            #[cfg(feature = "bpf")]
                            let process_fd_usage = reusable_batch.process_fd_usage.len();
                            #[cfg(not(feature = "bpf"))]
                            let process_fd_usage = 0usize;
                            #[cfg(feature = "bpf")]
                            let process_sched_usage = reusable_batch.process_sched_usage.len();
                            #[cfg(not(feature = "bpf"))]
                            let process_sched_usage = 0usize;
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
                                memory_usage,
                                process_io_usage,
                                process_fd_usage,
                                process_sched_usage,
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
                            scheduler_state.flush_running_to_boundary(&old_buf, monotonic_ns());
                            reusable_batch.metadata.updated_time = SystemTime::now();
                            collector.collect_into(&old_buf, &mut reusable_batch);
                            flush_controller.process_tick(&mut reusable_batch);
                            if !reusable_batch.is_empty() {
                                #[cfg(feature = "bpf")]
                                let memory_usage = reusable_batch.memory_usage.len();
                                #[cfg(not(feature = "bpf"))]
                                let memory_usage = 0usize;
                                #[cfg(feature = "bpf")]
                                let process_io_usage = reusable_batch.process_io_usage.len();
                                #[cfg(not(feature = "bpf"))]
                                let process_io_usage = 0usize;
                                #[cfg(feature = "bpf")]
                                let process_fd_usage = reusable_batch.process_fd_usage.len();
                                #[cfg(not(feature = "bpf"))]
                                let process_fd_usage = 0usize;
                                #[cfg(feature = "bpf")]
                                let process_sched_usage = reusable_batch.process_sched_usage.len();
                                #[cfg(not(feature = "bpf"))]
                                let process_sched_usage = 0usize;
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
                                    memory_usage,
                                    process_io_usage,
                                    process_fd_usage,
                                    process_sched_usage,
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

                    _ = host_specs_ticker.tick() => {
                        let now = SystemTime::now();
                        let row = AggregatedSink::new_host_specs_row(&state, now);
                        let meta = BatchMetadata {
                            client_name: Arc::clone(&meta_client_name),
                            network_name: Arc::clone(&meta_network_name),
                            updated_time: now,
                        };

                        for exporter in &exporters {
                            if let Err(e) = exporter.export_host_specs(&row, &meta).await {
                                tracing::error!(
                                    exporter = exporter.name(),
                                    error = %e,
                                    "host specs export failed",
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
            host_specs_interval = ?self.cfg.resolution.host_specs_poll_interval,
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

        if self.cfg.resolution.slot_aligned
            && self
                .slot_rotation_tx
                .send(SlotRotation {
                    new_slot,
                    slot_start,
                })
                .is_err()
        {
            warn!(
                slot = new_slot,
                "slot-aligned rotation queue closed, dropping rotation"
            );
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
        let client = ClientType::from_u8(client_type).unwrap_or(ClientType::Unknown);
        let local = local_port(e);
        let remote = remote_port(e);
        dim.port_label = match e.transport {
            NetTransport::Tcp => dims.network.resolve_tcp_port_label(client, local, remote),
            NetTransport::Udp => dims.network.resolve_udp_port_label(client, local, remote),
        };
    }

    dim
}

/// Creates a NetworkDimension for TCP retransmit events.
fn build_network_dimension_from_tcp_retransmit(
    pid: u32,
    client_type: u8,
    src_port: u16,
    dst_port: u16,
    dims: &DimensionsConfig,
) -> NetworkDimension {
    let mut dim = NetworkDimension {
        pid,
        client_type,
        port_label: 0,
        direction: 0, // Retransmits are always TX.
    };

    if dims.network.include_port {
        let client = ClientType::from_u8(client_type).unwrap_or(ClientType::Unknown);
        // Retransmits are TCP-only by definition.
        dim.port_label = dims
            .network
            .resolve_tcp_port_label(client, src_port, dst_port);
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
        let client = ClientType::from_u8(client_type).unwrap_or(ClientType::Unknown);
        let local = local_port(e);
        let remote = remote_port(e);
        // Inline TCP metrics are only attached to net_tx TCP probes.
        dim.port_label = dims.network.resolve_tcp_port_label(client, local, remote);
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

/// Extracts the peer/remote port from a network event.
fn remote_port(e: &NetIOEvent) -> u16 {
    if e.direction == Direction::TX {
        e.dst_port
    } else {
        e.src_port
    }
}

/// Returns current monotonic clock value in nanoseconds.
fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `clock_gettime(CLOCK_MONOTONIC, ...)` is thread-safe and does not
    // require any Rust-side invariants besides a valid pointer.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) } == 0 {
        (ts.tv_sec as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add(ts.tv_nsec as u64)
    } else {
        0
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
    use crate::agent::ports::{PortLabel, PortLabelMap};
    use crate::sink::aggregated::dimension::CpuCoreDimension;
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

    fn make_event_at(
        timestamp_ns: u64,
        pid: u32,
        tid: u32,
        event_type: EventType,
        typed: TypedEvent,
    ) -> ParsedEvent {
        ParsedEvent {
            raw: Event {
                timestamp_ns,
                pid,
                tid,
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
                transport: NetTransport::Tcp,
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
    fn test_scheduler_state_carries_running_thread_across_boundaries() {
        let dims = DimensionsConfig::default();
        let mut scheduler_state = SchedulerWindowState::default();

        let buf1 = Buffer::new(
            SystemTime::now(),
            0,
            SystemTime::now(),
            false,
            false,
            false,
            8,
        );

        let rq_event = make_event_at(
            1_000,
            123,
            77,
            EventType::SchedRunqueue,
            TypedEvent::SchedRunqueue(SchedRunqueueEvent {
                event: Event {
                    timestamp_ns: 1_000,
                    pid: 123,
                    tid: 77,
                    event_type: EventType::SchedRunqueue,
                    client_type: ClientType::Geth,
                },
                runqueue_ns: 50,
                off_cpu_ns: 100,
                cpu_id: 2,
            }),
        );

        AggregatedSink::process_event_with_scheduler_state(
            &buf1,
            &rq_event,
            &dims,
            &mut scheduler_state,
        );
        scheduler_state.flush_running_to_boundary(&buf1, 1_500);

        let core1 = buf1
            .cpu_on_core
            .get(&CpuCoreDimension {
                pid: 123,
                client_type: 1,
                cpu_id: 2,
            })
            .expect("core usage in first buffer");
        assert_eq!(core1.snapshot().sum, 500);

        let rq = buf1
            .sched_runqueue
            .get(&BasicDimension {
                pid: 123,
                client_type: 1,
            })
            .expect("runqueue metric");
        assert_eq!(rq.snapshot().sum, 50);

        let buf2 = Buffer::new(
            SystemTime::now(),
            0,
            SystemTime::now(),
            false,
            false,
            false,
            8,
        );
        scheduler_state.flush_running_to_boundary(&buf2, 1_900);

        let core2 = buf2
            .cpu_on_core
            .get(&CpuCoreDimension {
                pid: 123,
                client_type: 1,
                cpu_id: 2,
            })
            .expect("core usage carried into second buffer");
        assert_eq!(core2.snapshot().sum, 400);
    }

    #[test]
    fn test_scheduler_state_switch_out_uses_carried_start() {
        let dims = DimensionsConfig::default();
        let mut scheduler_state = SchedulerWindowState::default();

        let buf1 = Buffer::new(
            SystemTime::now(),
            0,
            SystemTime::now(),
            false,
            false,
            false,
            8,
        );

        let rq_event = make_event_at(
            10_000,
            123,
            88,
            EventType::SchedRunqueue,
            TypedEvent::SchedRunqueue(SchedRunqueueEvent {
                event: Event {
                    timestamp_ns: 10_000,
                    pid: 123,
                    tid: 88,
                    event_type: EventType::SchedRunqueue,
                    client_type: ClientType::Geth,
                },
                runqueue_ns: 0,
                off_cpu_ns: 0,
                cpu_id: 3,
            }),
        );
        AggregatedSink::process_event_with_scheduler_state(
            &buf1,
            &rq_event,
            &dims,
            &mut scheduler_state,
        );
        scheduler_state.flush_running_to_boundary(&buf1, 10_500);

        let buf2 = Buffer::new(
            SystemTime::now(),
            0,
            SystemTime::now(),
            false,
            false,
            false,
            8,
        );
        let switch_event = make_event_at(
            11_000,
            123,
            88,
            EventType::SchedSwitch,
            TypedEvent::Sched(SchedEvent {
                event: Event {
                    timestamp_ns: 11_000,
                    pid: 123,
                    tid: 88,
                    event_type: EventType::SchedSwitch,
                    client_type: ClientType::Geth,
                },
                on_cpu_ns: 2_000,
                voluntary: false,
                cpu_id: 3,
            }),
        );
        AggregatedSink::process_event_with_scheduler_state(
            &buf2,
            &switch_event,
            &dims,
            &mut scheduler_state,
        );

        let core2 = buf2
            .cpu_on_core
            .get(&CpuCoreDimension {
                pid: 123,
                client_type: 1,
                cpu_id: 3,
            })
            .expect("core usage on switch-out");
        // Uses carried state (11_000 - 10_500), not the raw 2_000ns slice.
        assert_eq!(core2.snapshot().sum, 500);

        let on_cpu = buf2
            .sched_on_cpu
            .get(&BasicDimension {
                pid: 123,
                client_type: 1,
            })
            .expect("sched_on_cpu recorded");
        // Latency distribution remains raw from sched_switch payload.
        assert_eq!(on_cpu.snapshot().sum, 2_000);
    }

    #[test]
    fn test_scheduler_state_fallback_without_switch_in_uses_raw_slice() {
        let dims = DimensionsConfig::default();
        let mut scheduler_state = SchedulerWindowState::default();

        let buf = Buffer::new(
            SystemTime::now(),
            0,
            SystemTime::now(),
            false,
            false,
            false,
            8,
        );
        let switch_event = make_event_at(
            2_000,
            123,
            99,
            EventType::SchedSwitch,
            TypedEvent::Sched(SchedEvent {
                event: Event {
                    timestamp_ns: 2_000,
                    pid: 123,
                    tid: 99,
                    event_type: EventType::SchedSwitch,
                    client_type: ClientType::Geth,
                },
                on_cpu_ns: 700,
                voluntary: true,
                cpu_id: 1,
            }),
        );
        AggregatedSink::process_event_with_scheduler_state(
            &buf,
            &switch_event,
            &dims,
            &mut scheduler_state,
        );

        let core = buf
            .cpu_on_core
            .get(&CpuCoreDimension {
                pid: 123,
                client_type: 1,
                cpu_id: 1,
            })
            .expect("fallback core usage");
        assert_eq!(core.snapshot().sum, 700);
    }

    #[test]
    fn test_scheduler_state_process_exit_accounts_tail_once() {
        let dims = DimensionsConfig::default();
        let mut scheduler_state = SchedulerWindowState::default();

        let buf = Buffer::new(
            SystemTime::now(),
            0,
            SystemTime::now(),
            false,
            false,
            false,
            8,
        );

        let rq_event = make_event_at(
            1_000,
            123,
            50,
            EventType::SchedRunqueue,
            TypedEvent::SchedRunqueue(SchedRunqueueEvent {
                event: Event {
                    timestamp_ns: 1_000,
                    pid: 123,
                    tid: 50,
                    event_type: EventType::SchedRunqueue,
                    client_type: ClientType::Geth,
                },
                runqueue_ns: 0,
                off_cpu_ns: 0,
                cpu_id: 4,
            }),
        );
        AggregatedSink::process_event_with_scheduler_state(
            &buf,
            &rq_event,
            &dims,
            &mut scheduler_state,
        );

        scheduler_state.flush_running_to_boundary(&buf, 1_300);

        let exit_event = make_event_at(
            1_500,
            123,
            50,
            EventType::ProcessExit,
            TypedEvent::ProcessExit(ProcessExitEvent {
                event: Event {
                    timestamp_ns: 1_500,
                    pid: 123,
                    tid: 50,
                    event_type: EventType::ProcessExit,
                    client_type: ClientType::Geth,
                },
                exit_code: 0,
            }),
        );
        AggregatedSink::process_event_with_scheduler_state(
            &buf,
            &exit_event,
            &dims,
            &mut scheduler_state,
        );
        scheduler_state.flush_running_to_boundary(&buf, 2_000);

        let core = buf
            .cpu_on_core
            .get(&CpuCoreDimension {
                pid: 123,
                client_type: 1,
                cpu_id: 4,
            })
            .expect("process-exit accounted runtime");
        assert_eq!(core.snapshot().sum, 500);
        assert!(scheduler_state.running_by_tid.is_empty());
    }

    #[test]
    fn test_scheduler_state_newer_switch_in_reattributes_previous_core() {
        let dims = DimensionsConfig::default();
        let mut scheduler_state = SchedulerWindowState::default();

        let buf = Buffer::new(
            SystemTime::now(),
            0,
            SystemTime::now(),
            false,
            false,
            false,
            8,
        );

        let rq1 = make_event_at(
            1_000,
            123,
            60,
            EventType::SchedRunqueue,
            TypedEvent::SchedRunqueue(SchedRunqueueEvent {
                event: Event {
                    timestamp_ns: 1_000,
                    pid: 123,
                    tid: 60,
                    event_type: EventType::SchedRunqueue,
                    client_type: ClientType::Geth,
                },
                runqueue_ns: 1,
                off_cpu_ns: 1,
                cpu_id: 1,
            }),
        );
        let rq2 = make_event_at(
            1_300,
            123,
            60,
            EventType::SchedRunqueue,
            TypedEvent::SchedRunqueue(SchedRunqueueEvent {
                event: Event {
                    timestamp_ns: 1_300,
                    pid: 123,
                    tid: 60,
                    event_type: EventType::SchedRunqueue,
                    client_type: ClientType::Geth,
                },
                runqueue_ns: 1,
                off_cpu_ns: 1,
                cpu_id: 3,
            }),
        );

        AggregatedSink::process_event_with_scheduler_state(&buf, &rq1, &dims, &mut scheduler_state);
        AggregatedSink::process_event_with_scheduler_state(&buf, &rq2, &dims, &mut scheduler_state);
        scheduler_state.flush_running_to_boundary(&buf, 1_500);

        let core1 = buf
            .cpu_on_core
            .get(&CpuCoreDimension {
                pid: 123,
                client_type: 1,
                cpu_id: 1,
            })
            .expect("first core usage");
        assert_eq!(core1.snapshot().sum, 300);

        let core3 = buf
            .cpu_on_core
            .get(&CpuCoreDimension {
                pid: 123,
                client_type: 1,
                cpu_id: 3,
            })
            .expect("second core usage");
        assert_eq!(core3.snapshot().sum, 200);
    }

    #[test]
    fn test_scheduler_state_stale_events_do_not_rewind_or_drop_running_state() {
        let dims = DimensionsConfig::default();
        let mut scheduler_state = SchedulerWindowState::default();

        let buf = Buffer::new(
            SystemTime::now(),
            0,
            SystemTime::now(),
            false,
            false,
            false,
            8,
        );

        let rq = make_event_at(
            1_000,
            123,
            70,
            EventType::SchedRunqueue,
            TypedEvent::SchedRunqueue(SchedRunqueueEvent {
                event: Event {
                    timestamp_ns: 1_000,
                    pid: 123,
                    tid: 70,
                    event_type: EventType::SchedRunqueue,
                    client_type: ClientType::Geth,
                },
                runqueue_ns: 10,
                off_cpu_ns: 20,
                cpu_id: 2,
            }),
        );
        let stale_rq = make_event_at(
            900,
            123,
            70,
            EventType::SchedRunqueue,
            TypedEvent::SchedRunqueue(SchedRunqueueEvent {
                event: Event {
                    timestamp_ns: 900,
                    pid: 123,
                    tid: 70,
                    event_type: EventType::SchedRunqueue,
                    client_type: ClientType::Geth,
                },
                runqueue_ns: 15,
                off_cpu_ns: 25,
                cpu_id: 4,
            }),
        );
        let stale_switch = make_event_at(
            950,
            123,
            70,
            EventType::SchedSwitch,
            TypedEvent::Sched(SchedEvent {
                event: Event {
                    timestamp_ns: 950,
                    pid: 123,
                    tid: 70,
                    event_type: EventType::SchedSwitch,
                    client_type: ClientType::Geth,
                },
                on_cpu_ns: 50,
                voluntary: false,
                cpu_id: 1,
            }),
        );
        let stale_exit = make_event_at(
            980,
            123,
            70,
            EventType::ProcessExit,
            TypedEvent::ProcessExit(ProcessExitEvent {
                event: Event {
                    timestamp_ns: 980,
                    pid: 123,
                    tid: 70,
                    event_type: EventType::ProcessExit,
                    client_type: ClientType::Geth,
                },
                exit_code: 0,
            }),
        );

        AggregatedSink::process_event_with_scheduler_state(&buf, &rq, &dims, &mut scheduler_state);
        AggregatedSink::process_event_with_scheduler_state(
            &buf,
            &stale_rq,
            &dims,
            &mut scheduler_state,
        );
        AggregatedSink::process_event_with_scheduler_state(
            &buf,
            &stale_switch,
            &dims,
            &mut scheduler_state,
        );
        AggregatedSink::process_event_with_scheduler_state(
            &buf,
            &stale_exit,
            &dims,
            &mut scheduler_state,
        );
        scheduler_state.flush_running_to_boundary(&buf, 1_200);

        let carried_core = buf
            .cpu_on_core
            .get(&CpuCoreDimension {
                pid: 123,
                client_type: 1,
                cpu_id: 2,
            })
            .expect("carried running core usage");
        assert_eq!(carried_core.snapshot().sum, 200);

        let fallback_core = buf
            .cpu_on_core
            .get(&CpuCoreDimension {
                pid: 123,
                client_type: 1,
                cpu_id: 1,
            })
            .expect("stale switch fallback usage");
        assert_eq!(fallback_core.snapshot().sum, 50);
        assert!(scheduler_state.running_by_tid.contains_key(&70));
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
            transport: NetTransport::Tcp,
            has_metrics: false,
            srtt_us: 0,
            cwnd: 0,
        };
        assert_eq!(local_port(&tx_event), 8545);
        assert_eq!(remote_port(&tx_event), 30303);

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
            transport: NetTransport::Tcp,
            has_metrics: false,
            srtt_us: 0,
            cwnd: 0,
        };
        assert_eq!(local_port(&rx_event), 8545);
        assert_eq!(remote_port(&rx_event), 30303);
    }

    #[test]
    fn test_network_dimension_resolves_peer_port_when_local_is_ephemeral() {
        let mut dims = DimensionsConfig::default();
        let mut map = PortLabelMap::default();
        map.insert(ClientType::Prysm, 13000, PortLabel::ClP2PTcp);
        dims.network.set_port_label_map(map);

        let net_event = NetIOEvent {
            event: Event {
                timestamp_ns: 0,
                pid: 1,
                tid: 1,
                event_type: EventType::NetTX,
                client_type: ClientType::Prysm,
            },
            bytes: 100,
            src_port: 45432,
            dst_port: 13000,
            direction: Direction::TX,
            transport: NetTransport::Tcp,
            has_metrics: false,
            srtt_us: 0,
            cwnd: 0,
        };

        let net_dim = build_network_dimension(1, ClientType::Prysm as u8, &net_event, &dims);
        assert_eq!(net_dim.port_label, PortLabel::ClP2PTcp as u8);
    }

    #[test]
    fn test_network_dimension_uses_tcp_label_for_shared_port() {
        let mut dims = DimensionsConfig::default();
        let mut map = PortLabelMap::default();
        map.insert(ClientType::Prysm, 13000, PortLabel::ClP2PTcp);
        map.insert(ClientType::Prysm, 13000, PortLabel::ClDiscovery);
        dims.network.set_port_label_map(map);

        let net_event = NetIOEvent {
            event: Event {
                timestamp_ns: 0,
                pid: 1,
                tid: 1,
                event_type: EventType::NetRX,
                client_type: ClientType::Prysm,
            },
            bytes: 100,
            src_port: 13000,
            dst_port: 13000,
            direction: Direction::RX,
            transport: NetTransport::Tcp,
            has_metrics: false,
            srtt_us: 0,
            cwnd: 0,
        };

        let net_dim = build_network_dimension(1, ClientType::Prysm as u8, &net_event, &dims);
        assert_eq!(net_dim.port_label, PortLabel::ClP2PTcp as u8);

        let retransmit_dim = build_network_dimension_from_tcp_retransmit(
            1,
            ClientType::Prysm as u8,
            45432,
            13000,
            &dims,
        );
        assert_eq!(retransmit_dim.port_label, PortLabel::ClP2PTcp as u8);
    }

    #[test]
    fn test_network_dimension_uses_udp_label_for_shared_port() {
        let mut dims = DimensionsConfig::default();
        let mut map = PortLabelMap::default();
        map.insert(ClientType::Prysm, 13000, PortLabel::ClP2PTcp);
        map.insert(ClientType::Prysm, 13000, PortLabel::ClDiscovery);
        dims.network.set_port_label_map(map);

        let net_event = NetIOEvent {
            event: Event {
                timestamp_ns: 0,
                pid: 1,
                tid: 1,
                event_type: EventType::NetRX,
                client_type: ClientType::Prysm,
            },
            bytes: 100,
            src_port: 13000,
            dst_port: 13000,
            direction: Direction::RX,
            transport: NetTransport::Udp,
            has_metrics: false,
            srtt_us: 0,
            cwnd: 0,
        };

        let net_dim = build_network_dimension(1, ClientType::Prysm as u8, &net_event, &dims);
        assert_eq!(net_dim.port_label, PortLabel::ClDiscovery as u8);
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
            transport: NetTransport::Tcp,
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
