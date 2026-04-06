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

use std::sync::atomic::{AtomicI64, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use anyhow::Result;
use smallvec::SmallVec;
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::beacon::SyncStatus;
use crate::config::{AggregatedSinkConfig, DimensionsConfig};
use crate::sink::Sink;
use crate::tracer::event::{Direction, NetIOEvent, NetTransport, ParsedEvent, TypedEvent};
use crate::tracer::{ParsedEventBatch, PARSED_EVENT_BATCH_SIZE};

use self::buffer::Buffer;
use self::clickhouse::{HostSpecsRow, SyncStateRow};
use self::collector::Collector;
use self::dimension::{BasicDimension, DiskDimension, NetworkDimension, TCPMetricsDimension};
use self::exporter::Exporter;
use self::flush::TieredFlushController;
use self::host_specs::collect_host_specs;
use self::metric::{BatchMetadata, MetricBatch};

type EventBatch = ParsedEventBatch;

/// Parsed events are queued in fixed-size batches to amortize channel overhead
/// across the tracer -> sink handoff.
const EVENT_BATCH_SIZE: usize = PARSED_EVENT_BATCH_SIZE;
/// Keep roughly a 65,536-event queue depth, but in batch units.
const EVENT_BATCH_CHANNEL_CAPACITY: usize = 4;
/// Drain a full bounded queue per wake to amortize `mpsc`/`select!` overhead
/// under sustained tracer load without letting the event loop run unbounded.
const EVENT_BATCHES_PER_WAKE: usize = EVENT_BATCH_CHANNEL_CAPACITY;
const PORT_LABEL_CACHE_SIZE: usize = 16;
const RUNNING_CPU_INLINE_CAPACITY: usize = 16;
const SCHED_TID_CACHE_SIZE: usize = 32;
const SCHED_TID_CACHE_WAYS: usize = 2;

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
    // Scheduler events close and flush the same running slice repeatedly, so
    // keep the resolved process dimension alongside the owning CPU id.
    basic_dim: BasicDimension,
    running_since_ns: u64,
    tid: u32,
    cpu_id: u32,
}

#[derive(Default)]
struct RunningThreadStore {
    // Active running state is naturally bounded by CPU count. Store one slot
    // per observed CPU so sched_switch can resolve state by cpu_id directly.
    entries: SmallVec<[Option<RunningThread>; RUNNING_CPU_INLINE_CAPACITY]>,
}

impl RunningThreadStore {
    #[inline(always)]
    fn with_capacity(capacity: usize) -> Self {
        Self {
            entries: SmallVec::with_capacity(capacity.min(RUNNING_CPU_INLINE_CAPACITY)),
        }
    }

    #[inline(always)]
    fn ensure_cpu_slot(&mut self, cpu_id: u32) {
        let slot = cpu_id as usize;
        while self.entries.len() <= slot {
            self.entries.push(None);
        }
    }

    #[inline(always)]
    fn cpu_slot_mut(&mut self, cpu_id: u32) -> &mut Option<RunningThread> {
        self.ensure_cpu_slot(cpu_id);
        // Safety: `ensure_cpu_slot` grows `entries` until `cpu_id` is in range.
        unsafe { self.entries.get_unchecked_mut(cpu_id as usize) }
    }

    #[inline(always)]
    fn take_cpu(&mut self, cpu_id: u32) -> Option<RunningThread> {
        if let Some(slot) = self.entries.get_mut(cpu_id as usize) {
            slot.take()
        } else {
            None
        }
    }

    #[inline(always)]
    fn find_cpu_for_tid(&self, tid: u32) -> Option<u32> {
        let len = self.entries.len();
        let mut cpu_id = 0usize;
        while cpu_id < len {
            // Safety: `cpu_id` stays strictly below `len`.
            if unsafe { self.entries.get_unchecked(cpu_id) }
                .is_some_and(|running| running.tid == tid)
            {
                return Some(cpu_id as u32);
            }
            cpu_id += 1;
        }

        None
    }

    #[inline(always)]
    fn cpu_matches_tid(&self, cpu_id: u32, tid: u32) -> bool {
        if let Some(Some(running)) = self.entries.get(cpu_id as usize) {
            running.tid == tid
        } else {
            false
        }
    }

    #[inline(always)]
    fn iter_mut(&mut self) -> impl Iterator<Item = &mut RunningThread> {
        self.entries.iter_mut().filter_map(Option::as_mut)
    }

    #[cfg(test)]
    #[inline(always)]
    fn is_empty(&self) -> bool {
        self.entries.iter().all(Option::is_none)
    }

    #[cfg(test)]
    #[inline(always)]
    fn contains_tid(&self, tid: u32) -> bool {
        self.find_cpu_for_tid(tid).is_some()
    }
}

#[derive(Clone, Copy)]
struct SchedTidCacheEntry {
    tid: u32,
    cpu_id: u32,
}

type SchedTidCacheSet = [Option<SchedTidCacheEntry>; SCHED_TID_CACHE_WAYS];

#[inline(always)]
fn sched_tid_cache_slot(tid: u32) -> usize {
    ((tid ^ tid.rotate_left(11)) as usize) & (SCHED_TID_CACHE_SIZE - 1)
}

struct SchedulerWindowState {
    running_by_cpu: RunningThreadStore,
    // The live set is bounded by active CPUs, so keep the no-hash direct cache
    // but allow two colliding tids per bucket before falling back to a scan.
    tid_to_cpu_cache: [SchedTidCacheSet; SCHED_TID_CACHE_SIZE],
}

impl Default for SchedulerWindowState {
    fn default() -> Self {
        Self {
            running_by_cpu: RunningThreadStore::with_capacity(64),
            tid_to_cpu_cache: [[None; SCHED_TID_CACHE_WAYS]; SCHED_TID_CACHE_SIZE],
        }
    }
}

#[derive(Clone, Copy)]
struct PortLabelCacheEntry {
    key: u64,
    label: u8,
}

struct PortLabelResolveCache {
    entries: [Option<PortLabelCacheEntry>; PORT_LABEL_CACHE_SIZE],
}

impl Default for PortLabelResolveCache {
    fn default() -> Self {
        Self {
            entries: [None; PORT_LABEL_CACHE_SIZE],
        }
    }
}

impl PortLabelResolveCache {
    #[inline(always)]
    fn resolve(
        &mut self,
        port_label_map: &crate::agent::ports::PortLabelMap,
        client_type: u8,
        transport: u8,
        primary_port: u16,
        secondary_port: u16,
    ) -> u8 {
        let key = pack_port_label_cache_key(client_type, transport, primary_port, secondary_port);
        let slot = port_label_cache_slot(key);

        if let Some(entry) = self.entries[slot] {
            if entry.key == key {
                return entry.label;
            }
        }

        let label = match transport {
            transport if transport == NetTransport::Tcp as u8 => {
                port_label_map.resolve_tcp_raw(client_type, primary_port, secondary_port) as u8
            }
            _ => port_label_map.resolve_udp_raw(client_type, primary_port, secondary_port) as u8,
        };

        self.entries[slot] = Some(PortLabelCacheEntry { key, label });
        label
    }
}

#[inline(always)]
fn pack_port_label_cache_key(
    client_type: u8,
    transport: u8,
    primary_port: u16,
    secondary_port: u16,
) -> u64 {
    u64::from(primary_port)
        | (u64::from(secondary_port) << 16)
        | (u64::from(client_type) << 32)
        | (u64::from(transport) << 40)
}

#[inline(always)]
fn port_label_cache_slot(key: u64) -> usize {
    ((key ^ key.rotate_left(25)) as usize) & (PORT_LABEL_CACHE_SIZE - 1)
}

// Resolve immutable dimension toggles once so ingest only branches on event data.
#[derive(Clone, Copy)]
struct ResolvedDimensions<'a> {
    network_direction_mask: u8,
    network_port_label_map: Option<&'a crate::agent::ports::PortLabelMap>,
    disk_device_mask: u32,
    disk_rw_mask: u8,
}

impl<'a> ResolvedDimensions<'a> {
    #[inline(always)]
    fn from_config(dims: &'a DimensionsConfig) -> Self {
        Self {
            network_direction_mask: if dims.network.include_direction {
                u8::MAX
            } else {
                0
            },
            network_port_label_map: if dims.network.include_port {
                dims.network.port_label_map.as_ref()
            } else {
                None
            },
            disk_device_mask: if dims.disk.include_device {
                u32::MAX
            } else {
                0
            },
            disk_rw_mask: if dims.disk.include_rw { u8::MAX } else { 0 },
        }
    }
}

impl SchedulerWindowState {
    #[inline(always)]
    fn find_cpu_for_tid(&mut self, tid: u32) -> Option<u32> {
        let cache_slot = sched_tid_cache_slot(tid);

        for entry in self.tid_to_cpu_cache[cache_slot].into_iter().flatten() {
            if entry.tid == tid && self.running_by_cpu.cpu_matches_tid(entry.cpu_id, tid) {
                return Some(entry.cpu_id);
            }
        }

        let Some(cpu_id) = self.running_by_cpu.find_cpu_for_tid(tid) else {
            self.clear_cached_tid_cpu(tid);
            return None;
        };

        self.remember_tid_cpu(tid, cpu_id);
        Some(cpu_id)
    }

    #[inline(always)]
    fn remember_tid_cpu(&mut self, tid: u32, cpu_id: u32) {
        let entry = Some(SchedTidCacheEntry { tid, cpu_id });
        let cache_set = &mut self.tid_to_cpu_cache[sched_tid_cache_slot(tid)];

        for slot in cache_set.iter_mut() {
            if slot.is_some_and(|cached| cached.tid == tid) {
                *slot = entry;
                return;
            }
        }

        for slot in cache_set.iter_mut() {
            if slot.is_none() {
                *slot = entry;
                return;
            }
        }

        cache_set[0] = entry;
    }

    #[inline(always)]
    fn clear_cached_tid_cpu(&mut self, tid: u32) {
        for slot in &mut self.tid_to_cpu_cache[sched_tid_cache_slot(tid)] {
            if slot.is_some_and(|entry| entry.tid == tid) {
                *slot = None;
            }
        }
    }

    #[inline(always)]
    fn forget_tid_cpu(&mut self, tid: u32) {
        self.clear_cached_tid_cpu(tid);
    }

    #[inline(always)]
    fn take_running_on_cpu(&mut self, cpu_id: u32) -> Option<RunningThread> {
        let running = self.running_by_cpu.take_cpu(cpu_id);
        if let Some(running) = running {
            self.forget_tid_cpu(running.tid);
        }
        running
    }

    #[inline(always)]
    fn restore_running(&mut self, running: RunningThread) {
        *self.running_by_cpu.cpu_slot_mut(running.cpu_id) = Some(running);
        self.remember_tid_cpu(running.tid, running.cpu_id);
    }

    #[inline(always)]
    fn flush_running_to_boundary(&mut self, buf: &mut Buffer, boundary_ns: u64) {
        for running in self.running_by_cpu.iter_mut() {
            if boundary_ns <= running.running_since_ns {
                continue;
            }
            let delta_ns = boundary_ns - running.running_since_ns;
            buf.add_cpu_on_core(running.basic_dim, running.cpu_id, delta_ns);
            running.running_since_ns = boundary_ns;
        }
    }

    #[inline(always)]
    fn handle_sched_switch(
        &mut self,
        buf: &mut Buffer,
        tid: u32,
        timestamp_ns: u64,
        dim: BasicDimension,
        on_cpu_ns: u64,
        cpu_id: u32,
    ) {
        let mut resolved_on_cpu_ns = Some(on_cpu_ns);

        if let Some(running) = self.take_running_on_cpu(cpu_id) {
            if running.tid == tid {
                if timestamp_ns > running.running_since_ns {
                    resolved_on_cpu_ns = Some(timestamp_ns - running.running_since_ns);
                } else if timestamp_ns == running.running_since_ns {
                    resolved_on_cpu_ns = None;
                }
            } else {
                self.restore_running(running);
            }
        }

        if let Some(resolved_on_cpu_ns) = resolved_on_cpu_ns {
            // Fallback for missing switch-in state (startup, drops, or stale events):
            // use the kernel-reported slice.
            buf.add_sched_slice(dim, cpu_id, on_cpu_ns, resolved_on_cpu_ns);
        } else {
            // Zero-length runtime for this slice; consume the running state.
            buf.add_sched_on_cpu(dim, cpu_id, on_cpu_ns);
        }
    }

    #[inline(always)]
    fn handle_sched_runqueue(
        &mut self,
        buf: &mut Buffer,
        tid: u32,
        timestamp_ns: u64,
        dim: BasicDimension,
        runqueue_ns: u64,
        off_cpu_ns: u64,
        cpu_id: u32,
    ) {
        buf.add_sched_runqueue(dim, runqueue_ns, off_cpu_ns);

        let next_running = RunningThread {
            tid,
            basic_dim: dim,
            cpu_id,
            running_since_ns: timestamp_ns,
        };

        let cpu_index = cpu_id as usize;
        let mut reused_target_slot = false;

        if let Some(prev_cpu) = self.find_cpu_for_tid(tid) {
            let prev = self
                .take_running_on_cpu(prev_cpu)
                .expect("find_cpu_for_tid must point to an occupied slot");
            if timestamp_ns > prev.running_since_ns {
                buf.add_cpu_on_core(
                    prev.basic_dim,
                    prev.cpu_id,
                    timestamp_ns - prev.running_since_ns,
                );
            } else if timestamp_ns < prev.running_since_ns {
                self.restore_running(prev);
                return;
            }

            reused_target_slot = prev_cpu as usize == cpu_index;
        }

        if !reused_target_slot {
            if let Some(prev) = self.take_running_on_cpu(cpu_id) {
                if timestamp_ns > prev.running_since_ns {
                    buf.add_cpu_on_core(
                        prev.basic_dim,
                        prev.cpu_id,
                        timestamp_ns - prev.running_since_ns,
                    );
                } else if timestamp_ns < prev.running_since_ns {
                    self.restore_running(prev);
                    return;
                }
            }
        }

        self.restore_running(next_running);
    }

    #[inline(always)]
    fn handle_sched_combined(
        &mut self,
        buf: &mut Buffer,
        prev_tid: u32,
        next_tid: u32,
        timestamp_ns: u64,
        prev_dim: BasicDimension,
        next_dim: BasicDimension,
        on_cpu_ns: u64,
        runqueue_ns: u64,
        off_cpu_ns: u64,
        cpu_id: u32,
    ) {
        buf.add_sched_runqueue(next_dim, runqueue_ns, off_cpu_ns);
        let mut resolved_prev_on_cpu_ns = Some(on_cpu_ns);

        let next_running = RunningThread {
            tid: next_tid,
            basic_dim: next_dim,
            cpu_id,
            running_since_ns: timestamp_ns,
        };

        let mut current_cpu_running = self.take_running_on_cpu(cpu_id);

        match current_cpu_running {
            Some(running) if running.tid == prev_tid => {
                if timestamp_ns > running.running_since_ns {
                    resolved_prev_on_cpu_ns = Some(timestamp_ns - running.running_since_ns);
                } else if timestamp_ns == running.running_since_ns {
                    resolved_prev_on_cpu_ns = None;
                } else if timestamp_ns < running.running_since_ns {
                    // Match `handle_sched_switch` fallback behavior for stale
                    // carried state on the outgoing thread.
                    resolved_prev_on_cpu_ns = Some(on_cpu_ns);
                }
                current_cpu_running = None;
            }
            Some(running) => {
                resolved_prev_on_cpu_ns = Some(on_cpu_ns);
                current_cpu_running = Some(running);
            }
            None => {
                resolved_prev_on_cpu_ns = Some(on_cpu_ns);
            }
        }

        if let Some(resolved_prev_on_cpu_ns) = resolved_prev_on_cpu_ns {
            buf.add_sched_slice(prev_dim, cpu_id, on_cpu_ns, resolved_prev_on_cpu_ns);
        } else {
            buf.add_sched_on_cpu(prev_dim, cpu_id, on_cpu_ns);
        }

        if let Some(running) = current_cpu_running.take() {
            if running.tid == next_tid {
                if timestamp_ns > running.running_since_ns {
                    buf.add_cpu_on_core(
                        running.basic_dim,
                        running.cpu_id,
                        timestamp_ns - running.running_since_ns,
                    );
                } else if timestamp_ns < running.running_since_ns {
                    self.restore_running(running);
                    return;
                }
            } else {
                current_cpu_running = Some(running);
            }
        }

        if current_cpu_running.is_some_and(|running| running.tid != next_tid) {
            if let Some(prev_cpu) = self.find_cpu_for_tid(next_tid) {
                let prev = self
                    .take_running_on_cpu(prev_cpu)
                    .expect("find_cpu_for_tid must point to an occupied slot");
                if timestamp_ns > prev.running_since_ns {
                    buf.add_cpu_on_core(
                        prev.basic_dim,
                        prev.cpu_id,
                        timestamp_ns - prev.running_since_ns,
                    );
                } else if timestamp_ns < prev.running_since_ns {
                    self.restore_running(prev);
                    if let Some(running) = current_cpu_running {
                        self.restore_running(running);
                    }
                    return;
                }
            }
        } else if current_cpu_running.is_none() {
            if let Some(prev_cpu) = self.find_cpu_for_tid(next_tid) {
                let prev = self
                    .take_running_on_cpu(prev_cpu)
                    .expect("find_cpu_for_tid must point to an occupied slot");
                if timestamp_ns > prev.running_since_ns {
                    buf.add_cpu_on_core(
                        prev.basic_dim,
                        prev.cpu_id,
                        timestamp_ns - prev.running_since_ns,
                    );
                } else if timestamp_ns < prev.running_since_ns {
                    self.restore_running(prev);
                    return;
                }
            }
        }

        if let Some(prev) = current_cpu_running {
            if timestamp_ns > prev.running_since_ns {
                buf.add_cpu_on_core(
                    prev.basic_dim,
                    prev.cpu_id,
                    timestamp_ns - prev.running_since_ns,
                );
            } else if timestamp_ns < prev.running_since_ns {
                self.restore_running(prev);
                return;
            }
        }

        self.restore_running(next_running);
    }

    fn handle_process_exit(&mut self, buf: &mut Buffer, tid: u32, timestamp_ns: u64) {
        if let Some(cpu_id) = self.find_cpu_for_tid(tid) {
            let running = self
                .take_running_on_cpu(cpu_id)
                .expect("find_cpu_for_tid must point to an occupied slot");
            if timestamp_ns > running.running_since_ns {
                buf.add_cpu_on_core(
                    running.basic_dim,
                    running.cpu_id,
                    timestamp_ns - running.running_since_ns,
                );
            }
            if timestamp_ns < running.running_since_ns {
                self.restore_running(running);
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
    exporters: Vec<Exporter>,

    /// Event-batch channel sender for the processing loop.
    event_tx: mpsc::Sender<EventBatch>,
    /// Event-batch channel receiver, taken by `start`.
    event_rx: Option<mpsc::Receiver<EventBatch>>,

    /// Queue of slot-rotation buffers waiting to be flushed.
    rotation_tx: mpsc::UnboundedSender<Buffer>,
    /// Queue receiver, taken by `start`.
    rotation_rx: Option<mpsc::UnboundedReceiver<Buffer>>,

    /// Queue of slot changes consumed by the run loop.
    slot_rotation_tx: mpsc::UnboundedSender<SlotRotation>,
    /// Slot change receiver, taken by `start`.
    slot_rotation_rx: Option<mpsc::UnboundedReceiver<SlotRotation>>,

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
        let (event_tx, event_rx) = mpsc::channel(EVENT_BATCH_CHANNEL_CAPACITY);
        let (rotation_tx, rotation_rx) = mpsc::unbounded_channel();
        let (slot_rotation_tx, slot_rotation_rx) = mpsc::unbounded_channel();

        Self {
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

    /// Resets a reusable buffer for the next aggregation window while preserving allocations.
    fn reset_buffer_from_state(state: &SharedState, buf: &mut Buffer, now: SystemTime, slot: u64) {
        let system_cores =
            u16::try_from(state.system_cores.load(Ordering::Relaxed)).unwrap_or(u16::MAX);
        buf.reset(
            now,
            slot,
            state.slot_start_time(),
            state.cl_syncing.load(Ordering::Relaxed) == 1,
            state.el_optimistic.load(Ordering::Relaxed) == 1,
            state.el_offline.load(Ordering::Relaxed) == 1,
            system_cores,
        );
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

    #[inline(always)]
    fn process_event_inner<
        const WITH_SCHEDULER_STATE: bool,
        const WITH_NETWORK_PORT_LABELS: bool,
    >(
        buf: &mut Buffer,
        event: &ParsedEvent,
        dimensions: &ResolvedDimensions<'_>,
        scheduler_state: &mut SchedulerWindowState,
        port_label_cache: &mut PortLabelResolveCache,
    ) {
        let basic_dim = BasicDimension::from_packed(event.raw.basic_dimension_key());

        match &event.typed {
            TypedEvent::SyscallRead(e) => {
                buf.add_syscall_read(basic_dim, e.latency_ns);
            }

            TypedEvent::SyscallWrite(e) => {
                buf.add_syscall_write(basic_dim, e.latency_ns);
            }

            TypedEvent::SyscallFutex(e) => {
                buf.add_syscall_futex(basic_dim, e.latency_ns);
            }

            TypedEvent::SyscallMmap(e) => {
                buf.add_syscall_mmap(basic_dim, e.latency_ns);
            }

            TypedEvent::SyscallEpollWait(e) => {
                buf.add_syscall_epoll_wait(basic_dim, e.latency_ns);
            }

            TypedEvent::SyscallFsync(e) => {
                buf.add_syscall_fsync(basic_dim, e.latency_ns);
            }

            TypedEvent::SyscallFdatasync(e) => {
                buf.add_syscall_fdatasync(basic_dim, e.latency_ns);
            }

            TypedEvent::SyscallPwrite(e) => {
                buf.add_syscall_pwrite(basic_dim, e.latency_ns);
            }

            TypedEvent::NetIOTx(e) => {
                let net_dim = build_tcp_metrics_dimension::<WITH_NETWORK_PORT_LABELS>(
                    basic_dim,
                    e.transport,
                    e.local_port,
                    e.remote_port,
                    dimensions.network_port_label_map,
                    port_label_cache,
                );
                buf.add_net_io_tx(net_dim, i64::from(e.bytes));
            }

            TypedEvent::NetIORx(e) => {
                let net_dim = build_tcp_metrics_dimension::<WITH_NETWORK_PORT_LABELS>(
                    basic_dim,
                    e.transport,
                    e.local_port,
                    e.remote_port,
                    dimensions.network_port_label_map,
                    port_label_cache,
                );
                buf.add_net_io_rx(net_dim, i64::from(e.bytes));
            }

            TypedEvent::NetIOTcpTxMetrics(e) => {
                let net_dim = build_tcp_metrics_dimension::<WITH_NETWORK_PORT_LABELS>(
                    basic_dim,
                    NetTransport::Tcp as u8,
                    e.local_port,
                    e.remote_port,
                    dimensions.network_port_label_map,
                    port_label_cache,
                );
                buf.add_net_io_with_tcp_metrics_dim(net_dim, i64::from(e.bytes), e.srtt_us, e.cwnd);
            }

            TypedEvent::TcpRetransmit(e) => {
                let net_dim = build_tcp_metrics_dimension::<WITH_NETWORK_PORT_LABELS>(
                    basic_dim,
                    NetTransport::Tcp as u8,
                    e.local_port,
                    e.remote_port,
                    dimensions.network_port_label_map,
                    port_label_cache,
                );
                buf.add_tcp_retransmit_dim(net_dim, i64::from(e.bytes));
            }

            TypedEvent::TcpState => {
                buf.add_tcp_state_change(basic_dim);
            }

            TypedEvent::DiskIO(e) => {
                let disk_dim =
                    build_disk_dimension_from_basic(basic_dim, e.device_id, e.rw, dimensions);
                buf.add_disk_io(disk_dim, e.latency_ns, e.bytes, e.queue_depth);
            }

            TypedEvent::BlockMerge(e) => {
                let disk_dim = build_disk_dimension_from_basic(basic_dim, 0, e.rw, dimensions);
                buf.add_block_merge(disk_dim, e.bytes);
            }

            TypedEvent::Sched(e) => {
                if WITH_SCHEDULER_STATE {
                    scheduler_state.handle_sched_switch(
                        buf,
                        event.raw.tid,
                        event.raw.timestamp_ns,
                        basic_dim,
                        e.on_cpu_ns,
                        e.cpu_id,
                    );
                } else {
                    buf.add_sched_switch(basic_dim, e.on_cpu_ns, e.cpu_id);
                }
            }

            TypedEvent::SchedCombined(e) => {
                let prev_dim = basic_dim;
                let next_dim = BasicDimension::new(e.next_pid, e.next_client_type);

                if WITH_SCHEDULER_STATE {
                    scheduler_state.handle_sched_combined(
                        buf,
                        event.raw.tid,
                        e.next_tid,
                        event.raw.timestamp_ns,
                        prev_dim,
                        next_dim,
                        e.on_cpu_ns,
                        e.runqueue_ns,
                        e.off_cpu_ns,
                        e.cpu_id,
                    );
                } else {
                    buf.add_sched_switch(prev_dim, e.on_cpu_ns, e.cpu_id);
                    buf.add_sched_runqueue(next_dim, e.runqueue_ns, e.off_cpu_ns);
                }
            }

            TypedEvent::SchedRunqueue(e) => {
                if WITH_SCHEDULER_STATE {
                    scheduler_state.handle_sched_runqueue(
                        buf,
                        event.raw.tid,
                        event.raw.timestamp_ns,
                        basic_dim,
                        e.runqueue_ns,
                        e.off_cpu_ns,
                        e.cpu_id,
                    );
                } else {
                    buf.add_sched_runqueue(basic_dim, e.runqueue_ns, e.off_cpu_ns);
                }
            }

            TypedEvent::PageFault(e) => {
                buf.add_page_fault(basic_dim, e.major);
            }

            TypedEvent::FDOpen => {
                buf.add_fd_open(basic_dim);
            }

            TypedEvent::FDClose => {
                buf.add_fd_close(basic_dim);
            }

            TypedEvent::MemReclaim(e) => {
                buf.add_mem_reclaim(basic_dim, e.duration_ns);
            }

            TypedEvent::MemCompaction(e) => {
                buf.add_mem_compaction(basic_dim, e.duration_ns);
            }

            TypedEvent::SwapIn(e) => {
                buf.add_swap_in(basic_dim, e.pages);
            }

            TypedEvent::SwapOut(e) => {
                buf.add_swap_out(basic_dim, e.pages);
            }

            TypedEvent::OOMKill => {
                buf.add_oom_kill(basic_dim);
            }

            TypedEvent::ProcessExit => {
                buf.add_process_exit(basic_dim);
                if WITH_SCHEDULER_STATE {
                    scheduler_state.handle_process_exit(buf, event.raw.tid, event.raw.timestamp_ns);
                }
            }
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    #[inline(always)]
    fn process_event_resolved<const WITH_SCHEDULER_STATE: bool>(
        buf: &mut Buffer,
        event: &ParsedEvent,
        dimensions: &ResolvedDimensions<'_>,
        scheduler_state: &mut SchedulerWindowState,
        port_label_cache: &mut PortLabelResolveCache,
    ) {
        if dimensions.network_port_label_map.is_some() {
            Self::process_event_inner::<WITH_SCHEDULER_STATE, true>(
                buf,
                event,
                dimensions,
                scheduler_state,
                port_label_cache,
            );
        } else {
            Self::process_event_inner::<WITH_SCHEDULER_STATE, false>(
                buf,
                event,
                dimensions,
                scheduler_state,
                port_label_cache,
            );
        }
    }

    /// Routes a parsed event to the appropriate buffer aggregator.
    #[cfg(test)]
    fn process_event(buf: &mut Buffer, event: &ParsedEvent, dimensions: &DimensionsConfig) {
        let mut port_label_cache = PortLabelResolveCache::default();
        let resolved_dimensions = ResolvedDimensions::from_config(dimensions);
        let mut scheduler_state = SchedulerWindowState::default();
        Self::process_event_resolved::<false>(
            buf,
            event,
            &resolved_dimensions,
            &mut scheduler_state,
            &mut port_label_cache,
        );
    }

    #[inline(always)]
    fn process_event_batch_with_scheduler_state(
        buf: &mut Buffer,
        events: &EventBatch,
        dimensions: &ResolvedDimensions<'_>,
        scheduler_state: &mut SchedulerWindowState,
        port_label_cache: &mut PortLabelResolveCache,
    ) {
        if dimensions.network_port_label_map.is_some() {
            for event in &events.events {
                Self::process_event_inner::<true, true>(
                    buf,
                    event,
                    dimensions,
                    scheduler_state,
                    port_label_cache,
                );
            }
        } else {
            for event in &events.events {
                Self::process_event_inner::<true, false>(
                    buf,
                    event,
                    dimensions,
                    scheduler_state,
                    port_label_cache,
                );
            }
        }
    }

    pub fn handle_event_batch(&self, events: EventBatch) {
        if events.is_empty() {
            return;
        }
        debug_assert!(events.len() <= EVENT_BATCH_SIZE);

        if self.event_tx.try_send(events).is_err() {
            warn!("aggregated sink event batch channel full, dropping batch");
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

        let state = Arc::clone(&self.state);
        let dimensions = self.cfg.dimensions.clone();
        let interval = self.cfg.resolution.interval;
        let sync_state_interval = self.cfg.resolution.sync_state_poll_interval;
        let host_specs_interval = self.cfg.resolution.host_specs_poll_interval;
        let resolution_overrides = self.cfg.resolution.overrides.clone();
        let sampling_cfg = self.cfg.sampling.clone();
        // Keep parse + aggregate collection running even with no exporters, but
        // avoid /proc snapshot reads when nothing can consume those metrics.
        let collect_process_snapshots = !exporters.is_empty();
        let collector = Collector::new_with_process_snapshots(
            interval,
            &sampling_cfg,
            collect_process_snapshots,
        );
        let mut flush_controller = TieredFlushController::new(interval, &resolution_overrides);
        let meta_client_name = Arc::clone(&self.meta_client_name);
        let meta_network_name = Arc::clone(&self.meta_network_name);
        let rotation_tx = self.rotation_tx.clone();
        let slot_aligned = self.cfg.resolution.slot_aligned;

        let run_task = tokio::spawn(async move {
            let resolved_dimensions = ResolvedDimensions::from_config(&dimensions);
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
            let mut port_label_cache = PortLabelResolveCache::default();
            let mut current_buf = initial_buf;
            let mut reusable_buf =
                AggregatedSink::new_buffer_from_state(&state, SystemTime::now(), 0);

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
                        while let Ok(events) = event_rx.try_recv() {
                            AggregatedSink::process_event_batch_with_scheduler_state(
                                &mut current_buf,
                                &events,
                                &resolved_dimensions,
                                &mut scheduler_state,
                                &mut port_label_cache,
                            );
                            events.recycle();
                        }

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
                        scheduler_state.flush_running_to_boundary(&mut current_buf, monotonic_ns());
                        reusable_batch.metadata.updated_time = SystemTime::now();
                        collector.collect_into(&current_buf, &mut reusable_batch);
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

                    Some(events) = event_rx.recv() => {
                        // Process the first batch.
                        AggregatedSink::process_event_batch_with_scheduler_state(
                            &mut current_buf,
                            &events,
                            &resolved_dimensions,
                            &mut scheduler_state,
                            &mut port_label_cache,
                        );
                        events.recycle();

                        // Drain more queued batches without blocking.
                        for _ in 0..EVENT_BATCHES_PER_WAKE - 1 {
                            match event_rx.try_recv() {
                                Ok(events) => {
                                    AggregatedSink::process_event_batch_with_scheduler_state(
                                        &mut current_buf,
                                        &events,
                                        &resolved_dimensions,
                                        &mut scheduler_state,
                                        &mut port_label_cache,
                                    );
                                    events.recycle();
                                }
                                Err(_) => break,
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
                            let mut old_buf = std::mem::replace(
                                &mut current_buf,
                                AggregatedSink::new_buffer_from_state(
                                &state,
                                SystemTime::now(),
                                rotation.new_slot,
                            ),
                            );
                            scheduler_state.flush_running_to_boundary(&mut old_buf, monotonic_ns());
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
                        AggregatedSink::reset_buffer_from_state(
                            &state,
                            &mut reusable_buf,
                            now,
                            slot,
                        );
                        std::mem::swap(&mut current_buf, &mut reusable_buf);
                        scheduler_state
                            .flush_running_to_boundary(&mut reusable_buf, monotonic_ns());
                        reusable_batch.metadata.updated_time = SystemTime::now();
                        collector.collect_into(&reusable_buf, &mut reusable_batch);
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
        let mut batch = ParsedEventBatch::with_capacity(1);
        batch.push(event);
        self.handle_event_batch(batch);
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
#[cfg_attr(not(test), allow(dead_code))]
fn build_network_dimension(
    pid: u32,
    client_type: u8,
    direction: u8,
    e: &NetIOEvent,
    dims: &DimensionsConfig,
) -> NetworkDimension {
    let resolved_dims = ResolvedDimensions::from_config(dims);
    build_network_dimension_from_parts_uncached(
        BasicDimension::new(pid, client_type),
        direction,
        e.transport,
        e.local_port,
        e.remote_port,
        &resolved_dims,
    )
}

#[inline(always)]
fn build_tcp_metrics_dimension_with_port_label_cached(
    basic: BasicDimension,
    transport: u8,
    local_port: u16,
    remote_port: u16,
    port_label_map: &crate::agent::ports::PortLabelMap,
    port_label_cache: &mut PortLabelResolveCache,
) -> TCPMetricsDimension {
    let port_label = port_label_cache.resolve(
        port_label_map,
        basic.client_type(),
        transport,
        local_port,
        remote_port,
    );

    TCPMetricsDimension::from_basic(basic, port_label)
}

#[inline(always)]
fn build_tcp_metrics_dimension<const WITH_PORT_LABELS: bool>(
    basic: BasicDimension,
    transport: u8,
    local_port: u16,
    remote_port: u16,
    port_label_map: Option<&crate::agent::ports::PortLabelMap>,
    port_label_cache: &mut PortLabelResolveCache,
) -> TCPMetricsDimension {
    if WITH_PORT_LABELS {
        build_tcp_metrics_dimension_with_port_label_cached(
            basic,
            transport,
            local_port,
            remote_port,
            port_label_map.expect("WITH_PORT_LABELS requires a port label map"),
            port_label_cache,
        )
    } else {
        TCPMetricsDimension::from_basic(basic, 0)
    }
}

/// Creates a NetworkDimension for TCP retransmit events.
#[cfg_attr(not(test), allow(dead_code))]
fn build_network_dimension_from_tcp_retransmit(
    pid: u32,
    client_type: u8,
    src_port: u16,
    dst_port: u16,
    dims: &DimensionsConfig,
) -> NetworkDimension {
    let resolved_dims = ResolvedDimensions::from_config(dims);
    build_network_dimension_from_parts_uncached(
        BasicDimension::new(pid, client_type),
        Direction::TX as u8,
        NetTransport::Tcp as u8,
        src_port,
        dst_port,
        &resolved_dims,
    )
}

#[inline(always)]
fn build_network_dimension_from_parts_uncached(
    basic: BasicDimension,
    raw_direction: u8,
    transport: u8,
    local_port: u16,
    remote_port: u16,
    dims: &ResolvedDimensions<'_>,
) -> NetworkDimension {
    let direction = raw_direction & dims.network_direction_mask;
    let port_label = if let Some(port_label_map) = dims.network_port_label_map {
        resolve_network_port_label_uncached(
            basic.client_type(),
            transport,
            local_port,
            remote_port,
            port_label_map,
        )
    } else {
        0
    };

    NetworkDimension::from_basic(basic, port_label, direction)
}

#[inline(always)]
fn resolve_network_port_label_uncached(
    client_type: u8,
    transport: u8,
    primary_port: u16,
    secondary_port: u16,
    port_label_map: &crate::agent::ports::PortLabelMap,
) -> u8 {
    match transport {
        transport if transport == NetTransport::Tcp as u8 => {
            port_label_map.resolve_tcp_raw(client_type, primary_port, secondary_port) as u8
        }
        _ => port_label_map.resolve_udp_raw(client_type, primary_port, secondary_port) as u8,
    }
}

/// Extracts the local port from a network event.
/// Ports are normalized during parsing, so this is just a field read.
#[cfg_attr(not(test), allow(dead_code))]
fn local_port(e: &NetIOEvent) -> u16 {
    e.local_port
}

/// Extracts the peer/remote port from a network event.
#[cfg_attr(not(test), allow(dead_code))]
fn remote_port(e: &NetIOEvent) -> u16 {
    e.remote_port
}

/// Creates a DiskDimension based on config.
#[cfg_attr(not(test), allow(dead_code))]
fn build_disk_dimension(
    pid: u32,
    client_type: u8,
    device_id: u32,
    rw: u8,
    dims: &DimensionsConfig,
) -> DiskDimension {
    let resolved_dims = ResolvedDimensions::from_config(dims);
    build_disk_dimension_from_basic(
        BasicDimension::new(pid, client_type),
        device_id,
        rw,
        &resolved_dims,
    )
}

#[inline(always)]
fn build_disk_dimension_from_basic(
    basic: BasicDimension,
    device_id: u32,
    rw: u8,
    dims: &ResolvedDimensions<'_>,
) -> DiskDimension {
    DiskDimension::from_basic(
        basic,
        device_id & dims.disk_device_mask,
        rw & dims.disk_rw_mask,
    )
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::ports::{PortLabel, PortLabelMap};
    use crate::sink::aggregated::dimension::CpuCoreDimension;
    use crate::tracer::event::*;

    fn make_event(event_type: EventType, typed: TypedEvent) -> ParsedEvent {
        ParsedEvent {
            raw: Event::new(0, 123, 123, event_type, ClientType::Geth as u8),
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
            raw: Event::new(timestamp_ns, pid, tid, event_type, ClientType::Geth as u8),
            typed,
        }
    }

    fn process_event_with_scheduler_state(
        buf: &mut Buffer,
        event: &ParsedEvent,
        dims: &DimensionsConfig,
        scheduler_state: &mut SchedulerWindowState,
    ) {
        let mut port_label_cache = PortLabelResolveCache::default();
        let resolved_dimensions = ResolvedDimensions::from_config(dims);
        AggregatedSink::process_event_resolved::<true>(
            buf,
            event,
            &resolved_dimensions,
            scheduler_state,
            &mut port_label_cache,
        );
    }

    #[test]
    fn test_running_thread_store_grows_cpu_slots() {
        let dim = BasicDimension::new(123, ClientType::Geth as u8);
        let mut store = RunningThreadStore::with_capacity(4);
        *store.cpu_slot_mut(0) = Some(RunningThread {
            tid: 10,
            basic_dim: dim,
            cpu_id: 0,
            running_since_ns: 100,
        });
        *store.cpu_slot_mut(2) = Some(RunningThread {
            tid: 30,
            basic_dim: dim,
            cpu_id: 2,
            running_since_ns: 300,
        });

        assert_eq!(store.entries.len(), 3);
        assert!(store.contains_tid(30));
    }

    #[test]
    fn test_running_thread_store_take_cpu_clears_slot() {
        let dim = BasicDimension::new(123, ClientType::Geth as u8);
        let mut store = RunningThreadStore::with_capacity(4);
        *store.cpu_slot_mut(0) = Some(RunningThread {
            tid: 10,
            basic_dim: dim,
            cpu_id: 0,
            running_since_ns: 100,
        });
        *store.cpu_slot_mut(1) = Some(RunningThread {
            tid: 20,
            basic_dim: dim,
            cpu_id: 1,
            running_since_ns: 200,
        });

        let removed = store.take_cpu(1).expect("cpu slot occupied");
        assert_eq!(removed.tid, 20);
        assert!(!store.contains_tid(20));
        assert!(store.contains_tid(10));
    }

    #[test]
    fn test_scheduler_tid_cache_collision_falls_back_to_running_scan() {
        let dim = BasicDimension::new(123, ClientType::Geth as u8);
        let tid_a = 10u32;
        let tid_b = (tid_a + 1..)
            .find(|tid| sched_tid_cache_slot(*tid) == sched_tid_cache_slot(tid_a))
            .expect("colliding tid");
        let mut scheduler_state = SchedulerWindowState::default();

        scheduler_state.restore_running(RunningThread {
            tid: tid_a,
            basic_dim: dim,
            cpu_id: 0,
            running_since_ns: 100,
        });
        scheduler_state.restore_running(RunningThread {
            tid: tid_b,
            basic_dim: dim,
            cpu_id: 1,
            running_since_ns: 200,
        });

        assert_eq!(scheduler_state.find_cpu_for_tid(tid_a), Some(0));
        assert_eq!(scheduler_state.find_cpu_for_tid(tid_b), Some(1));
        assert_eq!(scheduler_state.find_cpu_for_tid(tid_a), Some(0));
    }

    #[test]
    fn test_scheduler_tid_cache_keeps_two_colliding_tids_hot() {
        let dim = BasicDimension::new(123, ClientType::Geth as u8);
        let tid_a = 10u32;
        let tid_b = (tid_a + 1..)
            .find(|tid| sched_tid_cache_slot(*tid) == sched_tid_cache_slot(tid_a))
            .expect("colliding tid");
        let mut scheduler_state = SchedulerWindowState::default();

        scheduler_state.restore_running(RunningThread {
            tid: tid_a,
            basic_dim: dim,
            cpu_id: 0,
            running_since_ns: 100,
        });
        scheduler_state.restore_running(RunningThread {
            tid: tid_b,
            basic_dim: dim,
            cpu_id: 1,
            running_since_ns: 200,
        });

        assert_eq!(scheduler_state.find_cpu_for_tid(tid_a), Some(0));
        assert_eq!(scheduler_state.find_cpu_for_tid(tid_b), Some(1));

        let cache_set = &scheduler_state.tid_to_cpu_cache[sched_tid_cache_slot(tid_a)];
        assert!(cache_set
            .iter()
            .flatten()
            .any(|entry| entry.tid == tid_a && entry.cpu_id == 0));
        assert!(cache_set
            .iter()
            .flatten()
            .any(|entry| entry.tid == tid_b && entry.cpu_id == 1));
    }

    #[test]
    fn test_scheduler_tid_cache_clear_preserves_other_collision_entry() {
        let dim = BasicDimension::new(123, ClientType::Geth as u8);
        let tid_a = 10u32;
        let tid_b = (tid_a + 1..)
            .find(|tid| sched_tid_cache_slot(*tid) == sched_tid_cache_slot(tid_a))
            .expect("colliding tid");
        let mut scheduler_state = SchedulerWindowState::default();

        scheduler_state.restore_running(RunningThread {
            tid: tid_a,
            basic_dim: dim,
            cpu_id: 0,
            running_since_ns: 100,
        });
        scheduler_state.restore_running(RunningThread {
            tid: tid_b,
            basic_dim: dim,
            cpu_id: 1,
            running_since_ns: 200,
        });
        assert_eq!(scheduler_state.find_cpu_for_tid(tid_a), Some(0));
        assert_eq!(scheduler_state.find_cpu_for_tid(tid_b), Some(1));

        scheduler_state.clear_cached_tid_cpu(tid_a);

        let cache_set = &scheduler_state.tid_to_cpu_cache[sched_tid_cache_slot(tid_a)];
        assert!(!cache_set.iter().flatten().any(|entry| entry.tid == tid_a));
        assert!(cache_set.iter().flatten().any(|entry| entry.tid == tid_b));
    }

    #[test]
    fn test_process_event_syscall() {
        let mut buf = Buffer::new(
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
            TypedEvent::SyscallRead(SyscallEvent { latency_ns: 5_000 }),
        );

        AggregatedSink::process_event(&mut buf, &event, &dims);

        let dim = BasicDimension::new(123, 1);
        let entry = buf.syscall_read.get(&dim).expect("entry exists");
        assert_eq!(entry.snapshot().count, 1);
    }

    #[test]
    fn test_process_event_net_io() {
        let mut buf = Buffer::new(
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
            TypedEvent::NetIOTcpTxMetrics(NetIOTcpTxMetricsEvent {
                bytes: 1024,
                local_port: 8545,
                remote_port: 30303,
                srtt_us: 100,
                cwnd: 65535,
            }),
        );

        AggregatedSink::process_event(&mut buf, &event, &dims);

        // Metrics-bearing TCP TX events now use the combined TCP TX aggregate.
        assert!(!buf.tcp_tx.is_empty());
    }

    #[test]
    fn test_process_event_net_io_reuses_network_port_label_for_tcp_metrics() {
        let mut buf = Buffer::new(
            SystemTime::now(),
            0,
            SystemTime::now(),
            false,
            false,
            false,
            8,
        );
        let mut dims = DimensionsConfig::default();
        let mut map = PortLabelMap::default();
        map.insert(ClientType::Geth, 30303, PortLabel::ElP2PTcp);
        dims.network.set_port_label_map(map);

        let event = make_event(
            EventType::NetTX,
            TypedEvent::NetIOTcpTxMetrics(NetIOTcpTxMetricsEvent {
                bytes: 1024,
                local_port: 45_000,
                remote_port: 30_303,
                srtt_us: 100,
                cwnd: 65535,
            }),
        );

        AggregatedSink::process_event(&mut buf, &event, &dims);

        let net_dim =
            TCPMetricsDimension::new(123, ClientType::Geth as u8, PortLabel::ElP2PTcp as u8);
        assert!(buf.tcp_tx.contains_key(&net_dim));
    }

    #[test]
    fn test_process_event_disk_io() {
        let mut buf = Buffer::new(
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
                latency_ns: 50_000,
                bytes: 4096,
                rw: 1,
                queue_depth: 3,
                device_id: 259,
            }),
        );

        AggregatedSink::process_event(&mut buf, &event, &dims);

        assert!(!buf.disk_io_write.is_empty());
    }

    #[test]
    fn test_process_event_fd_open_close() {
        let mut buf = Buffer::new(
            SystemTime::now(),
            0,
            SystemTime::now(),
            false,
            false,
            false,
            8,
        );
        let dims = DimensionsConfig::default();

        let open_event = make_event(EventType::FDOpen, TypedEvent::FDOpen);

        let close_event = make_event(EventType::FDClose, TypedEvent::FDClose);

        AggregatedSink::process_event(&mut buf, &open_event, &dims);
        AggregatedSink::process_event(&mut buf, &close_event, &dims);

        assert!(!buf.fd_metrics.is_empty());
    }

    #[test]
    fn test_process_event_all_types() {
        let mut buf = Buffer::new(
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
                on_cpu_ns: 1_000_000,
                cpu_id: 3,
            }),
        );
        AggregatedSink::process_event(&mut buf, &event, &dims);
        assert!(buf
            .sched_on_cpu_snapshot(BasicDimension::new(123, 1))
            .is_some());
        assert!(!buf.cpu_on_core.is_empty());

        // Page fault
        let event = make_event(
            EventType::PageFault,
            TypedEvent::PageFault(PageFaultEvent { major: true }),
        );
        AggregatedSink::process_event(&mut buf, &event, &dims);
        assert!(!buf.page_fault_metrics.is_empty());

        // OOM kill
        let event = make_event(EventType::OOMKill, TypedEvent::OOMKill);
        AggregatedSink::process_event(&mut buf, &event, &dims);
        assert!(!buf.basic_cold_metrics.is_empty());

        // Process exit
        let event = make_event(EventType::ProcessExit, TypedEvent::ProcessExit);
        AggregatedSink::process_event(&mut buf, &event, &dims);
        assert!(!buf.basic_cold_metrics.is_empty());

        // Mem reclaim
        let event = make_event(
            EventType::MemReclaim,
            TypedEvent::MemReclaim(MemLatencyEvent { duration_ns: 5_000 }),
        );
        AggregatedSink::process_event(&mut buf, &event, &dims);
        assert!(!buf.basic_cold_metrics.is_empty());

        // Swap in
        let event = make_event(
            EventType::SwapIn,
            TypedEvent::SwapIn(SwapEvent { pages: 1 }),
        );
        AggregatedSink::process_event(&mut buf, &event, &dims);
        assert!(!buf.basic_cold_metrics.is_empty());

        // TCP state
        let event = make_event(EventType::TcpState, TypedEvent::TcpState);
        AggregatedSink::process_event(&mut buf, &event, &dims);
        assert!(!buf.basic_cold_metrics.is_empty());
    }

    #[test]
    fn test_process_event_sched_combined_with_scheduler_state() {
        let dims = DimensionsConfig::default();
        let mut scheduler_state = SchedulerWindowState::default();
        let mut buf = Buffer::new(
            SystemTime::now(),
            0,
            SystemTime::now(),
            false,
            false,
            false,
            8,
        );

        let event = make_event_at(
            1_000,
            123,
            77,
            EventType::SchedSwitch,
            TypedEvent::SchedCombined(SchedCombinedEvent {
                on_cpu_ns: 300,
                cpu_id: 2,
                next_pid: 124,
                next_tid: 88,
                next_client_type: ClientType::Geth as u8,
                runqueue_ns: 50,
                off_cpu_ns: 100,
            }),
        );

        process_event_with_scheduler_state(&mut buf, &event, &dims, &mut scheduler_state);
        scheduler_state.flush_running_to_boundary(&mut buf, 1_300);

        let prev_sched = buf
            .sched_on_cpu_snapshot(BasicDimension::new(123, ClientType::Geth as u8))
            .expect("prev sched_on_cpu");
        assert_eq!(prev_sched.sum, 300);

        let next_wait = buf
            .sched_wait
            .get(&BasicDimension::new(124, ClientType::Geth as u8))
            .expect("next sched_wait");
        assert_eq!(next_wait.runqueue_snapshot().sum, 50);
        assert_eq!(next_wait.off_cpu_snapshot().sum, 100);

        let prev_core = buf
            .cpu_on_core
            .get(&CpuCoreDimension::new(123, ClientType::Geth as u8, 2))
            .expect("prev core usage");
        assert_eq!(prev_core.cpu_on_core_snapshot().sum, 300);

        let next_core = buf
            .cpu_on_core
            .get(&CpuCoreDimension::new(124, ClientType::Geth as u8, 2))
            .expect("next core usage");
        assert_eq!(next_core.cpu_on_core_snapshot().sum, 300);
    }

    #[test]
    fn test_sched_combined_reattributes_existing_next_thread_runtime() {
        let dims = DimensionsConfig::default();
        let mut scheduler_state = SchedulerWindowState::default();
        let mut buf = Buffer::new(
            SystemTime::now(),
            0,
            SystemTime::now(),
            false,
            false,
            false,
            8,
        );

        let seed_running = make_event_at(
            1_000,
            124,
            88,
            EventType::SchedRunqueue,
            TypedEvent::SchedRunqueue(SchedRunqueueEvent {
                runqueue_ns: 0,
                off_cpu_ns: 0,
                cpu_id: 1,
            }),
        );
        process_event_with_scheduler_state(&mut buf, &seed_running, &dims, &mut scheduler_state);

        let combined = make_event_at(
            1_300,
            123,
            77,
            EventType::SchedSwitch,
            TypedEvent::SchedCombined(SchedCombinedEvent {
                on_cpu_ns: 50,
                cpu_id: 2,
                next_pid: 124,
                next_tid: 88,
                next_client_type: ClientType::Geth as u8,
                runqueue_ns: 10,
                off_cpu_ns: 20,
            }),
        );
        process_event_with_scheduler_state(&mut buf, &combined, &dims, &mut scheduler_state);
        scheduler_state.flush_running_to_boundary(&mut buf, 1_500);

        let cpu1 = buf
            .cpu_on_core
            .get(&CpuCoreDimension::new(124, ClientType::Geth as u8, 1))
            .expect("carried runtime on old cpu");
        assert_eq!(cpu1.cpu_on_core_snapshot().sum, 300);

        let prev_cpu2 = buf
            .cpu_on_core
            .get(&CpuCoreDimension::new(123, ClientType::Geth as u8, 2))
            .expect("fallback runtime on outgoing cpu");
        assert_eq!(prev_cpu2.cpu_on_core_snapshot().sum, 50);

        let next_cpu2 = buf
            .cpu_on_core
            .get(&CpuCoreDimension::new(124, ClientType::Geth as u8, 2))
            .expect("new running thread on target cpu");
        assert_eq!(next_cpu2.cpu_on_core_snapshot().sum, 200);
    }

    #[test]
    fn test_scheduler_state_carries_running_thread_across_boundaries() {
        let dims = DimensionsConfig::default();
        let mut scheduler_state = SchedulerWindowState::default();

        let mut buf1 = Buffer::new(
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
                runqueue_ns: 50,
                off_cpu_ns: 100,
                cpu_id: 2,
            }),
        );

        process_event_with_scheduler_state(&mut buf1, &rq_event, &dims, &mut scheduler_state);
        scheduler_state.flush_running_to_boundary(&mut buf1, 1_500);

        let core1 = buf1
            .cpu_on_core
            .get(&CpuCoreDimension::new(123, 1, 2))
            .expect("core usage in first buffer");
        assert_eq!(core1.cpu_on_core_snapshot().sum, 500);

        let rq = buf1
            .sched_wait
            .get(&BasicDimension::new(123, 1))
            .expect("runqueue metric");
        assert_eq!(rq.runqueue_snapshot().sum, 50);

        let mut buf2 = Buffer::new(
            SystemTime::now(),
            0,
            SystemTime::now(),
            false,
            false,
            false,
            8,
        );
        scheduler_state.flush_running_to_boundary(&mut buf2, 1_900);

        let core2 = buf2
            .cpu_on_core
            .get(&CpuCoreDimension::new(123, 1, 2))
            .expect("core usage carried into second buffer");
        assert_eq!(core2.cpu_on_core_snapshot().sum, 400);
    }

    #[test]
    fn test_scheduler_state_switch_out_uses_carried_start() {
        let dims = DimensionsConfig::default();
        let mut scheduler_state = SchedulerWindowState::default();

        let mut buf1 = Buffer::new(
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
                runqueue_ns: 0,
                off_cpu_ns: 0,
                cpu_id: 3,
            }),
        );
        process_event_with_scheduler_state(&mut buf1, &rq_event, &dims, &mut scheduler_state);
        scheduler_state.flush_running_to_boundary(&mut buf1, 10_500);

        let mut buf2 = Buffer::new(
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
                on_cpu_ns: 2_000,
                cpu_id: 3,
            }),
        );
        process_event_with_scheduler_state(&mut buf2, &switch_event, &dims, &mut scheduler_state);

        let core2 = buf2
            .cpu_on_core
            .get(&CpuCoreDimension::new(123, 1, 3))
            .expect("core usage on switch-out");
        // Uses carried state (11_000 - 10_500), not the raw 2_000ns slice.
        assert_eq!(core2.cpu_on_core_snapshot().sum, 500);

        let on_cpu = buf2
            .sched_on_cpu_snapshot(BasicDimension::new(123, 1))
            .expect("sched_on_cpu recorded");
        // Latency distribution remains raw from sched_switch payload.
        assert_eq!(on_cpu.sum, 2_000);
    }

    #[test]
    fn test_scheduler_state_fallback_without_switch_in_uses_raw_slice() {
        let dims = DimensionsConfig::default();
        let mut scheduler_state = SchedulerWindowState::default();

        let mut buf = Buffer::new(
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
                on_cpu_ns: 700,
                cpu_id: 1,
            }),
        );
        process_event_with_scheduler_state(&mut buf, &switch_event, &dims, &mut scheduler_state);

        let core = buf
            .cpu_on_core
            .get(&CpuCoreDimension::new(123, 1, 1))
            .expect("fallback core usage");
        assert_eq!(core.cpu_on_core_snapshot().sum, 700);
    }

    #[test]
    fn test_scheduler_state_process_exit_accounts_tail_once() {
        let dims = DimensionsConfig::default();
        let mut scheduler_state = SchedulerWindowState::default();

        let mut buf = Buffer::new(
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
                runqueue_ns: 0,
                off_cpu_ns: 0,
                cpu_id: 4,
            }),
        );
        process_event_with_scheduler_state(&mut buf, &rq_event, &dims, &mut scheduler_state);

        scheduler_state.flush_running_to_boundary(&mut buf, 1_300);

        let exit_event = make_event_at(
            1_500,
            123,
            50,
            EventType::ProcessExit,
            TypedEvent::ProcessExit,
        );
        process_event_with_scheduler_state(&mut buf, &exit_event, &dims, &mut scheduler_state);
        scheduler_state.flush_running_to_boundary(&mut buf, 2_000);

        let core = buf
            .cpu_on_core
            .get(&CpuCoreDimension::new(123, 1, 4))
            .expect("process-exit accounted runtime");
        assert_eq!(core.cpu_on_core_snapshot().sum, 500);
        assert!(scheduler_state.running_by_cpu.is_empty());
    }

    #[test]
    fn test_scheduler_state_newer_switch_in_reattributes_previous_core() {
        let dims = DimensionsConfig::default();
        let mut scheduler_state = SchedulerWindowState::default();

        let mut buf = Buffer::new(
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
                runqueue_ns: 1,
                off_cpu_ns: 1,
                cpu_id: 3,
            }),
        );

        process_event_with_scheduler_state(&mut buf, &rq1, &dims, &mut scheduler_state);
        process_event_with_scheduler_state(&mut buf, &rq2, &dims, &mut scheduler_state);
        scheduler_state.flush_running_to_boundary(&mut buf, 1_500);

        let core1 = buf
            .cpu_on_core
            .get(&CpuCoreDimension::new(123, 1, 1))
            .expect("first core usage");
        assert_eq!(core1.cpu_on_core_snapshot().sum, 300);

        let core3 = buf
            .cpu_on_core
            .get(&CpuCoreDimension::new(123, 1, 3))
            .expect("second core usage");
        assert_eq!(core3.cpu_on_core_snapshot().sum, 200);
    }

    #[test]
    fn test_scheduler_state_stale_events_do_not_rewind_or_drop_running_state() {
        let dims = DimensionsConfig::default();
        let mut scheduler_state = SchedulerWindowState::default();

        let mut buf = Buffer::new(
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
                on_cpu_ns: 50,
                cpu_id: 1,
            }),
        );
        let stale_exit = make_event_at(
            980,
            123,
            70,
            EventType::ProcessExit,
            TypedEvent::ProcessExit,
        );

        process_event_with_scheduler_state(&mut buf, &rq, &dims, &mut scheduler_state);
        process_event_with_scheduler_state(&mut buf, &stale_rq, &dims, &mut scheduler_state);
        process_event_with_scheduler_state(&mut buf, &stale_switch, &dims, &mut scheduler_state);
        process_event_with_scheduler_state(&mut buf, &stale_exit, &dims, &mut scheduler_state);
        scheduler_state.flush_running_to_boundary(&mut buf, 1_200);

        let carried_core = buf
            .cpu_on_core
            .get(&CpuCoreDimension::new(123, 1, 2))
            .expect("carried running core usage");
        assert_eq!(carried_core.cpu_on_core_snapshot().sum, 200);

        let fallback_core = buf
            .cpu_on_core
            .get(&CpuCoreDimension::new(123, 1, 1))
            .expect("stale switch fallback usage");
        assert_eq!(fallback_core.cpu_on_core_snapshot().sum, 50);
        assert!(scheduler_state.running_by_cpu.contains_tid(70));
    }

    #[test]
    fn test_local_port_tx_vs_rx() {
        let tx_event = NetIOEvent {
            bytes: 100,
            local_port: 8545,
            remote_port: 30303,
            transport: NetTransport::Tcp as u8,
        };
        assert_eq!(local_port(&tx_event), 8545);
        assert_eq!(remote_port(&tx_event), 30303);

        let rx_event = NetIOEvent {
            bytes: 100,
            local_port: 8545,
            remote_port: 30303,
            transport: NetTransport::Tcp as u8,
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
            bytes: 100,
            local_port: 45432,
            remote_port: 13000,
            transport: NetTransport::Tcp as u8,
        };

        let net_dim = build_network_dimension(
            1,
            ClientType::Prysm as u8,
            Direction::TX as u8,
            &net_event,
            &dims,
        );
        assert_eq!(net_dim.port_label(), PortLabel::ClP2PTcp as u8);
    }

    #[test]
    fn test_network_dimension_uses_tcp_label_for_shared_port() {
        let mut dims = DimensionsConfig::default();
        let mut map = PortLabelMap::default();
        map.insert(ClientType::Prysm, 13000, PortLabel::ClP2PTcp);
        map.insert(ClientType::Prysm, 13000, PortLabel::ClDiscovery);
        dims.network.set_port_label_map(map);

        let net_event = NetIOEvent {
            bytes: 100,
            local_port: 13000,
            remote_port: 13000,
            transport: NetTransport::Tcp as u8,
        };

        let net_dim = build_network_dimension(
            1,
            ClientType::Prysm as u8,
            Direction::RX as u8,
            &net_event,
            &dims,
        );
        assert_eq!(net_dim.port_label(), PortLabel::ClP2PTcp as u8);

        let retransmit_dim = build_network_dimension_from_tcp_retransmit(
            1,
            ClientType::Prysm as u8,
            45432,
            13000,
            &dims,
        );
        assert_eq!(retransmit_dim.port_label(), PortLabel::ClP2PTcp as u8);
    }

    #[test]
    fn test_network_dimension_uses_udp_label_for_shared_port() {
        let mut dims = DimensionsConfig::default();
        let mut map = PortLabelMap::default();
        map.insert(ClientType::Prysm, 13000, PortLabel::ClP2PTcp);
        map.insert(ClientType::Prysm, 13000, PortLabel::ClDiscovery);
        dims.network.set_port_label_map(map);

        let net_event = NetIOEvent {
            bytes: 100,
            local_port: 13000,
            remote_port: 13000,
            transport: NetTransport::Udp as u8,
        };

        let net_dim = build_network_dimension(
            1,
            ClientType::Prysm as u8,
            Direction::RX as u8,
            &net_event,
            &dims,
        );
        assert_eq!(net_dim.port_label(), PortLabel::ClDiscovery as u8);
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
            bytes: 100,
            local_port: 8545,
            remote_port: 30303,
            transport: NetTransport::Tcp as u8,
        };

        let net_dim = build_network_dimension(1, 1, Direction::TX as u8, &net_event, &dims);
        assert_eq!(net_dim.port_label(), 0);
        assert_eq!(net_dim.direction(), 0);

        let disk_dim = build_disk_dimension(1, 1, 259, 1, &dims);
        assert_eq!(disk_dim.device_id(), 0);
        assert_eq!(disk_dim.rw(), 0);
    }

    #[test]
    fn test_network_dimension_skips_empty_port_map() {
        let mut dims = DimensionsConfig::default();
        dims.network.set_port_label_map(PortLabelMap::default());

        let net_event = NetIOEvent {
            bytes: 100,
            local_port: 19999,
            remote_port: 45000,
            transport: NetTransport::Udp as u8,
        };

        let net_dim = build_network_dimension(
            1,
            ClientType::Unknown as u8,
            Direction::TX as u8,
            &net_event,
            &dims,
        );
        assert_eq!(net_dim.port_label(), PortLabel::Unknown as u8);
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
