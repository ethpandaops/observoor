use std::hash::Hash;
use std::hash::{BuildHasherDefault, Hasher};
use std::ptr::NonNull;
use std::time::SystemTime;

use hashbrown::{
    hash_map::{IntoIter as HashMapIntoIter, Iter as HashMapIter, RawEntryMut},
    HashMap,
};

use crate::tracer::event::{Direction, EventType};

use super::aggregate::{
    BasicAggregate, BasicColdAggregate, BasicSchedulerAggregate, CounterAggregate, DiskAggregate,
    LatencyAggregate, TcpTxAggregate,
};
use super::dimension::{
    BasicDimension, CpuCoreDimension, DiskDimension, NetworkDimension, TCPMetricsDimension,
};

#[derive(Default)]
pub struct PackedKeyHasher {
    hash: u64,
}

#[inline(always)]
fn mix_key_u64(value: u64) -> u64 {
    value ^ value.rotate_left(25)
}

impl Hasher for PackedKeyHasher {
    #[inline(always)]
    fn finish(&self) -> u64 {
        self.hash
    }

    #[inline(always)]
    fn write(&mut self, bytes: &[u8]) {
        let mut folded = 0u64;
        for (idx, byte) in bytes.iter().take(16).enumerate() {
            folded ^= u64::from(*byte) << ((idx % 8) * 8);
        }
        self.hash = mix_key_u64(folded);
    }

    #[inline(always)]
    fn write_u32(&mut self, i: u32) {
        self.hash = mix_key_u64(u64::from(i));
    }

    #[inline(always)]
    fn write_u64(&mut self, i: u64) {
        self.hash = mix_key_u64(i);
    }

    #[inline(always)]
    fn write_u128(&mut self, i: u128) {
        self.hash = mix_key_u64((i as u64) ^ ((i >> 64) as u64).rotate_left(32));
    }

    #[inline(always)]
    fn write_usize(&mut self, i: usize) {
        self.hash = mix_key_u64(i as u64);
    }
}

pub type FastHashBuilder = BuildHasherDefault<PackedKeyHasher>;

pub(crate) trait FastMapKey: Copy + Eq + Hash {
    fn precomputed_hash(self) -> u64;
}

#[derive(Clone, Copy)]
struct FastMapCacheEntry<K, V> {
    key: K,
    value: NonNull<V>,
}

// Safety: the cached pointer always points into the owning hash map allocation
// stored in the same `FastMap`. The cache is private to `buffer.rs`, only
// dereferenced through `&mut FastMap`, and the full `FastMap` moves together
// with its backing allocation when sent across tasks.
unsafe impl<K: Send, V: Send> Send for FastMapCacheEntry<K, V> {}
unsafe impl<K: Sync, V: Sync> Sync for FastMapCacheEntry<K, V> {}

#[inline(always)]
fn precomputed_u32_hash(value: u32) -> u64 {
    mix_key_u64(u64::from(value))
}

#[inline(always)]
fn precomputed_u64_hash(value: u64) -> u64 {
    mix_key_u64(value)
}

#[inline(always)]
fn precomputed_u128_hash(value: u128) -> u64 {
    mix_key_u64((value as u64) ^ ((value >> 64) as u64).rotate_left(32))
}

impl FastMapKey for u32 {
    #[inline(always)]
    fn precomputed_hash(self) -> u64 {
        precomputed_u32_hash(self)
    }
}

impl FastMapKey for u64 {
    #[inline(always)]
    fn precomputed_hash(self) -> u64 {
        precomputed_u64_hash(self)
    }
}

impl FastMapKey for u128 {
    #[inline(always)]
    fn precomputed_hash(self) -> u64 {
        precomputed_u128_hash(self)
    }
}

impl FastMapKey for BasicDimension {
    #[inline(always)]
    fn precomputed_hash(self) -> u64 {
        precomputed_u64_hash(self.packed())
    }
}

impl FastMapKey for CpuCoreDimension {
    #[inline(always)]
    fn precomputed_hash(self) -> u64 {
        precomputed_u128_hash(self.packed())
    }
}

impl FastMapKey for NetworkDimension {
    #[inline(always)]
    fn precomputed_hash(self) -> u64 {
        precomputed_u64_hash(self.packed())
    }
}

impl FastMapKey for TCPMetricsDimension {
    #[inline(always)]
    fn precomputed_hash(self) -> u64 {
        precomputed_u64_hash(self.packed())
    }
}

impl FastMapKey for DiskDimension {
    #[inline(always)]
    fn precomputed_hash(self) -> u64 {
        precomputed_u128_hash(self.packed())
    }
}

pub struct FastMap<K, V> {
    // Keep one consistent heap-backed layout for all aggregation maps.
    // Large aggregates stay out of the map object itself, which avoids the
    // inline/small-state cache pressure regressions seen in CPU benchmarks.
    inner: HashMap<K, V, FastHashBuilder>,
    // Hot-path event streams often update the same dimension repeatedly.
    // Cache the most recently resolved entry to bypass hashing/probing on hits.
    last_hit: Option<FastMapCacheEntry<K, V>>,
}

pub type FastMapIter<'a, K, V> = HashMapIter<'a, K, V>;
pub type FastMapIntoIter<K, V> = HashMapIntoIter<K, V>;

impl<K, V> FastMap<K, V> {
    #[inline(always)]
    fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: HashMap::with_capacity_and_hasher(capacity, FastHashBuilder::default()),
            last_hit: None,
        }
    }

    #[inline(always)]
    pub(crate) fn len(&self) -> usize {
        self.inner.len()
    }

    #[cfg_attr(not(test), allow(dead_code))]
    #[inline(always)]
    pub(crate) fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    #[inline(always)]
    pub(crate) fn clear(&mut self) {
        self.last_hit = None;
        self.inner.clear();
    }

    #[inline(always)]
    pub(crate) fn iter(&self) -> FastMapIter<'_, K, V> {
        self.inner.iter()
    }
}

impl<K, V> FastMap<K, V>
where
    K: Eq + Hash,
{
    #[cfg_attr(not(test), allow(dead_code))]
    #[inline(always)]
    pub(crate) fn get(&self, key: &K) -> Option<&V> {
        self.inner.get(key)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    #[inline(always)]
    pub(crate) fn contains_key(&self, key: &K) -> bool {
        self.inner.contains_key(key)
    }
}

impl<K, V> IntoIterator for FastMap<K, V> {
    type Item = (K, V);
    type IntoIter = FastMapIntoIter<K, V>;

    #[inline(always)]
    fn into_iter(self) -> Self::IntoIter {
        self.inner.into_iter()
    }
}

pub(crate) fn fast_map_with_capacity<K, V>(capacity: usize) -> FastMap<K, V> {
    FastMap::with_capacity(capacity)
}

#[inline(always)]
pub(crate) fn get_or_default_mut<K, V>(map: &mut FastMap<K, V>, key: K) -> &mut V
where
    K: FastMapKey,
    V: Default,
{
    if let Some(cached) = map.last_hit.as_ref() {
        if cached.key == key {
            let value = cached.value;
            // Safety: `last_hit` is populated from references returned by
            // `hashbrown` and invalidated on any new insertion before reuse.
            return unsafe { &mut *value.as_ptr() };
        }
    }

    let hash = key.precomputed_hash();

    let value = match map
        .inner
        .raw_entry_mut()
        .from_key_hashed_nocheck(hash, &key)
    {
        RawEntryMut::Occupied(entry) => entry.into_mut(),
        RawEntryMut::Vacant(entry) => entry.insert_hashed_nocheck(hash, key, V::default()).1,
    };
    map.last_hit = Some(FastMapCacheEntry {
        key,
        value: NonNull::from(&mut *value),
    });
    value
}

#[inline(always)]
fn add_counter_value<K>(map: &mut FastMap<K, CounterAggregate>, key: K, value: i64)
where
    K: FastMapKey,
{
    get_or_default_mut(map, key).add(value);
}

#[inline(always)]
fn record_disk(
    map: &mut FastMap<DiskDimension, DiskAggregate>,
    key: DiskDimension,
    latency_ns: u64,
    bytes: u32,
    queue_depth: u32,
) {
    get_or_default_mut(map, key).record(latency_ns, bytes, queue_depth);
}

#[inline(always)]
fn record_tcp_tx(
    map: &mut FastMap<TCPMetricsDimension, TcpTxAggregate>,
    key: TCPMetricsDimension,
    bytes: i64,
    rtt_us: u32,
    cwnd: u32,
) {
    get_or_default_mut(map, key).record(bytes, rtt_us, cwnd);
}

#[inline(always)]
fn record_tcp_metrics(
    map: &mut FastMap<TCPMetricsDimension, TcpTxAggregate>,
    key: TCPMetricsDimension,
    rtt_us: u32,
    cwnd: u32,
) {
    get_or_default_mut(map, key).record_metrics(rtt_us, cwnd);
}

#[inline(always)]
fn tcp_metrics_key_for_network(dim: NetworkDimension) -> TCPMetricsDimension {
    TCPMetricsDimension::new(dim.pid(), dim.client_type(), dim.port_label())
}

/// Aggregation buffer that collects events and aggregates them by dimension
/// over a time window.
///
/// Ingestion is serialized through the aggregated sink run loop, so these maps
/// stay as plain hash maps with no per-event synchronization.
#[allow(dead_code)]
pub struct Buffer {
    /// Start of this aggregation window.
    pub start_time: SystemTime,
    /// Current wallclock slot number.
    pub wallclock_slot: u64,
    /// Start time of the current wallclock slot.
    pub wallclock_slot_start: SystemTime,
    /// Whether the consensus layer is syncing.
    pub cl_syncing: bool,
    /// Whether the execution layer is optimistic.
    pub el_optimistic: bool,
    /// Whether the execution layer is offline.
    pub el_offline: bool,
    /// Number of online CPU cores on the host.
    pub system_cores: u16,

    // --- Hot BasicDimension metrics ---
    // Each syscall family gets its own small aggregate so the hot path updates
    // one compact value instead of bouncing around a larger multi-syscall blob.
    pub syscall_read: FastMap<BasicDimension, LatencyAggregate>,
    pub syscall_write: FastMap<BasicDimension, LatencyAggregate>,
    pub syscall_futex: FastMap<BasicDimension, LatencyAggregate>,
    pub syscall_mmap: FastMap<BasicDimension, LatencyAggregate>,
    pub syscall_fsync: FastMap<BasicDimension, LatencyAggregate>,

    // --- BasicDimension counters (page faults + FD activity) ---
    pub basic_metrics: FastMap<BasicDimension, BasicAggregate>,
    pub basic_sched_metrics: FastMap<BasicDimension, BasicSchedulerAggregate>,
    pub basic_cold_metrics: FastMap<BasicDimension, BasicColdAggregate>,

    // --- Network (TCPMetricsDimension -> CounterAggregate) ---
    // TX/RX already live in separate maps, so the hot-path network key only
    // needs pid/client/port-label and can skip packing direction entirely.
    pub net_io_tx: FastMap<TCPMetricsDimension, CounterAggregate>,
    pub net_io_rx: FastMap<TCPMetricsDimension, CounterAggregate>,
    pub tcp_retransmit: FastMap<TCPMetricsDimension, CounterAggregate>,

    // --- TCP TX bytes + metrics (TCPMetricsDimension -> TcpTxAggregate) ---
    pub tcp_tx: FastMap<TCPMetricsDimension, TcpTxAggregate>,

    // --- Disk (DiskDimension) ---
    // Disk completions frequently alternate read/write against the same device.
    // Splitting by direction lets each map keep a stable last-hit cache entry.
    pub disk_io_read: FastMap<DiskDimension, DiskAggregate>,
    pub disk_io_write: FastMap<DiskDimension, DiskAggregate>,
    pub block_merge: FastMap<DiskDimension, CounterAggregate>,

    pub cpu_on_core: FastMap<CpuCoreDimension, CounterAggregate>,
}

impl Buffer {
    /// Creates a new buffer with initialized maps.
    pub fn new(
        start_time: SystemTime,
        wallclock_slot: u64,
        wallclock_slot_start: SystemTime,
        cl_syncing: bool,
        el_optimistic: bool,
        el_offline: bool,
        system_cores: u16,
    ) -> Self {
        Self {
            start_time,
            wallclock_slot,
            wallclock_slot_start,
            cl_syncing,
            el_optimistic,
            el_offline,
            system_cores,
            // Hot BasicDimension metrics.
            syscall_read: fast_map_with_capacity(16),
            syscall_write: fast_map_with_capacity(16),
            syscall_futex: fast_map_with_capacity(16),
            syscall_mmap: fast_map_with_capacity(16),
            syscall_fsync: fast_map_with_capacity(16),
            // BasicDimension counters.
            basic_metrics: fast_map_with_capacity(16),
            basic_sched_metrics: fast_map_with_capacity(8),
            basic_cold_metrics: fast_map_with_capacity(8),
            // Network.
            net_io_tx: fast_map_with_capacity(64),
            net_io_rx: fast_map_with_capacity(64),
            tcp_retransmit: fast_map_with_capacity(32),
            // TCP TX bytes + metrics.
            tcp_tx: fast_map_with_capacity(32),
            // Disk.
            disk_io_read: fast_map_with_capacity(16),
            disk_io_write: fast_map_with_capacity(16),
            block_merge: fast_map_with_capacity(16),
            // Scheduler.
            cpu_on_core: fast_map_with_capacity(64),
        }
    }

    /// Resets this buffer for a new aggregation window while preserving map allocations.
    pub fn reset(
        &mut self,
        start_time: SystemTime,
        wallclock_slot: u64,
        wallclock_slot_start: SystemTime,
        cl_syncing: bool,
        el_optimistic: bool,
        el_offline: bool,
        system_cores: u16,
    ) {
        self.start_time = start_time;
        self.wallclock_slot = wallclock_slot;
        self.wallclock_slot_start = wallclock_slot_start;
        self.cl_syncing = cl_syncing;
        self.el_optimistic = el_optimistic;
        self.el_offline = el_offline;
        self.system_cores = system_cores;

        self.syscall_read.clear();
        self.syscall_write.clear();
        self.syscall_futex.clear();
        self.syscall_mmap.clear();
        self.syscall_fsync.clear();
        self.basic_metrics.clear();
        self.basic_sched_metrics.clear();
        self.basic_cold_metrics.clear();
        self.net_io_tx.clear();
        self.net_io_rx.clear();
        self.tcp_retransmit.clear();
        self.tcp_tx.clear();
        self.disk_io_read.clear();
        self.disk_io_write.clear();
        self.block_merge.clear();
        self.cpu_on_core.clear();
    }

    /// Adds a syscall latency event to the appropriate map.
    pub fn add_syscall(&mut self, event_type: EventType, dim: BasicDimension, latency_ns: u64) {
        match event_type {
            EventType::SyscallRead => self.add_syscall_read(dim, latency_ns),
            EventType::SyscallWrite => self.add_syscall_write(dim, latency_ns),
            EventType::SyscallFutex => self.add_syscall_futex(dim, latency_ns),
            EventType::SyscallMmap => self.add_syscall_mmap(dim, latency_ns),
            EventType::SyscallEpollWait => self.add_syscall_epoll_wait(dim, latency_ns),
            EventType::SyscallFsync => self.add_syscall_fsync(dim, latency_ns),
            EventType::SyscallFdatasync => self.add_syscall_fdatasync(dim, latency_ns),
            EventType::SyscallPwrite => self.add_syscall_pwrite(dim, latency_ns),
            _ => return,
        }
    }

    #[inline(always)]
    pub fn add_syscall_read(&mut self, dim: BasicDimension, latency_ns: u64) {
        get_or_default_mut(&mut self.syscall_read, dim).record(latency_ns);
    }

    #[inline(always)]
    pub fn add_syscall_write(&mut self, dim: BasicDimension, latency_ns: u64) {
        get_or_default_mut(&mut self.syscall_write, dim).record(latency_ns);
    }

    #[inline(always)]
    pub fn add_syscall_futex(&mut self, dim: BasicDimension, latency_ns: u64) {
        get_or_default_mut(&mut self.syscall_futex, dim).record(latency_ns);
    }

    #[inline(always)]
    pub fn add_syscall_mmap(&mut self, dim: BasicDimension, latency_ns: u64) {
        get_or_default_mut(&mut self.syscall_mmap, dim).record(latency_ns);
    }

    #[inline(always)]
    pub fn add_syscall_epoll_wait(&mut self, dim: BasicDimension, latency_ns: u64) {
        get_or_default_mut(&mut self.basic_cold_metrics, dim).record_syscall_epoll_wait(latency_ns);
    }

    #[inline(always)]
    pub fn add_syscall_fsync(&mut self, dim: BasicDimension, latency_ns: u64) {
        get_or_default_mut(&mut self.syscall_fsync, dim).record(latency_ns);
    }

    #[inline(always)]
    pub fn add_syscall_fdatasync(&mut self, dim: BasicDimension, latency_ns: u64) {
        get_or_default_mut(&mut self.basic_cold_metrics, dim).record_syscall_fdatasync(latency_ns);
    }

    #[inline(always)]
    pub fn add_syscall_pwrite(&mut self, dim: BasicDimension, latency_ns: u64) {
        get_or_default_mut(&mut self.basic_cold_metrics, dim).record_syscall_pwrite(latency_ns);
    }

    /// Adds a network I/O event.
    pub fn add_net_io(&mut self, dim: NetworkDimension, bytes: i64) {
        if dim.direction() == Direction::RX as u8 {
            self.add_net_io_rx(tcp_metrics_key_for_network(dim), bytes);
        } else {
            self.add_net_io_tx(tcp_metrics_key_for_network(dim), bytes);
        }
    }

    #[inline(always)]
    pub fn add_net_io_tx(&mut self, dim: TCPMetricsDimension, bytes: i64) {
        add_counter_value(&mut self.net_io_tx, dim, bytes);
    }

    #[inline(always)]
    pub fn add_net_io_rx(&mut self, dim: TCPMetricsDimension, bytes: i64) {
        add_counter_value(&mut self.net_io_rx, dim, bytes);
    }

    /// Adds a TCP retransmit event.
    pub fn add_tcp_retransmit(&mut self, dim: NetworkDimension, bytes: i64) {
        self.add_tcp_retransmit_dim(tcp_metrics_key_for_network(dim), bytes);
    }

    #[inline(always)]
    pub fn add_tcp_retransmit_dim(&mut self, dim: TCPMetricsDimension, bytes: i64) {
        add_counter_value(&mut self.tcp_retransmit, dim, bytes);
    }

    /// Adds TCP TX bytes together with inline TCP metrics.
    pub fn add_net_io_with_tcp_metrics(
        &mut self,
        dim: NetworkDimension,
        bytes: i64,
        rtt_us: u32,
        cwnd: u32,
    ) {
        self.add_net_io_with_tcp_metrics_dim(tcp_metrics_key_for_network(dim), bytes, rtt_us, cwnd);
    }

    #[inline(always)]
    pub fn add_net_io_with_tcp_metrics_dim(
        &mut self,
        dim: TCPMetricsDimension,
        bytes: i64,
        rtt_us: u32,
        cwnd: u32,
    ) {
        record_tcp_tx(&mut self.tcp_tx, dim, bytes, rtt_us, cwnd);
    }

    /// Adds TCP metrics (RTT and CWND).
    ///
    /// Kept for tests and compatibility helpers that still construct a
    /// TCP-only dimension directly.
    pub fn add_tcp_metrics(&mut self, dim: TCPMetricsDimension, rtt_us: u32, cwnd: u32) {
        record_tcp_metrics(&mut self.tcp_tx, dim, rtt_us, cwnd);
    }

    /// Adds a disk I/O event with latency, bytes, and queue depth.
    pub fn add_disk_io(
        &mut self,
        dim: DiskDimension,
        latency_ns: u64,
        bytes: u32,
        queue_depth: u32,
    ) {
        if dim.rw() == 0 {
            record_disk(&mut self.disk_io_read, dim, latency_ns, bytes, queue_depth);
        } else {
            record_disk(&mut self.disk_io_write, dim, latency_ns, bytes, queue_depth);
        }
    }

    /// Adds a block merge event.
    pub fn add_block_merge(&mut self, dim: DiskDimension, bytes: u32) {
        add_counter_value(&mut self.block_merge, dim, i64::from(bytes));
    }

    /// Records scheduler on-CPU latency distribution from sched_switch events.
    pub fn add_sched_on_cpu(&mut self, dim: BasicDimension, on_cpu_ns: u64) {
        get_or_default_mut(&mut self.basic_sched_metrics, dim).record_sched_on_cpu(on_cpu_ns);
    }

    /// Adds per-core on-CPU time used for utilization aggregation.
    pub fn add_cpu_on_core(&mut self, dim: BasicDimension, cpu_id: u32, on_cpu_ns: u64) {
        self.add_cpu_on_core_dim(CpuCoreDimension::from_basic(dim, cpu_id), on_cpu_ns);
    }

    /// Adds per-core on-CPU time using an already packed core dimension.
    #[inline(always)]
    pub fn add_cpu_on_core_dim(&mut self, dim: CpuCoreDimension, on_cpu_ns: u64) {
        add_counter_value(&mut self.cpu_on_core, dim, on_cpu_ns as i64);
    }

    /// Adds a scheduler switch event (on-CPU time).
    ///
    /// This helper is kept for direct tests/benchmarks. Production code uses
    /// carried scheduler state and calls `add_sched_on_cpu`/`add_cpu_on_core`
    /// separately to keep window accounting exact across rotations.
    pub fn add_sched_switch(&mut self, dim: BasicDimension, on_cpu_ns: u64, cpu_id: u32) {
        self.add_sched_on_cpu(dim, on_cpu_ns);
        self.add_cpu_on_core(dim, cpu_id, on_cpu_ns);
    }

    /// Adds scheduler runqueue and off-CPU latency.
    pub fn add_sched_runqueue(&mut self, dim: BasicDimension, runqueue_ns: u64, off_cpu_ns: u64) {
        if runqueue_ns > 0 || off_cpu_ns > 0 {
            get_or_default_mut(&mut self.basic_sched_metrics, dim)
                .record_sched_wait(runqueue_ns, off_cpu_ns);
        }
    }

    /// Adds a page fault event.
    pub fn add_page_fault(&mut self, dim: BasicDimension, major: bool) {
        get_or_default_mut(&mut self.basic_metrics, dim).record_page_fault(major);
    }

    /// Adds an FD open event.
    pub fn add_fd_open(&mut self, dim: BasicDimension) {
        get_or_default_mut(&mut self.basic_metrics, dim).record_fd_open();
    }

    /// Adds an FD close event.
    pub fn add_fd_close(&mut self, dim: BasicDimension) {
        get_or_default_mut(&mut self.basic_metrics, dim).record_fd_close();
    }

    /// Adds a memory reclaim event.
    pub fn add_mem_reclaim(&mut self, dim: BasicDimension, duration_ns: u64) {
        get_or_default_mut(&mut self.basic_cold_metrics, dim).record_mem_reclaim(duration_ns);
    }

    /// Adds a memory compaction event.
    pub fn add_mem_compaction(&mut self, dim: BasicDimension, duration_ns: u64) {
        get_or_default_mut(&mut self.basic_cold_metrics, dim).record_mem_compaction(duration_ns);
    }

    /// Adds a swap-in event.
    pub fn add_swap_in(&mut self, dim: BasicDimension, pages: u64) {
        get_or_default_mut(&mut self.basic_cold_metrics, dim).record_swap_in(pages);
    }

    /// Adds a swap-out event.
    pub fn add_swap_out(&mut self, dim: BasicDimension, pages: u64) {
        get_or_default_mut(&mut self.basic_cold_metrics, dim).record_swap_out(pages);
    }

    /// Adds an OOM kill event.
    pub fn add_oom_kill(&mut self, dim: BasicDimension) {
        get_or_default_mut(&mut self.basic_cold_metrics, dim).record_oom_kill();
    }

    /// Adds a process exit event.
    pub fn add_process_exit(&mut self, dim: BasicDimension) {
        get_or_default_mut(&mut self.basic_cold_metrics, dim).record_process_exit();
    }

    /// Adds a TCP state change event.
    pub fn add_tcp_state_change(&mut self, dim: BasicDimension) {
        get_or_default_mut(&mut self.basic_cold_metrics, dim).record_tcp_state_change();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sink::aggregated::aggregate::CountAggregate;

    fn test_buffer() -> Buffer {
        Buffer::new(
            SystemTime::now(),
            100,
            SystemTime::now(),
            false,
            false,
            false,
            16,
        )
    }

    #[test]
    fn test_add_syscall_read() {
        let mut buf = test_buffer();
        let dim = BasicDimension::new(1, 1);

        buf.add_syscall(EventType::SyscallRead, dim, 5_000);
        buf.add_syscall(EventType::SyscallRead, dim, 10_000);

        let snap = buf.syscall_read.get(&dim).expect("entry exists").snapshot();
        assert_eq!(snap.count, 2);
        assert_eq!(snap.sum, 15_000);
    }

    #[test]
    fn test_add_syscall_epoll_wait_uses_cold_basic_map() {
        let mut buf = test_buffer();
        let dim = BasicDimension::new(1, 1);

        buf.add_syscall(EventType::SyscallEpollWait, dim, 8_000);

        assert!(buf.basic_metrics.get(&dim).is_none());
        let entry = buf.basic_cold_metrics.get(&dim).expect("cold entry exists");
        let snap = entry.syscall_epoll_wait_snapshot();
        assert_eq!(snap.count, 1);
        assert_eq!(snap.sum, 8_000);
    }

    #[test]
    fn test_add_syscall_unknown_type_is_noop() {
        let mut buf = test_buffer();
        let dim = BasicDimension::new(1, 1);

        // DiskIO is not a syscall type, should be ignored.
        buf.add_syscall(EventType::DiskIO, dim, 5_000);
        assert!(buf.basic_metrics.is_empty());
        assert!(buf.syscall_read.is_empty());
        assert!(buf.syscall_write.is_empty());
        assert!(buf.syscall_futex.is_empty());
        assert!(buf.syscall_mmap.is_empty());
        assert!(buf.syscall_fsync.is_empty());
    }

    #[test]
    fn test_add_net_io() {
        let mut buf = test_buffer();
        let dim = NetworkDimension::new(1, 1, 3, 0);
        let key = TCPMetricsDimension::new(1, 1, 3);

        buf.add_net_io(dim, 1024);
        buf.add_net_io(dim, 2048);

        let entry = buf.net_io_tx.get(&key).expect("entry exists");
        let snap = entry.snapshot();
        assert_eq!(snap.count, 2);
        assert_eq!(snap.sum, 3072);
    }

    #[test]
    fn test_add_net_io_separates_tx_and_rx_maps() {
        let mut buf = test_buffer();
        let tx = NetworkDimension::new(1, 1, 3, Direction::TX as u8);
        let rx = NetworkDimension::new(1, 1, 3, Direction::RX as u8);
        let key = TCPMetricsDimension::new(1, 1, 3);

        buf.add_net_io(tx, 1024);
        buf.add_net_io(rx, 2048);

        assert_eq!(
            buf.net_io_tx
                .get(&key)
                .expect("tx entry exists")
                .snapshot()
                .sum,
            1024
        );
        assert_eq!(
            buf.net_io_rx
                .get(&key)
                .expect("rx entry exists")
                .snapshot()
                .sum,
            2048
        );
    }

    #[test]
    fn test_add_tcp_metrics() {
        let mut buf = test_buffer();
        let dim = TCPMetricsDimension::new(1, 1, 3);

        buf.add_tcp_metrics(dim, 100, 65535);

        let metrics = buf.tcp_tx.get(&dim).expect("tcp metrics exist");
        assert_eq!(metrics.rtt_snapshot().sum, 100);
        assert_eq!(metrics.cwnd_snapshot().sum, 65535);
    }

    #[test]
    fn test_get_or_default_mut_cache_handles_repeated_hits_and_new_keys() {
        let mut map = fast_map_with_capacity::<BasicDimension, CountAggregate>(1);
        let key1 = BasicDimension::new(1, 1);
        let key2 = BasicDimension::new(2, 1);

        get_or_default_mut(&mut map, key1).add_count(1);
        get_or_default_mut(&mut map, key1).add_count(2);
        get_or_default_mut(&mut map, key2).add_count(3);
        get_or_default_mut(&mut map, key1).add_count(4);

        assert_eq!(map.get(&key1).expect("key1 exists").snapshot().count, 7);
        assert_eq!(map.get(&key2).expect("key2 exists").snapshot().count, 3);
    }

    #[test]
    fn test_add_net_io_with_tcp_metrics() {
        let mut buf = test_buffer();
        let dim = NetworkDimension::new(1, 1, 3, 0);
        let key = TCPMetricsDimension::new(1, 1, 3);

        buf.add_net_io_with_tcp_metrics(dim, 1500, 100, 65535);

        let metrics = buf.tcp_tx.get(&key).expect("tcp tx metrics exist");
        assert_eq!(metrics.bytes_snapshot().sum, 1500);
        assert_eq!(metrics.rtt_snapshot().sum, 100);
        assert_eq!(metrics.cwnd_snapshot().sum, 65535);
    }

    #[test]
    fn test_add_disk_io() {
        let mut buf = test_buffer();
        let dim = DiskDimension::new(1, 1, 259, 1);

        buf.add_disk_io(dim, 50_000, 4096, 3);

        let disk = buf.disk_io_write.get(&dim).expect("disk aggregate exists");
        assert_eq!(disk.latency_snapshot().count, 1);
        assert_eq!(disk.bytes_snapshot().sum, 4096);
        assert_eq!(disk.queue_depth_snapshot().sum, 3);
    }

    #[test]
    fn test_add_sched_switch_tracks_per_core() {
        let mut buf = test_buffer();
        let dim = BasicDimension::new(1, 1);

        buf.add_sched_switch(dim, 1_000, 2);
        buf.add_sched_switch(dim, 2_000, 2);
        buf.add_sched_switch(dim, 500, 4);

        let on_cpu = buf
            .basic_sched_metrics
            .get(&dim)
            .expect("sched_on_cpu exists");
        let on_cpu_snap = on_cpu.sched_on_cpu_snapshot();
        assert_eq!(on_cpu_snap.count, 3);
        assert_eq!(on_cpu_snap.sum, 3_500);

        let core2 = buf
            .cpu_on_core
            .get(&CpuCoreDimension::new(1, 1, 2))
            .expect("core 2 exists");
        let core2_snap = core2.snapshot();
        assert_eq!(core2_snap.count, 2);
        assert_eq!(core2_snap.sum, 3_000);

        let core4 = buf
            .cpu_on_core
            .get(&CpuCoreDimension::new(1, 1, 4))
            .expect("core 4 exists");
        let core4_snap = core4.snapshot();
        assert_eq!(core4_snap.count, 1);
        assert_eq!(core4_snap.sum, 500);
    }

    #[test]
    fn test_add_sched_runqueue_skips_zero() {
        let mut buf = test_buffer();
        let dim = BasicDimension::new(1, 1);

        buf.add_sched_runqueue(dim, 0, 5_000);
        let first = buf
            .basic_sched_metrics
            .get(&dim)
            .expect("sched wait exists");
        assert_eq!(first.sched_runqueue_snapshot().count, 0);
        assert_eq!(first.sched_off_cpu_snapshot().count, 1);

        let mut buf2 = test_buffer();
        buf2.add_sched_runqueue(dim, 5_000, 0);
        let second = buf2
            .basic_sched_metrics
            .get(&dim)
            .expect("sched wait exists");
        assert_eq!(second.sched_runqueue_snapshot().count, 1);
        assert_eq!(second.sched_off_cpu_snapshot().count, 0);
    }

    #[test]
    fn test_add_page_fault() {
        let mut buf = test_buffer();
        let dim = BasicDimension::new(1, 1);

        buf.add_page_fault(dim, true);
        buf.add_page_fault(dim, false);
        buf.add_page_fault(dim, false);

        let page_faults = buf.basic_metrics.get(&dim).expect("page faults exist");
        assert_eq!(page_faults.page_fault_major_snapshot().count, 1);
        assert_eq!(page_faults.page_fault_minor_snapshot().count, 2);
    }

    #[test]
    fn test_add_fd_open_close() {
        let mut buf = test_buffer();
        let dim = BasicDimension::new(1, 1);

        buf.add_fd_open(dim);
        buf.add_fd_open(dim);
        buf.add_fd_close(dim);

        let fd = buf.basic_metrics.get(&dim).expect("fd aggregate exists");
        assert_eq!(fd.fd_open_snapshot().count, 2);
        assert_eq!(fd.fd_close_snapshot().count, 1);
    }

    #[test]
    fn test_fast_map_preserves_entries() {
        let mut map = fast_map_with_capacity::<u32, u32>(32);

        for key in 0..10 {
            *get_or_default_mut(&mut map, key) += 1;
        }

        assert_eq!(map.len(), 10);
        for key in 0..10 {
            assert_eq!(map.get(&key), Some(&1));
        }
    }

    #[test]
    fn test_fast_map_single_entry_reuses_hash_storage() {
        let mut map = fast_map_with_capacity::<u32, u32>(4);

        *get_or_default_mut(&mut map, 10) += 1;
        *get_or_default_mut(&mut map, 10) += 1;

        assert_eq!(map.get(&10), Some(&2));
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn test_buffer_reset_clears_aggregates_and_updates_metadata() {
        let start = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(10);
        let slot_start = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(12);
        let mut buf = Buffer::new(start, 1, slot_start, false, false, false, 8);
        let dim = BasicDimension::new(1, 1);

        buf.add_syscall(EventType::SyscallRead, dim, 5_000);
        buf.add_fd_open(dim);

        let new_start = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(20);
        let new_slot_start = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(24);
        buf.reset(new_start, 2, new_slot_start, true, true, true, 16);

        assert_eq!(buf.start_time, new_start);
        assert_eq!(buf.wallclock_slot, 2);
        assert_eq!(buf.wallclock_slot_start, new_slot_start);
        assert!(buf.cl_syncing);
        assert!(buf.el_optimistic);
        assert!(buf.el_offline);
        assert_eq!(buf.system_cores, 16);
        assert!(buf.syscall_read.is_empty());
        assert!(buf.syscall_write.is_empty());
        assert!(buf.syscall_futex.is_empty());
        assert!(buf.syscall_mmap.is_empty());
        assert!(buf.syscall_fsync.is_empty());
        assert!(buf.basic_metrics.is_empty());
        assert!(buf.basic_sched_metrics.is_empty());
        assert!(buf.basic_cold_metrics.is_empty());
        assert!(buf.net_io_tx.is_empty());
        assert!(buf.net_io_rx.is_empty());

        buf.add_syscall(EventType::SyscallRead, dim, 7_500);
        let snap = buf
            .syscall_read
            .get(&dim)
            .expect("entry exists after reset")
            .snapshot();
        assert_eq!(snap.count, 1);
        assert_eq!(snap.sum, 7_500);
    }
}
