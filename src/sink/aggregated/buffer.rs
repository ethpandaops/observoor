use std::hash::Hash;
use std::hash::{BuildHasherDefault, Hasher};
use std::time::SystemTime;

use hashbrown::{
    hash_map::{IntoIter as HashMapIntoIter, Iter as HashMapIter, RawEntryMut},
    HashMap,
};

use crate::tracer::event::EventType;

use super::aggregate::{
    CountAggregate, CounterAggregate, DiskAggregate, FdAggregate, LatencyAggregate,
    SchedWaitAggregate, TcpTxAggregate,
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
}

pub type FastMapIter<'a, K, V> = HashMapIter<'a, K, V>;
pub type FastMapIntoIter<K, V> = HashMapIntoIter<K, V>;

impl<K, V> FastMap<K, V> {
    #[inline(always)]
    fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: HashMap::with_capacity_and_hasher(capacity, FastHashBuilder::default()),
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
    let hash = key.precomputed_hash();

    match map
        .inner
        .raw_entry_mut()
        .from_key_hashed_nocheck(hash, &key)
    {
        RawEntryMut::Occupied(entry) => entry.into_mut(),
        RawEntryMut::Vacant(entry) => entry.insert_hashed_nocheck(hash, key, V::default()).1,
    }
}

#[inline(always)]
pub(crate) fn record_latency<K>(map: &mut FastMap<K, LatencyAggregate>, key: K, latency_ns: u64)
where
    K: FastMapKey,
{
    get_or_default_mut(map, key).record(latency_ns);
}

#[inline(always)]
fn add_counter_value<K>(map: &mut FastMap<K, CounterAggregate>, key: K, value: i64)
where
    K: FastMapKey,
{
    get_or_default_mut(map, key).add(value);
}

#[inline(always)]
fn add_count_only<K>(map: &mut FastMap<K, CountAggregate>, key: K, count: u32)
where
    K: FastMapKey,
{
    get_or_default_mut(map, key).add_count(count);
}

#[inline(always)]
fn record_sched_wait(
    map: &mut FastMap<BasicDimension, SchedWaitAggregate>,
    key: BasicDimension,
    runqueue_ns: u64,
    off_cpu_ns: u64,
) {
    get_or_default_mut(map, key).record(runqueue_ns, off_cpu_ns);
}

#[inline(always)]
fn record_fd_open(map: &mut FastMap<BasicDimension, FdAggregate>, key: BasicDimension) {
    get_or_default_mut(map, key).record_open();
}

#[inline(always)]
fn record_fd_close(map: &mut FastMap<BasicDimension, FdAggregate>, key: BasicDimension) {
    get_or_default_mut(map, key).record_close();
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
    map: &mut FastMap<NetworkDimension, TcpTxAggregate>,
    key: NetworkDimension,
    bytes: i64,
    rtt_us: u32,
    cwnd: u32,
) {
    get_or_default_mut(map, key).record(bytes, rtt_us, cwnd);
}

#[inline(always)]
fn record_tcp_metrics(
    map: &mut FastMap<NetworkDimension, TcpTxAggregate>,
    key: NetworkDimension,
    rtt_us: u32,
    cwnd: u32,
) {
    get_or_default_mut(map, key).record_metrics(rtt_us, cwnd);
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

    // --- Syscalls (BasicDimension -> LatencyAggregate) ---
    pub syscall_read: FastMap<BasicDimension, LatencyAggregate>,
    pub syscall_write: FastMap<BasicDimension, LatencyAggregate>,
    pub syscall_futex: FastMap<BasicDimension, LatencyAggregate>,
    pub syscall_mmap: FastMap<BasicDimension, LatencyAggregate>,
    pub syscall_epoll_wait: FastMap<BasicDimension, LatencyAggregate>,
    pub syscall_fsync: FastMap<BasicDimension, LatencyAggregate>,
    pub syscall_fdatasync: FastMap<BasicDimension, LatencyAggregate>,
    pub syscall_pwrite: FastMap<BasicDimension, LatencyAggregate>,

    // --- Network (NetworkDimension -> CounterAggregate) ---
    pub net_io: FastMap<NetworkDimension, CounterAggregate>,
    pub tcp_retransmit: FastMap<NetworkDimension, CounterAggregate>,

    // --- TCP TX bytes + metrics (NetworkDimension -> TcpTxAggregate) ---
    pub tcp_tx: FastMap<NetworkDimension, TcpTxAggregate>,

    // --- Disk (DiskDimension) ---
    pub disk_io: FastMap<DiskDimension, DiskAggregate>,
    pub block_merge: FastMap<DiskDimension, CounterAggregate>,

    // --- Scheduler (BasicDimension -> LatencyAggregate) ---
    pub sched_on_cpu: FastMap<BasicDimension, LatencyAggregate>,
    pub cpu_on_core: FastMap<CpuCoreDimension, CounterAggregate>,
    pub sched_wait: FastMap<BasicDimension, SchedWaitAggregate>,

    // --- Page faults (BasicDimension -> CountAggregate) ---
    pub page_fault_major: FastMap<BasicDimension, CountAggregate>,
    pub page_fault_minor: FastMap<BasicDimension, CountAggregate>,

    // --- FD operations (BasicDimension -> CountAggregate) ---
    pub fd_ops: FastMap<BasicDimension, FdAggregate>,

    // --- Memory pressure ---
    pub mem_reclaim: FastMap<BasicDimension, LatencyAggregate>,
    pub mem_compaction: FastMap<BasicDimension, LatencyAggregate>,
    pub swap_in: FastMap<BasicDimension, CounterAggregate>,
    pub swap_out: FastMap<BasicDimension, CounterAggregate>,
    pub oom_kill: FastMap<BasicDimension, CountAggregate>,
    pub process_exit: FastMap<BasicDimension, CountAggregate>,
    pub tcp_state_change: FastMap<BasicDimension, CountAggregate>,
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
            // Syscalls.
            syscall_read: fast_map_with_capacity(16),
            syscall_write: fast_map_with_capacity(16),
            syscall_futex: fast_map_with_capacity(16),
            syscall_mmap: fast_map_with_capacity(16),
            syscall_epoll_wait: fast_map_with_capacity(16),
            syscall_fsync: fast_map_with_capacity(16),
            syscall_fdatasync: fast_map_with_capacity(16),
            syscall_pwrite: fast_map_with_capacity(16),
            // Network.
            net_io: fast_map_with_capacity(64),
            tcp_retransmit: fast_map_with_capacity(32),
            // TCP TX bytes + metrics.
            tcp_tx: fast_map_with_capacity(32),
            // Disk.
            disk_io: fast_map_with_capacity(16),
            block_merge: fast_map_with_capacity(16),
            // Scheduler.
            sched_on_cpu: fast_map_with_capacity(16),
            cpu_on_core: fast_map_with_capacity(64),
            sched_wait: fast_map_with_capacity(16),
            // Page faults.
            page_fault_major: fast_map_with_capacity(16),
            page_fault_minor: fast_map_with_capacity(16),
            // FD operations.
            fd_ops: fast_map_with_capacity(16),
            // Memory pressure.
            mem_reclaim: fast_map_with_capacity(8),
            mem_compaction: fast_map_with_capacity(8),
            swap_in: fast_map_with_capacity(8),
            swap_out: fast_map_with_capacity(8),
            oom_kill: fast_map_with_capacity(8),
            process_exit: fast_map_with_capacity(8),
            tcp_state_change: fast_map_with_capacity(8),
        }
    }

    /// Adds a syscall latency event to the appropriate map.
    pub fn add_syscall(&mut self, event_type: EventType, dim: BasicDimension, latency_ns: u64) {
        let map = match event_type {
            EventType::SyscallRead => &mut self.syscall_read,
            EventType::SyscallWrite => &mut self.syscall_write,
            EventType::SyscallFutex => &mut self.syscall_futex,
            EventType::SyscallMmap => &mut self.syscall_mmap,
            EventType::SyscallEpollWait => &mut self.syscall_epoll_wait,
            EventType::SyscallFsync => &mut self.syscall_fsync,
            EventType::SyscallFdatasync => &mut self.syscall_fdatasync,
            EventType::SyscallPwrite => &mut self.syscall_pwrite,
            _ => return,
        };
        record_latency(map, dim, latency_ns);
    }

    /// Adds a network I/O event.
    pub fn add_net_io(&mut self, dim: NetworkDimension, bytes: i64) {
        add_counter_value(&mut self.net_io, dim, bytes);
    }

    /// Adds a TCP retransmit event.
    pub fn add_tcp_retransmit(&mut self, dim: NetworkDimension, bytes: i64) {
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
        record_tcp_tx(&mut self.tcp_tx, dim, bytes, rtt_us, cwnd);
    }

    /// Adds TCP metrics (RTT and CWND).
    ///
    /// Kept for tests and compatibility helpers that still construct a
    /// TCP-only dimension directly.
    pub fn add_tcp_metrics(&mut self, dim: TCPMetricsDimension, rtt_us: u32, cwnd: u32) {
        let tx_dim = NetworkDimension::new(dim.pid(), dim.client_type(), dim.port_label(), 0);
        record_tcp_metrics(&mut self.tcp_tx, tx_dim, rtt_us, cwnd);
    }

    /// Adds a disk I/O event with latency, bytes, and queue depth.
    pub fn add_disk_io(
        &mut self,
        dim: DiskDimension,
        latency_ns: u64,
        bytes: u32,
        queue_depth: u32,
    ) {
        record_disk(&mut self.disk_io, dim, latency_ns, bytes, queue_depth);
    }

    /// Adds a block merge event.
    pub fn add_block_merge(&mut self, dim: DiskDimension, bytes: u32) {
        add_counter_value(&mut self.block_merge, dim, i64::from(bytes));
    }

    /// Records scheduler on-CPU latency distribution from sched_switch events.
    pub fn add_sched_on_cpu(&mut self, dim: BasicDimension, on_cpu_ns: u64) {
        record_latency(&mut self.sched_on_cpu, dim, on_cpu_ns);
    }

    /// Adds per-core on-CPU time used for utilization aggregation.
    pub fn add_cpu_on_core(&mut self, dim: BasicDimension, cpu_id: u32, on_cpu_ns: u64) {
        add_counter_value(
            &mut self.cpu_on_core,
            CpuCoreDimension::from_basic(dim, cpu_id),
            on_cpu_ns as i64,
        );
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
            record_sched_wait(&mut self.sched_wait, dim, runqueue_ns, off_cpu_ns);
        }
    }

    /// Adds a page fault event.
    pub fn add_page_fault(&mut self, dim: BasicDimension, major: bool) {
        if major {
            add_count_only(&mut self.page_fault_major, dim, 1);
        } else {
            add_count_only(&mut self.page_fault_minor, dim, 1);
        }
    }

    /// Adds an FD open event.
    pub fn add_fd_open(&mut self, dim: BasicDimension) {
        record_fd_open(&mut self.fd_ops, dim);
    }

    /// Adds an FD close event.
    pub fn add_fd_close(&mut self, dim: BasicDimension) {
        record_fd_close(&mut self.fd_ops, dim);
    }

    /// Adds a memory reclaim event.
    pub fn add_mem_reclaim(&mut self, dim: BasicDimension, duration_ns: u64) {
        record_latency(&mut self.mem_reclaim, dim, duration_ns);
    }

    /// Adds a memory compaction event.
    pub fn add_mem_compaction(&mut self, dim: BasicDimension, duration_ns: u64) {
        record_latency(&mut self.mem_compaction, dim, duration_ns);
    }

    /// Adds a swap-in event.
    pub fn add_swap_in(&mut self, dim: BasicDimension, pages: u64) {
        add_counter_value(&mut self.swap_in, dim, pages as i64);
    }

    /// Adds a swap-out event.
    pub fn add_swap_out(&mut self, dim: BasicDimension, pages: u64) {
        add_counter_value(&mut self.swap_out, dim, pages as i64);
    }

    /// Adds an OOM kill event.
    pub fn add_oom_kill(&mut self, dim: BasicDimension) {
        add_count_only(&mut self.oom_kill, dim, 1);
    }

    /// Adds a process exit event.
    pub fn add_process_exit(&mut self, dim: BasicDimension) {
        add_count_only(&mut self.process_exit, dim, 1);
    }

    /// Adds a TCP state change event.
    pub fn add_tcp_state_change(&mut self, dim: BasicDimension) {
        add_count_only(&mut self.tcp_state_change, dim, 1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

        let entry = buf.syscall_read.get(&dim).expect("entry exists");
        let snap = entry.snapshot();
        assert_eq!(snap.count, 2);
        assert_eq!(snap.sum, 15_000);
    }

    #[test]
    fn test_add_syscall_unknown_type_is_noop() {
        let mut buf = test_buffer();
        let dim = BasicDimension::new(1, 1);

        // DiskIO is not a syscall type, should be ignored.
        buf.add_syscall(EventType::DiskIO, dim, 5_000);
        assert!(buf.syscall_read.is_empty());
    }

    #[test]
    fn test_add_net_io() {
        let mut buf = test_buffer();
        let dim = NetworkDimension::new(1, 1, 3, 0);

        buf.add_net_io(dim, 1024);
        buf.add_net_io(dim, 2048);

        let entry = buf.net_io.get(&dim).expect("entry exists");
        let snap = entry.snapshot();
        assert_eq!(snap.count, 2);
        assert_eq!(snap.sum, 3072);
    }

    #[test]
    fn test_add_tcp_metrics() {
        let mut buf = test_buffer();
        let dim = TCPMetricsDimension::new(1, 1, 3);

        buf.add_tcp_metrics(dim, 100, 65535);

        let metrics = buf
            .tcp_tx
            .get(&NetworkDimension::new(1, 1, 3, 0))
            .expect("tcp metrics exist");
        assert_eq!(metrics.rtt_snapshot().sum, 100);
        assert_eq!(metrics.cwnd_snapshot().sum, 65535);
    }

    #[test]
    fn test_add_net_io_with_tcp_metrics() {
        let mut buf = test_buffer();
        let dim = NetworkDimension::new(1, 1, 3, 0);

        buf.add_net_io_with_tcp_metrics(dim, 1500, 100, 65535);

        let metrics = buf.tcp_tx.get(&dim).expect("tcp tx metrics exist");
        assert_eq!(metrics.bytes_snapshot().sum, 1500);
        assert_eq!(metrics.rtt_snapshot().sum, 100);
        assert_eq!(metrics.cwnd_snapshot().sum, 65535);
    }

    #[test]
    fn test_add_disk_io() {
        let mut buf = test_buffer();
        let dim = DiskDimension::new(1, 1, 259, 1);

        buf.add_disk_io(dim, 50_000, 4096, 3);

        let disk = buf.disk_io.get(&dim).expect("disk aggregate exists");
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

        let on_cpu = buf.sched_on_cpu.get(&dim).expect("sched_on_cpu exists");
        let on_cpu_snap = on_cpu.snapshot();
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
        let first = buf.sched_wait.get(&dim).expect("sched wait exists");
        assert_eq!(first.runqueue_snapshot().count, 0);
        assert_eq!(first.off_cpu_snapshot().count, 1);

        let mut buf2 = test_buffer();
        buf2.add_sched_runqueue(dim, 5_000, 0);
        let second = buf2.sched_wait.get(&dim).expect("sched wait exists");
        assert_eq!(second.runqueue_snapshot().count, 1);
        assert_eq!(second.off_cpu_snapshot().count, 0);
    }

    #[test]
    fn test_add_page_fault() {
        let mut buf = test_buffer();
        let dim = BasicDimension::new(1, 1);

        buf.add_page_fault(dim, true);
        buf.add_page_fault(dim, false);
        buf.add_page_fault(dim, false);

        let major = buf.page_fault_major.get(&dim).expect("major exists");
        assert_eq!(major.snapshot().count, 1);
        let minor = buf.page_fault_minor.get(&dim).expect("minor exists");
        assert_eq!(minor.snapshot().count, 2);
    }

    #[test]
    fn test_add_fd_open_close() {
        let mut buf = test_buffer();
        let dim = BasicDimension::new(1, 1);

        buf.add_fd_open(dim);
        buf.add_fd_open(dim);
        buf.add_fd_close(dim);

        let fd = buf.fd_ops.get(&dim).expect("fd aggregate exists");
        assert_eq!(fd.open_snapshot().count, 2);
        assert_eq!(fd.close_snapshot().count, 1);
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
}
