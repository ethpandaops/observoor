use std::hash::{BuildHasherDefault, Hash, Hasher};
use std::slice::Iter as SliceIter;
use std::time::SystemTime;

use hashbrown::hash_map::Iter as HashMapIter;
use hashbrown::HashMap;

use crate::tracer::event::EventType;

use super::aggregate::{
    CounterAggregate, DiskAggregate, LatencyAggregate, SchedWaitAggregate, TcpMetricsAggregate,
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
pub(crate) type FastMap<K, V> = HashMap<K, V, FastHashBuilder>;

pub(crate) fn fast_map_with_capacity<K, V>(capacity: usize) -> FastMap<K, V> {
    HashMap::with_capacity_and_hasher(capacity, FastHashBuilder::default())
}

/// Stores a small number of common keys inline and spills to a hash map only
/// when cardinality exceeds the inline capacity.
#[doc(hidden)]
pub struct InlineOrMap<K, V, const INLINE_CAP: usize = 1> {
    inline: [Option<(K, V)>; INLINE_CAP],
    inline_len: usize,
    spill: FastMap<K, V>,
}

#[doc(hidden)]
pub struct InlineOrMapIter<'a, K, V> {
    inline: SliceIter<'a, Option<(K, V)>>,
    spill: HashMapIter<'a, K, V>,
}

impl<'a, K, V> Iterator for InlineOrMapIter<'a, K, V> {
    type Item = (&'a K, &'a V);

    fn next(&mut self) -> Option<Self::Item> {
        for slot in self.inline.by_ref() {
            if let Some((key, value)) = slot.as_ref() {
                return Some((key, value));
            }
        }

        self.spill.next()
    }
}

impl<K, V, const INLINE_CAP: usize> InlineOrMap<K, V, INLINE_CAP>
where
    K: Copy + Eq + Hash,
{
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inline: std::array::from_fn(|_| None),
            inline_len: 0,
            spill: fast_map_with_capacity(capacity),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.inline_len == 0 && self.spill.is_empty()
    }

    pub fn len(&self) -> usize {
        self.spill.len() + self.inline_len
    }

    pub fn get(&self, key: &K) -> Option<&V> {
        self.inline
            .iter()
            .find_map(|slot| match slot.as_ref() {
                Some((inline_key, value)) if inline_key == key => Some(value),
                _ => None,
            })
            .or_else(|| self.spill.get(key))
    }

    pub fn contains_key(&self, key: &K) -> bool {
        self.get(key).is_some()
    }

    fn spill_inline_entries(&mut self) {
        for slot in &mut self.inline {
            if let Some((key, value)) = slot.take() {
                self.spill.insert(key, value);
            }
        }
        self.inline_len = 0;
    }

    pub(crate) fn get_or_insert_with(&mut self, key: K, default: impl FnOnce() -> V) -> &mut V {
        let mut empty_slot = None;
        for idx in 0..INLINE_CAP {
            match self.inline[idx].as_ref() {
                Some((inline_key, _)) if *inline_key == key => {
                    return &mut self.inline[idx].as_mut().expect("inline entry exists").1;
                }
                None if empty_slot.is_none() => {
                    empty_slot = Some(idx);
                }
                _ => {}
            }
        }

        if self.spill.is_empty() {
            if let Some(idx) = empty_slot {
                self.inline[idx] = Some((key, default()));
                self.inline_len += 1;
                return &mut self.inline[idx].as_mut().expect("inline entry inserted").1;
            }

            self.spill_inline_entries();
        }

        self.spill.entry(key).or_insert_with(default)
    }

    pub(crate) fn get_or_default_mut(&mut self, key: K) -> &mut V
    where
        V: Default,
    {
        self.get_or_insert_with(key, V::default)
    }

    pub fn iter(&self) -> InlineOrMapIter<'_, K, V> {
        InlineOrMapIter {
            inline: self.inline.iter(),
            spill: self.spill.iter(),
        }
    }
}

pub(crate) type BasicLatencyMap = InlineOrMap<BasicDimension, LatencyAggregate>;
pub(crate) type BasicCounterMap = InlineOrMap<BasicDimension, CounterAggregate>;
pub(crate) type SchedWaitMap = InlineOrMap<BasicDimension, SchedWaitAggregate>;
// These event families usually stay at very low cardinality per process
// (direction, rw, port label, or a handful of active cores), so a small inline
// set avoids hashing on the common path and spills only for wider fan-out.
pub(crate) type NetworkCounterMap = InlineOrMap<NetworkDimension, CounterAggregate, 4>;
pub(crate) type TcpMetricsMap = InlineOrMap<TCPMetricsDimension, TcpMetricsAggregate, 4>;
pub(crate) type DiskAggregateMap = InlineOrMap<DiskDimension, DiskAggregate, 4>;
pub(crate) type DiskCounterMap = InlineOrMap<DiskDimension, CounterAggregate, 4>;
pub(crate) type CpuCoreCounterMap = InlineOrMap<CpuCoreDimension, CounterAggregate, 4>;

/// Aggregation buffer that collects events and aggregates them by dimension
/// over a time window.
///
/// Ingestion is serialized through the aggregated sink run loop, so these maps
/// stay unsynchronized and can optimize for the common low-cardinality case.
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
    pub syscall_read: BasicLatencyMap,
    pub syscall_write: BasicLatencyMap,
    pub syscall_futex: BasicLatencyMap,
    pub syscall_mmap: BasicLatencyMap,
    pub syscall_epoll_wait: BasicLatencyMap,
    pub syscall_fsync: BasicLatencyMap,
    pub syscall_fdatasync: BasicLatencyMap,
    pub syscall_pwrite: BasicLatencyMap,

    // --- Network (NetworkDimension -> CounterAggregate) ---
    pub net_io: NetworkCounterMap,
    pub tcp_retransmit: NetworkCounterMap,

    // --- TCP metrics (TCPMetricsDimension -> TcpMetricsAggregate) ---
    pub tcp_metrics: TcpMetricsMap,

    // --- Disk (DiskDimension) ---
    pub disk_io: DiskAggregateMap,
    pub block_merge: DiskCounterMap,

    // --- Scheduler (BasicDimension -> LatencyAggregate) ---
    pub sched_on_cpu: BasicLatencyMap,
    pub cpu_on_core: CpuCoreCounterMap,
    pub sched_wait: SchedWaitMap,

    // --- Page faults (BasicDimension -> CounterAggregate) ---
    pub page_fault_major: BasicCounterMap,
    pub page_fault_minor: BasicCounterMap,

    // --- FD operations (BasicDimension -> CounterAggregate) ---
    pub fd_open: BasicCounterMap,
    pub fd_close: BasicCounterMap,

    // --- Memory pressure ---
    pub mem_reclaim: BasicLatencyMap,
    pub mem_compaction: BasicLatencyMap,
    pub swap_in: BasicCounterMap,
    pub swap_out: BasicCounterMap,
    pub oom_kill: BasicCounterMap,
    pub process_exit: BasicCounterMap,
    pub tcp_state_change: BasicCounterMap,
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
            syscall_read: InlineOrMap::with_capacity(16),
            syscall_write: InlineOrMap::with_capacity(16),
            syscall_futex: InlineOrMap::with_capacity(16),
            syscall_mmap: InlineOrMap::with_capacity(16),
            syscall_epoll_wait: InlineOrMap::with_capacity(16),
            syscall_fsync: InlineOrMap::with_capacity(16),
            syscall_fdatasync: InlineOrMap::with_capacity(16),
            syscall_pwrite: InlineOrMap::with_capacity(16),
            // Network.
            net_io: InlineOrMap::with_capacity(64),
            tcp_retransmit: InlineOrMap::with_capacity(32),
            // TCP metrics.
            tcp_metrics: InlineOrMap::with_capacity(32),
            // Disk.
            disk_io: InlineOrMap::with_capacity(16),
            block_merge: InlineOrMap::with_capacity(16),
            // Scheduler.
            sched_on_cpu: InlineOrMap::with_capacity(16),
            cpu_on_core: InlineOrMap::with_capacity(64),
            sched_wait: InlineOrMap::with_capacity(16),
            // Page faults.
            page_fault_major: InlineOrMap::with_capacity(16),
            page_fault_minor: InlineOrMap::with_capacity(16),
            // FD operations.
            fd_open: InlineOrMap::with_capacity(16),
            fd_close: InlineOrMap::with_capacity(16),
            // Memory pressure.
            mem_reclaim: InlineOrMap::with_capacity(8),
            mem_compaction: InlineOrMap::with_capacity(8),
            swap_in: InlineOrMap::with_capacity(8),
            swap_out: InlineOrMap::with_capacity(8),
            oom_kill: InlineOrMap::with_capacity(8),
            process_exit: InlineOrMap::with_capacity(8),
            tcp_state_change: InlineOrMap::with_capacity(8),
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
        map.get_or_default_mut(dim).record(latency_ns);
    }

    /// Adds a network I/O event.
    pub fn add_net_io(&mut self, dim: NetworkDimension, bytes: i64) {
        self.net_io.get_or_default_mut(dim).add(bytes);
    }

    /// Adds a TCP retransmit event.
    pub fn add_tcp_retransmit(&mut self, dim: NetworkDimension, bytes: i64) {
        self.tcp_retransmit.get_or_default_mut(dim).add(bytes);
    }

    /// Adds TCP metrics (RTT and CWND).
    pub fn add_tcp_metrics(&mut self, dim: TCPMetricsDimension, rtt_us: u32, cwnd: u32) {
        self.tcp_metrics
            .get_or_default_mut(dim)
            .record(rtt_us, cwnd);
    }

    /// Adds a disk I/O event with latency, bytes, and queue depth.
    pub fn add_disk_io(
        &mut self,
        dim: DiskDimension,
        latency_ns: u64,
        bytes: u32,
        queue_depth: u32,
    ) {
        self.disk_io
            .get_or_default_mut(dim)
            .record(latency_ns, bytes, queue_depth);
    }

    /// Adds a block merge event.
    pub fn add_block_merge(&mut self, dim: DiskDimension, bytes: u32) {
        self.block_merge
            .get_or_default_mut(dim)
            .add(i64::from(bytes));
    }

    /// Records scheduler on-CPU latency distribution from sched_switch events.
    pub fn add_sched_on_cpu(&mut self, dim: BasicDimension, on_cpu_ns: u64) {
        self.sched_on_cpu.get_or_default_mut(dim).record(on_cpu_ns);
    }

    /// Adds per-core on-CPU time used for utilization aggregation.
    pub fn add_cpu_on_core(&mut self, dim: BasicDimension, cpu_id: u32, on_cpu_ns: u64) {
        self.cpu_on_core
            .get_or_default_mut(CpuCoreDimension::from_basic(dim, cpu_id))
            .add(on_cpu_ns as i64);
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
            self.sched_wait
                .get_or_default_mut(dim)
                .record(runqueue_ns, off_cpu_ns);
        }
    }

    /// Adds a page fault event.
    pub fn add_page_fault(&mut self, dim: BasicDimension, major: bool) {
        if major {
            self.page_fault_major.get_or_default_mut(dim).add_count(1);
        } else {
            self.page_fault_minor.get_or_default_mut(dim).add_count(1);
        }
    }

    /// Adds an FD open event.
    pub fn add_fd_open(&mut self, dim: BasicDimension) {
        self.fd_open.get_or_default_mut(dim).add_count(1);
    }

    /// Adds an FD close event.
    pub fn add_fd_close(&mut self, dim: BasicDimension) {
        self.fd_close.get_or_default_mut(dim).add_count(1);
    }

    /// Adds a memory reclaim event.
    pub fn add_mem_reclaim(&mut self, dim: BasicDimension, duration_ns: u64) {
        self.mem_reclaim.get_or_default_mut(dim).record(duration_ns);
    }

    /// Adds a memory compaction event.
    pub fn add_mem_compaction(&mut self, dim: BasicDimension, duration_ns: u64) {
        self.mem_compaction
            .get_or_default_mut(dim)
            .record(duration_ns);
    }

    /// Adds a swap-in event.
    pub fn add_swap_in(&mut self, dim: BasicDimension, pages: u64) {
        self.swap_in.get_or_default_mut(dim).add(pages as i64);
    }

    /// Adds a swap-out event.
    pub fn add_swap_out(&mut self, dim: BasicDimension, pages: u64) {
        self.swap_out.get_or_default_mut(dim).add(pages as i64);
    }

    /// Adds an OOM kill event.
    pub fn add_oom_kill(&mut self, dim: BasicDimension) {
        self.oom_kill.get_or_default_mut(dim).add_count(1);
    }

    /// Adds a process exit event.
    pub fn add_process_exit(&mut self, dim: BasicDimension) {
        self.process_exit.get_or_default_mut(dim).add_count(1);
    }

    /// Adds a TCP state change event.
    pub fn add_tcp_state_change(&mut self, dim: BasicDimension) {
        self.tcp_state_change.get_or_default_mut(dim).add_count(1);
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

        let metrics = buf.tcp_metrics.get(&dim).expect("tcp metrics exist");
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

        let open = buf.fd_open.get(&dim).expect("open exists");
        assert_eq!(open.snapshot().count, 2);
        let close = buf.fd_close.get(&dim).expect("close exists");
        assert_eq!(close.snapshot().count, 1);
    }

    #[test]
    fn test_inline_or_map_spills_on_second_dimension() {
        let mut map: BasicCounterMap = InlineOrMap::with_capacity(4);
        let first = BasicDimension::new(1, 1);
        let second = BasicDimension::new(2, 1);

        map.get_or_default_mut(first).add_count(2);
        map.get_or_default_mut(second).add_count(1);

        assert_eq!(map.len(), 2);
        assert_eq!(map.get(&first).expect("first exists").snapshot().count, 2);
        assert_eq!(map.get(&second).expect("second exists").snapshot().count, 1);
    }

    #[test]
    fn test_inline_or_map_keeps_multiple_dimensions_without_spilling() {
        let mut map: InlineOrMap<NetworkDimension, CounterAggregate, 4> =
            InlineOrMap::with_capacity(4);

        for idx in 0..4u32 {
            let dim = NetworkDimension::new(10 + idx, 1, idx as u8, (idx % 2) as u8);
            map.get_or_default_mut(dim).add_count(1);
        }

        assert_eq!(map.len(), 4);
        assert!(map.contains_key(&NetworkDimension::new(10, 1, 0, 0)));
        assert!(map.contains_key(&NetworkDimension::new(13, 1, 3, 1)));
    }
}
