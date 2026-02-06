use std::time::SystemTime;

use dashmap::DashMap;

use crate::tracer::event::EventType;

use super::aggregate::{CounterAggregate, GaugeAggregate, LatencyAggregate};
use super::dimension::{BasicDimension, DiskDimension, NetworkDimension, TCPMetricsDimension};

/// Thread-safe aggregation buffer that collects events and aggregates
/// them by dimension over a time window.
///
/// Uses `DashMap` for concurrent map access, eliminating the need for
/// a global RWMutex. Each map entry is independently lockable.
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

    // --- Syscalls (BasicDimension -> LatencyAggregate) ---
    pub syscall_read: DashMap<BasicDimension, LatencyAggregate>,
    pub syscall_write: DashMap<BasicDimension, LatencyAggregate>,
    pub syscall_futex: DashMap<BasicDimension, LatencyAggregate>,
    pub syscall_mmap: DashMap<BasicDimension, LatencyAggregate>,
    pub syscall_epoll_wait: DashMap<BasicDimension, LatencyAggregate>,
    pub syscall_fsync: DashMap<BasicDimension, LatencyAggregate>,
    pub syscall_fdatasync: DashMap<BasicDimension, LatencyAggregate>,
    pub syscall_pwrite: DashMap<BasicDimension, LatencyAggregate>,

    // --- Network (NetworkDimension -> CounterAggregate) ---
    pub net_io: DashMap<NetworkDimension, CounterAggregate>,
    pub tcp_retransmit: DashMap<NetworkDimension, CounterAggregate>,

    // --- TCP metrics (TCPMetricsDimension -> GaugeAggregate) ---
    pub tcp_rtt: DashMap<TCPMetricsDimension, GaugeAggregate>,
    pub tcp_cwnd: DashMap<TCPMetricsDimension, GaugeAggregate>,

    // --- Disk (DiskDimension) ---
    pub disk_latency: DashMap<DiskDimension, LatencyAggregate>,
    pub disk_bytes: DashMap<DiskDimension, CounterAggregate>,
    pub disk_queue_depth: DashMap<DiskDimension, GaugeAggregate>,
    pub block_merge: DashMap<DiskDimension, CounterAggregate>,

    // --- Scheduler (BasicDimension -> LatencyAggregate) ---
    pub sched_on_cpu: DashMap<BasicDimension, LatencyAggregate>,
    pub sched_off_cpu: DashMap<BasicDimension, LatencyAggregate>,
    pub sched_runqueue: DashMap<BasicDimension, LatencyAggregate>,

    // --- Page faults (BasicDimension -> CounterAggregate) ---
    pub page_fault_major: DashMap<BasicDimension, CounterAggregate>,
    pub page_fault_minor: DashMap<BasicDimension, CounterAggregate>,

    // --- FD operations (BasicDimension -> CounterAggregate) ---
    pub fd_open: DashMap<BasicDimension, CounterAggregate>,
    pub fd_close: DashMap<BasicDimension, CounterAggregate>,

    // --- Memory pressure ---
    pub mem_reclaim: DashMap<BasicDimension, LatencyAggregate>,
    pub mem_compaction: DashMap<BasicDimension, LatencyAggregate>,
    pub swap_in: DashMap<BasicDimension, CounterAggregate>,
    pub swap_out: DashMap<BasicDimension, CounterAggregate>,
    pub oom_kill: DashMap<BasicDimension, CounterAggregate>,
    pub process_exit: DashMap<BasicDimension, CounterAggregate>,
    pub tcp_state_change: DashMap<BasicDimension, CounterAggregate>,
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
    ) -> Self {
        Self {
            start_time,
            wallclock_slot,
            wallclock_slot_start,
            cl_syncing,
            el_optimistic,
            el_offline,
            // Syscalls.
            syscall_read: DashMap::with_capacity(16),
            syscall_write: DashMap::with_capacity(16),
            syscall_futex: DashMap::with_capacity(16),
            syscall_mmap: DashMap::with_capacity(16),
            syscall_epoll_wait: DashMap::with_capacity(16),
            syscall_fsync: DashMap::with_capacity(16),
            syscall_fdatasync: DashMap::with_capacity(16),
            syscall_pwrite: DashMap::with_capacity(16),
            // Network.
            net_io: DashMap::with_capacity(64),
            tcp_retransmit: DashMap::with_capacity(32),
            // TCP metrics.
            tcp_rtt: DashMap::with_capacity(32),
            tcp_cwnd: DashMap::with_capacity(32),
            // Disk.
            disk_latency: DashMap::with_capacity(16),
            disk_bytes: DashMap::with_capacity(16),
            disk_queue_depth: DashMap::with_capacity(16),
            block_merge: DashMap::with_capacity(16),
            // Scheduler.
            sched_on_cpu: DashMap::with_capacity(16),
            sched_off_cpu: DashMap::with_capacity(16),
            sched_runqueue: DashMap::with_capacity(16),
            // Page faults.
            page_fault_major: DashMap::with_capacity(16),
            page_fault_minor: DashMap::with_capacity(16),
            // FD operations.
            fd_open: DashMap::with_capacity(16),
            fd_close: DashMap::with_capacity(16),
            // Memory pressure.
            mem_reclaim: DashMap::with_capacity(8),
            mem_compaction: DashMap::with_capacity(8),
            swap_in: DashMap::with_capacity(8),
            swap_out: DashMap::with_capacity(8),
            oom_kill: DashMap::with_capacity(8),
            process_exit: DashMap::with_capacity(8),
            tcp_state_change: DashMap::with_capacity(8),
        }
    }

    /// Adds a syscall latency event to the appropriate map.
    pub fn add_syscall(&self, event_type: EventType, dim: BasicDimension, latency_ns: u64) {
        let map = match event_type {
            EventType::SyscallRead => &self.syscall_read,
            EventType::SyscallWrite => &self.syscall_write,
            EventType::SyscallFutex => &self.syscall_futex,
            EventType::SyscallMmap => &self.syscall_mmap,
            EventType::SyscallEpollWait => &self.syscall_epoll_wait,
            EventType::SyscallFsync => &self.syscall_fsync,
            EventType::SyscallFdatasync => &self.syscall_fdatasync,
            EventType::SyscallPwrite => &self.syscall_pwrite,
            _ => return,
        };
        map.entry(dim).or_default().record(latency_ns);
    }

    /// Adds a network I/O event.
    pub fn add_net_io(&self, dim: NetworkDimension, bytes: i64) {
        self.net_io.entry(dim).or_default().add(bytes);
    }

    /// Adds a TCP retransmit event.
    pub fn add_tcp_retransmit(&self, dim: NetworkDimension, bytes: i64) {
        self.tcp_retransmit.entry(dim).or_default().add(bytes);
    }

    /// Adds TCP metrics (RTT and CWND).
    pub fn add_tcp_metrics(&self, dim: TCPMetricsDimension, rtt_us: u32, cwnd: u32) {
        self.tcp_rtt
            .entry(dim)
            .or_default()
            .record(i64::from(rtt_us));
        self.tcp_cwnd
            .entry(dim)
            .or_default()
            .record(i64::from(cwnd));
    }

    /// Adds a disk I/O event with latency, bytes, and queue depth.
    pub fn add_disk_io(&self, dim: DiskDimension, latency_ns: u64, bytes: u32, queue_depth: u32) {
        self.disk_latency.entry(dim).or_default().record(latency_ns);
        self.disk_bytes
            .entry(dim)
            .or_default()
            .add(i64::from(bytes));
        self.disk_queue_depth
            .entry(dim)
            .or_default()
            .record(i64::from(queue_depth));
    }

    /// Adds a block merge event.
    pub fn add_block_merge(&self, dim: DiskDimension, bytes: u32) {
        self.block_merge
            .entry(dim)
            .or_default()
            .add(i64::from(bytes));
    }

    /// Adds a scheduler switch event (on-CPU time).
    pub fn add_sched_switch(&self, dim: BasicDimension, on_cpu_ns: u64) {
        self.sched_on_cpu.entry(dim).or_default().record(on_cpu_ns);
    }

    /// Adds scheduler runqueue and off-CPU latency.
    pub fn add_sched_runqueue(&self, dim: BasicDimension, runqueue_ns: u64, off_cpu_ns: u64) {
        if runqueue_ns > 0 {
            self.sched_runqueue
                .entry(dim)
                .or_default()
                .record(runqueue_ns);
        }
        if off_cpu_ns > 0 {
            self.sched_off_cpu
                .entry(dim)
                .or_default()
                .record(off_cpu_ns);
        }
    }

    /// Adds a page fault event.
    pub fn add_page_fault(&self, dim: BasicDimension, major: bool) {
        if major {
            self.page_fault_major.entry(dim).or_default().add_count(1);
        } else {
            self.page_fault_minor.entry(dim).or_default().add_count(1);
        }
    }

    /// Adds an FD open event.
    pub fn add_fd_open(&self, dim: BasicDimension) {
        self.fd_open.entry(dim).or_default().add_count(1);
    }

    /// Adds an FD close event.
    pub fn add_fd_close(&self, dim: BasicDimension) {
        self.fd_close.entry(dim).or_default().add_count(1);
    }

    /// Adds a memory reclaim event.
    pub fn add_mem_reclaim(&self, dim: BasicDimension, duration_ns: u64) {
        self.mem_reclaim.entry(dim).or_default().record(duration_ns);
    }

    /// Adds a memory compaction event.
    pub fn add_mem_compaction(&self, dim: BasicDimension, duration_ns: u64) {
        self.mem_compaction
            .entry(dim)
            .or_default()
            .record(duration_ns);
    }

    /// Adds a swap-in event.
    pub fn add_swap_in(&self, dim: BasicDimension, pages: u64) {
        self.swap_in.entry(dim).or_default().add(pages as i64);
    }

    /// Adds a swap-out event.
    pub fn add_swap_out(&self, dim: BasicDimension, pages: u64) {
        self.swap_out.entry(dim).or_default().add(pages as i64);
    }

    /// Adds an OOM kill event.
    pub fn add_oom_kill(&self, dim: BasicDimension) {
        self.oom_kill.entry(dim).or_default().add_count(1);
    }

    /// Adds a process exit event.
    pub fn add_process_exit(&self, dim: BasicDimension) {
        self.process_exit.entry(dim).or_default().add_count(1);
    }

    /// Adds a TCP state change event.
    pub fn add_tcp_state_change(&self, dim: BasicDimension) {
        self.tcp_state_change.entry(dim).or_default().add_count(1);
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
        )
    }

    #[test]
    fn test_add_syscall_read() {
        let buf = test_buffer();
        let dim = BasicDimension {
            pid: 1,
            client_type: 1,
        };

        buf.add_syscall(EventType::SyscallRead, dim, 5_000);
        buf.add_syscall(EventType::SyscallRead, dim, 10_000);

        let entry = buf.syscall_read.get(&dim).expect("entry exists");
        let snap = entry.snapshot();
        assert_eq!(snap.count, 2);
        assert_eq!(snap.sum, 15_000);
    }

    #[test]
    fn test_add_syscall_unknown_type_is_noop() {
        let buf = test_buffer();
        let dim = BasicDimension {
            pid: 1,
            client_type: 1,
        };

        // DiskIO is not a syscall type, should be ignored.
        buf.add_syscall(EventType::DiskIO, dim, 5_000);
        assert!(buf.syscall_read.is_empty());
    }

    #[test]
    fn test_add_net_io() {
        let buf = test_buffer();
        let dim = NetworkDimension {
            pid: 1,
            client_type: 1,
            local_port: 8545,
            direction: 0,
        };

        buf.add_net_io(dim, 1024);
        buf.add_net_io(dim, 2048);

        let entry = buf.net_io.get(&dim).expect("entry exists");
        let snap = entry.snapshot();
        assert_eq!(snap.count, 2);
        assert_eq!(snap.sum, 3072);
    }

    #[test]
    fn test_add_tcp_metrics() {
        let buf = test_buffer();
        let dim = TCPMetricsDimension {
            pid: 1,
            client_type: 1,
            local_port: 8545,
        };

        buf.add_tcp_metrics(dim, 100, 65535);

        let rtt = buf.tcp_rtt.get(&dim).expect("rtt exists");
        assert_eq!(rtt.snapshot().sum, 100);
        let cwnd = buf.tcp_cwnd.get(&dim).expect("cwnd exists");
        assert_eq!(cwnd.snapshot().sum, 65535);
    }

    #[test]
    fn test_add_disk_io() {
        let buf = test_buffer();
        let dim = DiskDimension {
            pid: 1,
            client_type: 1,
            device_id: 259,
            rw: 1,
        };

        buf.add_disk_io(dim, 50_000, 4096, 3);

        let lat = buf.disk_latency.get(&dim).expect("latency exists");
        assert_eq!(lat.snapshot().count, 1);
        let bytes = buf.disk_bytes.get(&dim).expect("bytes exists");
        assert_eq!(bytes.snapshot().sum, 4096);
        let qd = buf.disk_queue_depth.get(&dim).expect("queue depth exists");
        assert_eq!(qd.snapshot().sum, 3);
    }

    #[test]
    fn test_add_sched_runqueue_skips_zero() {
        let buf = test_buffer();
        let dim = BasicDimension {
            pid: 1,
            client_type: 1,
        };

        buf.add_sched_runqueue(dim, 0, 5_000);
        assert!(buf.sched_runqueue.is_empty());
        assert!(!buf.sched_off_cpu.is_empty());

        let buf2 = test_buffer();
        buf2.add_sched_runqueue(dim, 5_000, 0);
        assert!(!buf2.sched_runqueue.is_empty());
        assert!(buf2.sched_off_cpu.is_empty());
    }

    #[test]
    fn test_add_page_fault() {
        let buf = test_buffer();
        let dim = BasicDimension {
            pid: 1,
            client_type: 1,
        };

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
        let buf = test_buffer();
        let dim = BasicDimension {
            pid: 1,
            client_type: 1,
        };

        buf.add_fd_open(dim);
        buf.add_fd_open(dim);
        buf.add_fd_close(dim);

        let open = buf.fd_open.get(&dim).expect("open exists");
        assert_eq!(open.snapshot().count, 2);
        let close = buf.fd_close.get(&dim).expect("close exists");
        assert_eq!(close.snapshot().count, 1);
    }

    #[test]
    fn test_concurrent_add_syscall() {
        use std::sync::Arc;
        use std::thread;

        let buf = Arc::new(test_buffer());
        let dim = BasicDimension {
            pid: 1,
            client_type: 1,
        };
        let mut handles = Vec::new();

        for _ in 0..4 {
            let buf = Arc::clone(&buf);
            handles.push(thread::spawn(move || {
                for _ in 0..1000 {
                    buf.add_syscall(EventType::SyscallRead, dim, 5_000);
                }
            }));
        }

        for h in handles {
            h.join().expect("thread panicked");
        }

        let entry = buf.syscall_read.get(&dim).expect("entry exists");
        assert_eq!(entry.snapshot().count, 4000);
    }
}
