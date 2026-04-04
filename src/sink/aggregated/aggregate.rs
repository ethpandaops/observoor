use super::histogram::{Histogram, NUM_BUCKETS};

/// Tracks latency statistics with histogram.
/// Used for syscalls, disk I/O latency, scheduler events, memory latency.
pub struct LatencyAggregate {
    sum: i64,
    count: u32,
    min: i64,
    max: i64,
    histogram: Histogram,
}

impl LatencyAggregate {
    /// Creates a new aggregate with min initialized to MAX and max to MIN.
    pub fn new() -> Self {
        Self {
            sum: 0,
            count: 0,
            min: i64::MAX,
            max: i64::MIN,
            histogram: Histogram::new(),
        }
    }

    /// Records a latency value in nanoseconds.
    pub fn record(&mut self, value_ns: u64) {
        let val = value_ns as i64;
        self.sum += val;
        self.count += 1;
        self.histogram.record(value_ns);
        if val < self.min {
            self.min = val;
        }
        if val > self.max {
            self.max = val;
        }
    }

    /// Returns a point-in-time snapshot of all statistics.
    pub fn snapshot(&self) -> LatencySnapshot {
        let count = self.count;
        let mut min_val = self.min;
        let mut max_val = self.max;

        // Handle case where no values were recorded.
        if count == 0 {
            min_val = 0;
            max_val = 0;
        }

        LatencySnapshot {
            sum: self.sum,
            count,
            min: min_val,
            max: max_val,
            histogram: self.histogram.snapshot(),
        }
    }
}

impl Default for LatencyAggregate {
    fn default() -> Self {
        Self::new()
    }
}

/// Point-in-time view of latency statistics.
#[derive(Debug, Clone)]
pub struct LatencySnapshot {
    pub sum: i64,
    pub count: u32,
    pub min: i64,
    pub max: i64,
    pub histogram: [u32; NUM_BUCKETS],
}

/// Tracks all syscall latency families behind a single per-dimension map entry.
///
/// Mixed syscall workloads often bounce between multiple syscall types for the
/// same PID, so co-locating the aggregates lets the hot path reuse one map
/// lookup and one last-hit cache entry across all syscall variants.
pub struct SyscallAggregate {
    read: LatencyAggregate,
    write: LatencyAggregate,
    futex: LatencyAggregate,
    mmap: LatencyAggregate,
    fsync: LatencyAggregate,
}

impl SyscallAggregate {
    /// Creates a new aggregate for all syscall latency metrics.
    pub fn new() -> Self {
        Self {
            read: LatencyAggregate::new(),
            write: LatencyAggregate::new(),
            futex: LatencyAggregate::new(),
            mmap: LatencyAggregate::new(),
            fsync: LatencyAggregate::new(),
        }
    }

    #[inline(always)]
    pub fn record_read(&mut self, latency_ns: u64) {
        self.read.record(latency_ns);
    }

    #[inline(always)]
    pub fn record_write(&mut self, latency_ns: u64) {
        self.write.record(latency_ns);
    }

    #[inline(always)]
    pub fn record_futex(&mut self, latency_ns: u64) {
        self.futex.record(latency_ns);
    }

    #[inline(always)]
    pub fn record_mmap(&mut self, latency_ns: u64) {
        self.mmap.record(latency_ns);
    }

    #[inline(always)]
    pub fn record_fsync(&mut self, latency_ns: u64) {
        self.fsync.record(latency_ns);
    }

    #[inline(always)]
    pub fn read_snapshot(&self) -> LatencySnapshot {
        self.read.snapshot()
    }

    #[inline(always)]
    pub fn write_snapshot(&self) -> LatencySnapshot {
        self.write.snapshot()
    }

    #[inline(always)]
    pub fn futex_snapshot(&self) -> LatencySnapshot {
        self.futex.snapshot()
    }

    #[inline(always)]
    pub fn mmap_snapshot(&self) -> LatencySnapshot {
        self.mmap.snapshot()
    }

    #[inline(always)]
    pub fn fsync_snapshot(&self) -> LatencySnapshot {
        self.fsync.snapshot()
    }
}

impl Default for SyscallAggregate {
    fn default() -> Self {
        Self::new()
    }
}

/// Tracks all BasicDimension-keyed metrics behind one per-dimension entry.
///
/// The hottest ingest workloads interleave syscalls, scheduler events, page
/// faults, and FD activity for the same PID. Co-locating them lets the sink
/// reuse one hash lookup and one last-hit cache entry across those event
/// families instead of bouncing between multiple maps.
pub struct BasicAggregate {
    syscalls: SyscallAggregate,
    sched_on_cpu: LatencyAggregate,
    sched_wait: SchedWaitAggregate,
    page_fault_major: CountAggregate,
    page_fault_minor: CountAggregate,
    fd_ops: FdAggregate,
}

impl BasicAggregate {
    pub fn new() -> Self {
        Self {
            syscalls: SyscallAggregate::new(),
            sched_on_cpu: LatencyAggregate::new(),
            sched_wait: SchedWaitAggregate::new(),
            page_fault_major: CountAggregate::new(),
            page_fault_minor: CountAggregate::new(),
            fd_ops: FdAggregate::new(),
        }
    }

    #[inline(always)]
    pub fn record_syscall_read(&mut self, latency_ns: u64) {
        self.syscalls.record_read(latency_ns);
    }

    #[inline(always)]
    pub fn record_syscall_write(&mut self, latency_ns: u64) {
        self.syscalls.record_write(latency_ns);
    }

    #[inline(always)]
    pub fn record_syscall_futex(&mut self, latency_ns: u64) {
        self.syscalls.record_futex(latency_ns);
    }

    #[inline(always)]
    pub fn record_syscall_mmap(&mut self, latency_ns: u64) {
        self.syscalls.record_mmap(latency_ns);
    }

    #[inline(always)]
    pub fn record_syscall_fsync(&mut self, latency_ns: u64) {
        self.syscalls.record_fsync(latency_ns);
    }

    #[inline(always)]
    pub fn record_sched_on_cpu(&mut self, on_cpu_ns: u64) {
        self.sched_on_cpu.record(on_cpu_ns);
    }

    #[inline(always)]
    pub fn record_sched_wait(&mut self, runqueue_ns: u64, off_cpu_ns: u64) {
        self.sched_wait.record(runqueue_ns, off_cpu_ns);
    }

    #[inline(always)]
    pub fn record_page_fault(&mut self, major: bool) {
        if major {
            self.page_fault_major.add_count(1);
        } else {
            self.page_fault_minor.add_count(1);
        }
    }

    #[inline(always)]
    pub fn record_fd_open(&mut self) {
        self.fd_ops.record_open();
    }

    #[inline(always)]
    pub fn record_fd_close(&mut self) {
        self.fd_ops.record_close();
    }

    #[inline(always)]
    pub fn syscalls(&self) -> &SyscallAggregate {
        &self.syscalls
    }

    #[inline(always)]
    pub fn sched_on_cpu_snapshot(&self) -> LatencySnapshot {
        self.sched_on_cpu.snapshot()
    }

    #[inline(always)]
    pub fn sched_runqueue_snapshot(&self) -> LatencySnapshot {
        self.sched_wait.runqueue_snapshot()
    }

    #[inline(always)]
    pub fn sched_off_cpu_snapshot(&self) -> LatencySnapshot {
        self.sched_wait.off_cpu_snapshot()
    }

    #[inline(always)]
    pub fn page_fault_major_snapshot(&self) -> CounterSnapshot {
        self.page_fault_major.snapshot()
    }

    #[inline(always)]
    pub fn page_fault_minor_snapshot(&self) -> CounterSnapshot {
        self.page_fault_minor.snapshot()
    }

    #[inline(always)]
    pub fn fd_open_snapshot(&self) -> CounterSnapshot {
        self.fd_ops.open_snapshot()
    }

    #[inline(always)]
    pub fn fd_close_snapshot(&self) -> CounterSnapshot {
        self.fd_ops.close_snapshot()
    }
}

impl Default for BasicAggregate {
    fn default() -> Self {
        Self::new()
    }
}

/// Tracks rarely-hit BasicDimension metrics outside the hottest map entry.
///
/// Stress-bench spends most of its time in syscall, scheduler, FD, and page
/// fault ingestion. Moving colder memory/process counters and infrequent
/// syscall families out of `BasicAggregate` shrinks the value stored behind
/// `basic_metrics`, improving cache density on the hot path while keeping full
/// aggregation coverage intact.
pub struct BasicColdAggregate {
    syscall_epoll_wait: LatencyAggregate,
    syscall_fdatasync: LatencyAggregate,
    syscall_pwrite: LatencyAggregate,
    mem_reclaim: LatencyAggregate,
    mem_compaction: LatencyAggregate,
    swap_in: CounterAggregate,
    swap_out: CounterAggregate,
    oom_kill: CountAggregate,
    process_exit: CountAggregate,
    tcp_state_change: CountAggregate,
}

impl BasicColdAggregate {
    pub fn new() -> Self {
        Self {
            syscall_epoll_wait: LatencyAggregate::new(),
            syscall_fdatasync: LatencyAggregate::new(),
            syscall_pwrite: LatencyAggregate::new(),
            mem_reclaim: LatencyAggregate::new(),
            mem_compaction: LatencyAggregate::new(),
            swap_in: CounterAggregate::new(),
            swap_out: CounterAggregate::new(),
            oom_kill: CountAggregate::new(),
            process_exit: CountAggregate::new(),
            tcp_state_change: CountAggregate::new(),
        }
    }

    #[inline(always)]
    pub fn record_syscall_epoll_wait(&mut self, duration_ns: u64) {
        self.syscall_epoll_wait.record(duration_ns);
    }

    #[inline(always)]
    pub fn record_syscall_fdatasync(&mut self, duration_ns: u64) {
        self.syscall_fdatasync.record(duration_ns);
    }

    #[inline(always)]
    pub fn record_syscall_pwrite(&mut self, duration_ns: u64) {
        self.syscall_pwrite.record(duration_ns);
    }

    #[inline(always)]
    pub fn record_mem_reclaim(&mut self, duration_ns: u64) {
        self.mem_reclaim.record(duration_ns);
    }

    #[inline(always)]
    pub fn record_mem_compaction(&mut self, duration_ns: u64) {
        self.mem_compaction.record(duration_ns);
    }

    #[inline(always)]
    pub fn record_swap_in(&mut self, pages: u64) {
        self.swap_in.add(pages as i64);
    }

    #[inline(always)]
    pub fn record_swap_out(&mut self, pages: u64) {
        self.swap_out.add(pages as i64);
    }

    #[inline(always)]
    pub fn record_oom_kill(&mut self) {
        self.oom_kill.add_count(1);
    }

    #[inline(always)]
    pub fn record_process_exit(&mut self) {
        self.process_exit.add_count(1);
    }

    #[inline(always)]
    pub fn record_tcp_state_change(&mut self) {
        self.tcp_state_change.add_count(1);
    }

    #[inline(always)]
    pub fn syscall_epoll_wait_snapshot(&self) -> LatencySnapshot {
        self.syscall_epoll_wait.snapshot()
    }

    #[inline(always)]
    pub fn syscall_fdatasync_snapshot(&self) -> LatencySnapshot {
        self.syscall_fdatasync.snapshot()
    }

    #[inline(always)]
    pub fn syscall_pwrite_snapshot(&self) -> LatencySnapshot {
        self.syscall_pwrite.snapshot()
    }

    #[inline(always)]
    pub fn mem_reclaim_snapshot(&self) -> LatencySnapshot {
        self.mem_reclaim.snapshot()
    }

    #[inline(always)]
    pub fn mem_compaction_snapshot(&self) -> LatencySnapshot {
        self.mem_compaction.snapshot()
    }

    #[inline(always)]
    pub fn swap_in_snapshot(&self) -> CounterSnapshot {
        self.swap_in.snapshot()
    }

    #[inline(always)]
    pub fn swap_out_snapshot(&self) -> CounterSnapshot {
        self.swap_out.snapshot()
    }

    #[inline(always)]
    pub fn oom_kill_snapshot(&self) -> CounterSnapshot {
        self.oom_kill.snapshot()
    }

    #[inline(always)]
    pub fn process_exit_snapshot(&self) -> CounterSnapshot {
        self.process_exit.snapshot()
    }

    #[inline(always)]
    pub fn tcp_state_change_snapshot(&self) -> CounterSnapshot {
        self.tcp_state_change.snapshot()
    }
}

impl Default for BasicColdAggregate {
    fn default() -> Self {
        Self::new()
    }
}

/// Tracks count and sum for counter-type metrics.
/// Used for network bytes, FD operations, page faults, etc.
pub struct CounterAggregate {
    count: u32,
    sum: i64,
}

impl CounterAggregate {
    /// Creates a new counter aggregate.
    pub fn new() -> Self {
        Self { count: 0, sum: 0 }
    }

    /// Records a value (typically bytes), incrementing count by 1.
    pub fn add(&mut self, value: i64) {
        self.count += 1;
        self.sum += value;
    }

    /// Increments only the count by n.
    pub fn add_count(&mut self, n: u32) {
        self.count += n;
    }

    /// Returns a point-in-time snapshot.
    pub fn snapshot(&self) -> CounterSnapshot {
        CounterSnapshot {
            count: self.count,
            sum: self.sum,
        }
    }
}

impl Default for CounterAggregate {
    fn default() -> Self {
        Self::new()
    }
}

/// Tracks only the count for counter metrics whose exported sum is always zero.
/// Used for count-only events like FD operations and page faults.
pub struct CountAggregate {
    count: u32,
}

impl CountAggregate {
    /// Creates a new count-only aggregate.
    pub fn new() -> Self {
        Self { count: 0 }
    }

    /// Increments the count by n.
    pub fn add_count(&mut self, n: u32) {
        self.count += n;
    }

    /// Returns a point-in-time snapshot with a fixed zero sum.
    pub fn snapshot(&self) -> CounterSnapshot {
        CounterSnapshot {
            count: self.count,
            sum: 0,
        }
    }
}

impl Default for CountAggregate {
    fn default() -> Self {
        Self::new()
    }
}

/// Tracks FD open/close counters behind a single per-dimension map entry.
pub struct FdAggregate {
    open_count: u32,
    close_count: u32,
}

impl FdAggregate {
    /// Creates a new FD aggregate.
    pub fn new() -> Self {
        Self {
            open_count: 0,
            close_count: 0,
        }
    }

    /// Records one FD open event.
    #[inline(always)]
    pub fn record_open(&mut self) {
        self.open_count += 1;
    }

    /// Records one FD close event.
    #[inline(always)]
    pub fn record_close(&mut self) {
        self.close_count += 1;
    }

    /// Returns a point-in-time snapshot of FD opens.
    #[inline(always)]
    pub fn open_snapshot(&self) -> CounterSnapshot {
        CounterSnapshot {
            count: self.open_count,
            sum: 0,
        }
    }

    /// Returns a point-in-time snapshot of FD closes.
    #[inline(always)]
    pub fn close_snapshot(&self) -> CounterSnapshot {
        CounterSnapshot {
            count: self.close_count,
            sum: 0,
        }
    }
}

impl Default for FdAggregate {
    fn default() -> Self {
        Self::new()
    }
}

/// Point-in-time view of counter statistics.
#[derive(Debug, Clone)]
pub struct CounterSnapshot {
    pub count: u32,
    pub sum: i64,
}

/// Tracks statistics for gauge-type metrics.
/// Used for TCP RTT, CWND, queue depth, etc.
pub struct GaugeAggregate {
    sum: i64,
    count: u32,
    min: i64,
    max: i64,
}

impl GaugeAggregate {
    /// Creates a new gauge aggregate with min initialized to MAX and max to MIN.
    pub fn new() -> Self {
        Self {
            sum: 0,
            count: 0,
            min: i64::MAX,
            max: i64::MIN,
        }
    }

    /// Records a gauge value.
    pub fn record(&mut self, value: i64) {
        self.sum += value;
        self.count += 1;
        if value < self.min {
            self.min = value;
        }
        if value > self.max {
            self.max = value;
        }
    }

    /// Returns a point-in-time snapshot.
    pub fn snapshot(&self) -> GaugeSnapshot {
        let count = self.count;
        let mut min_val = self.min;
        let mut max_val = self.max;

        if count == 0 {
            min_val = 0;
            max_val = 0;
        }

        GaugeSnapshot {
            sum: self.sum,
            count,
            min: min_val,
            max: max_val,
        }
    }
}

impl Default for GaugeAggregate {
    fn default() -> Self {
        Self::new()
    }
}

/// Point-in-time view of gauge statistics.
#[derive(Debug, Clone)]
pub struct GaugeSnapshot {
    pub sum: i64,
    pub count: u32,
    pub min: i64,
    pub max: i64,
}

/// Tracks all metrics emitted by a disk I/O completion.
/// Used to avoid hashing the same disk dimension multiple times per event.
pub struct DiskAggregate {
    latency: LatencyAggregate,
    bytes: CounterAggregate,
    queue_depth: GaugeAggregate,
}

impl DiskAggregate {
    /// Creates a new aggregate for disk latency, bytes, and queue depth.
    pub fn new() -> Self {
        Self {
            latency: LatencyAggregate::new(),
            bytes: CounterAggregate::new(),
            queue_depth: GaugeAggregate::new(),
        }
    }

    /// Records all per-disk metrics emitted by one disk I/O event.
    pub fn record(&mut self, latency_ns: u64, bytes: u32, queue_depth: u32) {
        self.latency.record(latency_ns);
        self.bytes.add(i64::from(bytes));
        self.queue_depth.record(i64::from(queue_depth));
    }

    /// Returns a point-in-time snapshot of disk latency.
    pub fn latency_snapshot(&self) -> LatencySnapshot {
        self.latency.snapshot()
    }

    /// Returns a point-in-time snapshot of disk bytes.
    pub fn bytes_snapshot(&self) -> CounterSnapshot {
        self.bytes.snapshot()
    }

    /// Returns a point-in-time snapshot of disk queue depth.
    pub fn queue_depth_snapshot(&self) -> GaugeSnapshot {
        self.queue_depth.snapshot()
    }
}

impl Default for DiskAggregate {
    fn default() -> Self {
        Self::new()
    }
}

/// Tracks all TCP gauge metrics emitted by one network event.
/// Used to avoid hashing the same TCP dimension multiple times per event.
pub struct TcpMetricsAggregate {
    rtt: GaugeAggregate,
    cwnd: GaugeAggregate,
}

impl TcpMetricsAggregate {
    /// Creates a new aggregate for TCP RTT and congestion window.
    pub fn new() -> Self {
        Self {
            rtt: GaugeAggregate::new(),
            cwnd: GaugeAggregate::new(),
        }
    }

    /// Records both gauge values emitted by one TCP event.
    pub fn record(&mut self, rtt_us: u32, cwnd: u32) {
        self.rtt.record(i64::from(rtt_us));
        self.cwnd.record(i64::from(cwnd));
    }

    /// Returns a point-in-time snapshot of RTT.
    pub fn rtt_snapshot(&self) -> GaugeSnapshot {
        self.rtt.snapshot()
    }

    /// Returns a point-in-time snapshot of CWND.
    pub fn cwnd_snapshot(&self) -> GaugeSnapshot {
        self.cwnd.snapshot()
    }
}

/// Tracks both wait components emitted by one sched_runqueue event.
/// Used to avoid hashing the same scheduler dimension twice per event.
pub struct SchedWaitAggregate {
    runqueue: LatencyAggregate,
    off_cpu: LatencyAggregate,
}

impl SchedWaitAggregate {
    /// Creates a new aggregate for runqueue and off-CPU latency.
    pub fn new() -> Self {
        Self {
            runqueue: LatencyAggregate::new(),
            off_cpu: LatencyAggregate::new(),
        }
    }

    /// Records both wait components emitted by one scheduler event.
    pub fn record(&mut self, runqueue_ns: u64, off_cpu_ns: u64) {
        if runqueue_ns > 0 {
            self.runqueue.record(runqueue_ns);
        }
        if off_cpu_ns > 0 {
            self.off_cpu.record(off_cpu_ns);
        }
    }

    /// Returns a point-in-time snapshot of runqueue latency.
    pub fn runqueue_snapshot(&self) -> LatencySnapshot {
        self.runqueue.snapshot()
    }

    /// Returns a point-in-time snapshot of off-CPU latency.
    pub fn off_cpu_snapshot(&self) -> LatencySnapshot {
        self.off_cpu.snapshot()
    }
}

impl Default for SchedWaitAggregate {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for TcpMetricsAggregate {
    fn default() -> Self {
        Self::new()
    }
}

/// Tracks TCP TX bytes alongside inline TCP gauge metrics from the same event.
/// Used to avoid hashing the same network dimension twice for metric-bearing
/// TCP transmit events.
pub struct TcpTxAggregate {
    bytes: CounterAggregate,
    metrics: TcpMetricsAggregate,
}

impl TcpTxAggregate {
    /// Creates a new aggregate for TCP TX bytes, RTT, and congestion window.
    pub fn new() -> Self {
        Self {
            bytes: CounterAggregate::new(),
            metrics: TcpMetricsAggregate::new(),
        }
    }

    /// Records bytes plus inline TCP gauge metrics from one transmit event.
    pub fn record(&mut self, bytes: i64, rtt_us: u32, cwnd: u32) {
        self.bytes.add(bytes);
        self.metrics.record(rtt_us, cwnd);
    }

    /// Records only the inline TCP gauge metrics.
    ///
    /// Kept for compatibility helpers that still build a TCP-only dimension.
    pub fn record_metrics(&mut self, rtt_us: u32, cwnd: u32) {
        self.metrics.record(rtt_us, cwnd);
    }

    /// Returns a point-in-time snapshot of TX bytes.
    pub fn bytes_snapshot(&self) -> CounterSnapshot {
        self.bytes.snapshot()
    }

    /// Returns a point-in-time snapshot of RTT.
    pub fn rtt_snapshot(&self) -> GaugeSnapshot {
        self.metrics.rtt_snapshot()
    }

    /// Returns a point-in-time snapshot of CWND.
    pub fn cwnd_snapshot(&self) -> GaugeSnapshot {
        self.metrics.cwnd_snapshot()
    }
}

impl Default for TcpTxAggregate {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_latency_aggregate_single_value() {
        let mut agg = LatencyAggregate::new();
        agg.record(5_000); // 5us

        let snap = agg.snapshot();
        assert_eq!(snap.sum, 5_000);
        assert_eq!(snap.count, 1);
        assert_eq!(snap.min, 5_000);
        assert_eq!(snap.max, 5_000);
        // 5_000ns is in bucket 1 (1us-10us).
        assert_eq!(snap.histogram[1], 1);
    }

    #[test]
    fn test_latency_aggregate_multiple_values() {
        let mut agg = LatencyAggregate::new();
        agg.record(1_000);
        agg.record(5_000);
        agg.record(10_000);

        let snap = agg.snapshot();
        assert_eq!(snap.sum, 16_000);
        assert_eq!(snap.count, 3);
        assert_eq!(snap.min, 1_000);
        assert_eq!(snap.max, 10_000);
    }

    #[test]
    fn test_latency_aggregate_empty_snapshot() {
        let agg = LatencyAggregate::new();
        let snap = agg.snapshot();
        assert_eq!(snap.count, 0);
        assert_eq!(snap.min, 0);
        assert_eq!(snap.max, 0);
    }

    #[test]
    fn test_counter_aggregate_add() {
        let mut agg = CounterAggregate::new();
        agg.add(100);
        agg.add(200);

        let snap = agg.snapshot();
        assert_eq!(snap.count, 2);
        assert_eq!(snap.sum, 300);
    }

    #[test]
    fn test_counter_aggregate_add_count() {
        let mut agg = CounterAggregate::new();
        agg.add_count(5);
        agg.add_count(3);

        let snap = agg.snapshot();
        assert_eq!(snap.count, 8);
        assert_eq!(snap.sum, 0);
    }

    #[test]
    fn test_counter_aggregate_empty_snapshot() {
        let agg = CounterAggregate::new();
        let snap = agg.snapshot();
        assert_eq!(snap.count, 0);
        assert_eq!(snap.sum, 0);
    }

    #[test]
    fn test_count_aggregate_add_count() {
        let mut agg = CountAggregate::new();
        agg.add_count(5);
        agg.add_count(3);

        let snap = agg.snapshot();
        assert_eq!(snap.count, 8);
        assert_eq!(snap.sum, 0);
    }

    #[test]
    fn test_count_aggregate_empty_snapshot() {
        let agg = CountAggregate::new();
        let snap = agg.snapshot();
        assert_eq!(snap.count, 0);
        assert_eq!(snap.sum, 0);
    }

    #[test]
    fn test_gauge_aggregate_single_value() {
        let mut agg = GaugeAggregate::new();
        agg.record(42);

        let snap = agg.snapshot();
        assert_eq!(snap.sum, 42);
        assert_eq!(snap.count, 1);
        assert_eq!(snap.min, 42);
        assert_eq!(snap.max, 42);
    }

    #[test]
    fn test_gauge_aggregate_multiple_values() {
        let mut agg = GaugeAggregate::new();
        agg.record(10);
        agg.record(50);
        agg.record(30);

        let snap = agg.snapshot();
        assert_eq!(snap.sum, 90);
        assert_eq!(snap.count, 3);
        assert_eq!(snap.min, 10);
        assert_eq!(snap.max, 50);
    }

    #[test]
    fn test_gauge_aggregate_empty_snapshot() {
        let agg = GaugeAggregate::new();
        let snap = agg.snapshot();
        assert_eq!(snap.count, 0);
        assert_eq!(snap.min, 0);
        assert_eq!(snap.max, 0);
    }

    #[test]
    fn test_gauge_aggregate_negative_values() {
        let mut agg = GaugeAggregate::new();
        agg.record(-10);
        agg.record(20);
        agg.record(-30);

        let snap = agg.snapshot();
        assert_eq!(snap.sum, -20);
        assert_eq!(snap.count, 3);
        assert_eq!(snap.min, -30);
        assert_eq!(snap.max, 20);
    }

    #[test]
    fn test_latency_aggregate_many_values() {
        let mut agg = LatencyAggregate::new();
        for i in 0..4000 {
            agg.record(i as u64);
        }
        let snap = agg.snapshot();
        assert_eq!(snap.count, 4000);
    }

    #[test]
    fn test_disk_aggregate_records_all_components() {
        let mut agg = DiskAggregate::new();
        agg.record(50_000, 4096, 3);

        let latency = agg.latency_snapshot();
        assert_eq!(latency.count, 1);
        assert_eq!(latency.sum, 50_000);

        let bytes = agg.bytes_snapshot();
        assert_eq!(bytes.count, 1);
        assert_eq!(bytes.sum, 4096);

        let queue_depth = agg.queue_depth_snapshot();
        assert_eq!(queue_depth.count, 1);
        assert_eq!(queue_depth.sum, 3);
    }

    #[test]
    fn test_tcp_tx_aggregate_records_all_components() {
        let mut agg = TcpTxAggregate::new();
        agg.record(1_500, 120, 64_000);

        let bytes = agg.bytes_snapshot();
        assert_eq!(bytes.count, 1);
        assert_eq!(bytes.sum, 1_500);

        let rtt = agg.rtt_snapshot();
        assert_eq!(rtt.count, 1);
        assert_eq!(rtt.sum, 120);

        let cwnd = agg.cwnd_snapshot();
        assert_eq!(cwnd.count, 1);
        assert_eq!(cwnd.sum, 64_000);
    }
}
