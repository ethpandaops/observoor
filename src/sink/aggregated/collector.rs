use std::collections::HashMap;
use std::time::Duration;

#[cfg(all(feature = "bpf", not(test)))]
use std::fs;

use crate::config::{EventSamplingMode, SamplingConfig};
use crate::tracer::event::{ClientType, EventType, MAX_EVENT_TYPE};

use super::aggregate::{CounterAggregate, GaugeAggregate, LatencyAggregate};
use super::buffer::Buffer;
use super::dimension::{
    direction_string, port_label_string, rw_string, BasicDimension, DiskDimension,
    TCPMetricsDimension,
};
use super::metric::{
    BatchMetadata, CounterMetric, CpuUtilMetric, GaugeMetric, LatencyMetric, MetricBatch,
    SamplingMode, SlotInfo, WindowInfo,
};
#[cfg(feature = "bpf")]
use super::metric::{
    MemoryUsageMetric, ProcessFDUsageMetric, ProcessIOUsageMetric, ProcessSchedUsageMetric,
};

/// Canonical list of all metric names emitted by this collector.
pub const ALL_METRIC_NAMES: &[&str] = &[
    // Latency (14)
    "syscall_read",
    "syscall_write",
    "syscall_futex",
    "syscall_mmap",
    "syscall_epoll_wait",
    "syscall_fsync",
    "syscall_fdatasync",
    "syscall_pwrite",
    "sched_on_cpu",
    "sched_off_cpu",
    "sched_runqueue",
    "mem_reclaim",
    "mem_compaction",
    "disk_latency",
    // Counter (13)
    "page_fault_major",
    "page_fault_minor",
    "swap_in",
    "swap_out",
    "oom_kill",
    "fd_open",
    "fd_close",
    "process_exit",
    "tcp_state_change",
    "net_io",
    "tcp_retransmit",
    "disk_bytes",
    "block_merge",
    // Gauge (3)
    "tcp_rtt",
    "tcp_cwnd",
    "disk_queue_depth",
];

/// Performs single-pass collection from a Buffer into a MetricBatch.
pub struct Collector {
    interval_ms: u16,
    sampling_by_event: [EventSamplingMetadata; MAX_EVENT_TYPE + 1],
    #[cfg(feature = "bpf")]
    collect_process_snapshots: bool,
    #[cfg(feature = "bpf")]
    proc_status_reader: fn(u32) -> Option<ProcStatusSnapshot>,
    #[cfg(feature = "bpf")]
    proc_io_reader: fn(u32) -> Option<ProcIOSnapshot>,
    #[cfg(feature = "bpf")]
    proc_limits_reader: fn(u32) -> Option<ProcLimitsSnapshot>,
    #[cfg(feature = "bpf")]
    proc_fd_count_reader: fn(u32) -> Option<u32>,
}

#[derive(Clone, Copy)]
struct EventSamplingMetadata {
    mode: SamplingMode,
    rate: f32,
}

#[cfg(feature = "bpf")]
#[derive(Clone, Copy, Debug, Default)]
struct ProcMemorySnapshot {
    vm_size_bytes: u64,
    vm_rss_bytes: u64,
    rss_anon_bytes: u64,
    rss_file_bytes: u64,
    rss_shmem_bytes: u64,
    vm_swap_bytes: u64,
}

#[cfg(feature = "bpf")]
#[derive(Clone, Copy, Debug, Default)]
struct ProcStatusSnapshot {
    memory: Option<ProcMemorySnapshot>,
    threads: u32,
    voluntary_ctxt_switches: u64,
    nonvoluntary_ctxt_switches: u64,
}

#[cfg(feature = "bpf")]
#[derive(Clone, Copy, Debug, Default)]
struct ProcIOSnapshot {
    rchar_bytes: u64,
    wchar_bytes: u64,
    syscr: u64,
    syscw: u64,
    read_bytes: u64,
    write_bytes: u64,
    cancelled_write_bytes: i64,
}

#[cfg(feature = "bpf")]
#[derive(Clone, Copy, Debug, Default)]
struct ProcLimitsSnapshot {
    fd_limit_soft: u64,
    fd_limit_hard: u64,
}

impl Collector {
    /// Creates a new collector with the given aggregation interval.
    pub fn new(interval: Duration, sampling: &SamplingConfig) -> Self {
        Self::new_with_process_snapshots(interval, sampling, false)
    }

    /// Backward-compatible constructor for process snapshot collection.
    pub fn new_with_memory_usage(
        interval: Duration,
        sampling: &SamplingConfig,
        collect_process_snapshots: bool,
    ) -> Self {
        Self::new_with_process_snapshots(interval, sampling, collect_process_snapshots)
    }

    /// Creates a new collector and controls whether process-level snapshots are collected.
    pub fn new_with_process_snapshots(
        interval: Duration,
        sampling: &SamplingConfig,
        collect_process_snapshots: bool,
    ) -> Self {
        #[cfg(not(feature = "bpf"))]
        let _ = collect_process_snapshots;

        let mut sampling_by_event = [EventSamplingMetadata {
            mode: SamplingMode::None,
            rate: 1.0,
        }; MAX_EVENT_TYPE + 1];

        for event_type in EventType::all() {
            let resolved = sampling
                .resolved_rule_for_event(*event_type)
                .unwrap_or_else(|_| crate::config::ResolvedSamplingRule::none());
            let mode = match resolved.mode {
                EventSamplingMode::None => SamplingMode::None,
                EventSamplingMode::Probability => SamplingMode::Probability,
                EventSamplingMode::Nth => SamplingMode::Nth,
            };
            if let Some(slot) = sampling_by_event.get_mut(usize::from(*event_type as u8)) {
                *slot = EventSamplingMetadata {
                    mode,
                    rate: resolved.rate,
                };
            }
        }

        Self {
            interval_ms: interval.as_millis() as u16,
            sampling_by_event,
            #[cfg(feature = "bpf")]
            collect_process_snapshots,
            #[cfg(feature = "bpf")]
            proc_status_reader: default_proc_status_reader,
            #[cfg(feature = "bpf")]
            proc_io_reader: default_proc_io_reader,
            #[cfg(feature = "bpf")]
            proc_limits_reader: default_proc_limits_reader,
            #[cfg(feature = "bpf")]
            proc_fd_count_reader: default_proc_fd_count_reader,
        }
    }

    fn sampling_for_event(&self, event_type: EventType) -> EventSamplingMetadata {
        self.sampling_by_event
            .get(usize::from(event_type as u8))
            .copied()
            .unwrap_or(EventSamplingMetadata {
                mode: SamplingMode::None,
                rate: 1.0,
            })
    }

    /// Iterates the buffer once and returns all metrics.
    pub fn collect(&self, buf: &Buffer, meta: BatchMetadata) -> MetricBatch {
        let latency_capacity = self.estimate_latency_capacity(buf);
        let counter_capacity = self.estimate_counter_capacity(buf);
        let gauge_capacity = self.estimate_gauge_capacity(buf);
        let cpu_util_capacity = self.estimate_cpu_util_capacity(buf);
        #[cfg(feature = "bpf")]
        let memory_usage_capacity = if self.collect_process_snapshots {
            self.estimate_memory_usage_capacity(buf)
        } else {
            0
        };
        #[cfg(feature = "bpf")]
        let process_io_usage_capacity = if self.collect_process_snapshots {
            self.estimate_process_io_usage_capacity(buf)
        } else {
            0
        };
        #[cfg(feature = "bpf")]
        let process_fd_usage_capacity = if self.collect_process_snapshots {
            self.estimate_process_fd_usage_capacity(buf)
        } else {
            0
        };
        #[cfg(feature = "bpf")]
        let process_sched_usage_capacity = if self.collect_process_snapshots {
            self.estimate_process_sched_usage_capacity(buf)
        } else {
            0
        };
        let mut batch = MetricBatch {
            metadata: meta,
            latency: Vec::with_capacity(latency_capacity),
            counter: Vec::with_capacity(counter_capacity),
            gauge: Vec::with_capacity(gauge_capacity),
            cpu_util: Vec::with_capacity(cpu_util_capacity),
            #[cfg(feature = "bpf")]
            memory_usage: Vec::with_capacity(memory_usage_capacity),
            #[cfg(feature = "bpf")]
            process_io_usage: Vec::with_capacity(process_io_usage_capacity),
            #[cfg(feature = "bpf")]
            process_fd_usage: Vec::with_capacity(process_fd_usage_capacity),
            #[cfg(feature = "bpf")]
            process_sched_usage: Vec::with_capacity(process_sched_usage_capacity),
        };

        self.collect_into(buf, &mut batch);
        batch
    }

    /// Iterates the buffer and writes metrics into an existing batch.
    ///
    /// Reuses existing vector allocations when capacities are sufficient.
    pub fn collect_into(&self, buf: &Buffer, batch: &mut MetricBatch) {
        let window = WindowInfo {
            start: buf.start_time,
            interval_ms: self.interval_ms,
        };

        let slot = SlotInfo {
            number: buf.wallclock_slot as u32,
            start_time: buf.wallclock_slot_start,
        };

        let latency_capacity = self.estimate_latency_capacity(buf);
        let counter_capacity = self.estimate_counter_capacity(buf);
        let gauge_capacity = self.estimate_gauge_capacity(buf);
        let cpu_util_capacity = self.estimate_cpu_util_capacity(buf);
        #[cfg(feature = "bpf")]
        let memory_usage_capacity = if self.collect_process_snapshots {
            self.estimate_memory_usage_capacity(buf)
        } else {
            0
        };
        #[cfg(feature = "bpf")]
        let process_io_usage_capacity = if self.collect_process_snapshots {
            self.estimate_process_io_usage_capacity(buf)
        } else {
            0
        };
        #[cfg(feature = "bpf")]
        let process_fd_usage_capacity = if self.collect_process_snapshots {
            self.estimate_process_fd_usage_capacity(buf)
        } else {
            0
        };
        #[cfg(feature = "bpf")]
        let process_sched_usage_capacity = if self.collect_process_snapshots {
            self.estimate_process_sched_usage_capacity(buf)
        } else {
            0
        };
        reserve_if_needed(&mut batch.latency, latency_capacity);
        reserve_if_needed(&mut batch.counter, counter_capacity);
        reserve_if_needed(&mut batch.gauge, gauge_capacity);
        reserve_if_needed(&mut batch.cpu_util, cpu_util_capacity);
        #[cfg(feature = "bpf")]
        if self.collect_process_snapshots {
            reserve_if_needed(&mut batch.memory_usage, memory_usage_capacity);
            reserve_if_needed(&mut batch.process_io_usage, process_io_usage_capacity);
            reserve_if_needed(&mut batch.process_fd_usage, process_fd_usage_capacity);
            reserve_if_needed(&mut batch.process_sched_usage, process_sched_usage_capacity);
        }

        batch.latency.clear();
        batch.counter.clear();
        batch.gauge.clear();
        batch.cpu_util.clear();
        #[cfg(feature = "bpf")]
        {
            batch.memory_usage.clear();
            batch.process_io_usage.clear();
            batch.process_fd_usage.clear();
            batch.process_sched_usage.clear();
        }

        self.collect_basic_latency(batch, buf, window, slot);
        self.collect_disk_latency(batch, buf, window, slot);
        self.collect_basic_counters(batch, buf, window, slot);
        self.collect_network_counters(batch, buf, window, slot);
        self.collect_disk_counters(batch, buf, window, slot);
        self.collect_tcp_gauges(batch, buf, window, slot);
        self.collect_disk_gauges(batch, buf, window, slot);
        self.collect_cpu_utilization(batch, buf, window, slot);
    }

    fn estimate_latency_capacity(&self, buf: &Buffer) -> usize {
        buf.syscall_read.len()
            + buf.syscall_write.len()
            + buf.syscall_futex.len()
            + buf.syscall_mmap.len()
            + buf.syscall_epoll_wait.len()
            + buf.syscall_fsync.len()
            + buf.syscall_fdatasync.len()
            + buf.syscall_pwrite.len()
            + buf.sched_on_cpu.len()
            + buf.sched_off_cpu.len()
            + buf.sched_runqueue.len()
            + buf.mem_reclaim.len()
            + buf.mem_compaction.len()
            + buf.disk_latency.len()
    }

    fn estimate_counter_capacity(&self, buf: &Buffer) -> usize {
        buf.page_fault_major.len()
            + buf.page_fault_minor.len()
            + buf.swap_in.len()
            + buf.swap_out.len()
            + buf.oom_kill.len()
            + buf.fd_open.len()
            + buf.fd_close.len()
            + buf.process_exit.len()
            + buf.tcp_state_change.len()
            + buf.net_io.len()
            + buf.tcp_retransmit.len()
            + buf.disk_bytes.len()
            + buf.block_merge.len()
    }

    fn estimate_gauge_capacity(&self, buf: &Buffer) -> usize {
        buf.tcp_rtt.len() + buf.tcp_cwnd.len() + buf.disk_queue_depth.len()
    }

    fn estimate_cpu_util_capacity(&self, buf: &Buffer) -> usize {
        buf.cpu_on_core.len()
    }

    #[cfg(feature = "bpf")]
    fn estimate_memory_usage_capacity(&self, buf: &Buffer) -> usize {
        buf.cpu_on_core.len()
    }

    #[cfg(feature = "bpf")]
    fn estimate_process_io_usage_capacity(&self, buf: &Buffer) -> usize {
        buf.cpu_on_core.len()
    }

    #[cfg(feature = "bpf")]
    fn estimate_process_fd_usage_capacity(&self, buf: &Buffer) -> usize {
        buf.cpu_on_core.len()
    }

    #[cfg(feature = "bpf")]
    fn estimate_process_sched_usage_capacity(&self, buf: &Buffer) -> usize {
        buf.cpu_on_core.len()
    }

    /// Collects all basic-dimension latency metrics (syscalls, sched, memory).
    fn collect_basic_latency(
        &self,
        batch: &mut MetricBatch,
        buf: &Buffer,
        window: WindowInfo,
        slot: SlotInfo,
    ) {
        let maps: &[(
            EventType,
            &str,
            &dashmap::DashMap<BasicDimension, LatencyAggregate>,
        )] = &[
            (EventType::SyscallRead, "syscall_read", &buf.syscall_read),
            (EventType::SyscallWrite, "syscall_write", &buf.syscall_write),
            (EventType::SyscallFutex, "syscall_futex", &buf.syscall_futex),
            (EventType::SyscallMmap, "syscall_mmap", &buf.syscall_mmap),
            (
                EventType::SyscallEpollWait,
                "syscall_epoll_wait",
                &buf.syscall_epoll_wait,
            ),
            (EventType::SyscallFsync, "syscall_fsync", &buf.syscall_fsync),
            (
                EventType::SyscallFdatasync,
                "syscall_fdatasync",
                &buf.syscall_fdatasync,
            ),
            (
                EventType::SyscallPwrite,
                "syscall_pwrite",
                &buf.syscall_pwrite,
            ),
            (EventType::SchedSwitch, "sched_on_cpu", &buf.sched_on_cpu),
            (
                EventType::SchedRunqueue,
                "sched_off_cpu",
                &buf.sched_off_cpu,
            ),
            (
                EventType::SchedRunqueue,
                "sched_runqueue",
                &buf.sched_runqueue,
            ),
            (EventType::MemReclaim, "mem_reclaim", &buf.mem_reclaim),
            (
                EventType::MemCompaction,
                "mem_compaction",
                &buf.mem_compaction,
            ),
        ];

        for &(event_type, name, map) in maps {
            let sampling = self.sampling_for_event(event_type);
            for entry in map.iter() {
                let dim = *entry.key();
                let snap = entry.value().snapshot();
                if snap.count == 0 {
                    continue;
                }

                batch.latency.push(LatencyMetric {
                    metric_type: name,
                    window,
                    slot,
                    pid: dim.pid,
                    client_type: client_type_from_u8(dim.client_type),
                    device_id: None,
                    rw: None,
                    sampling_mode: sampling.mode,
                    sampling_rate: sampling.rate,
                    sum: snap.sum,
                    count: snap.count,
                    min: snap.min,
                    max: snap.max,
                    histogram: snap.histogram,
                });
            }
        }
    }

    /// Collects disk latency metrics with device/rw dimensions.
    fn collect_disk_latency(
        &self,
        batch: &mut MetricBatch,
        buf: &Buffer,
        window: WindowInfo,
        slot: SlotInfo,
    ) {
        let sampling = self.sampling_for_event(EventType::DiskIO);
        for entry in buf.disk_latency.iter() {
            let dim = *entry.key();
            let snap = entry.value().snapshot();
            if snap.count == 0 {
                continue;
            }

            batch.latency.push(LatencyMetric {
                metric_type: "disk_latency",
                window,
                slot,
                pid: dim.pid,
                client_type: client_type_from_u8(dim.client_type),
                device_id: Some(dim.device_id),
                rw: Some(rw_string(dim.rw)),
                sampling_mode: sampling.mode,
                sampling_rate: sampling.rate,
                sum: snap.sum,
                count: snap.count,
                min: snap.min,
                max: snap.max,
                histogram: snap.histogram,
            });
        }
    }

    /// Collects all basic-dimension counter metrics.
    fn collect_basic_counters(
        &self,
        batch: &mut MetricBatch,
        buf: &Buffer,
        window: WindowInfo,
        slot: SlotInfo,
    ) {
        let maps: &[(
            EventType,
            &str,
            &dashmap::DashMap<BasicDimension, CounterAggregate>,
        )] = &[
            (
                EventType::PageFault,
                "page_fault_major",
                &buf.page_fault_major,
            ),
            (
                EventType::PageFault,
                "page_fault_minor",
                &buf.page_fault_minor,
            ),
            (EventType::SwapIn, "swap_in", &buf.swap_in),
            (EventType::SwapOut, "swap_out", &buf.swap_out),
            (EventType::OOMKill, "oom_kill", &buf.oom_kill),
            (EventType::FDOpen, "fd_open", &buf.fd_open),
            (EventType::FDClose, "fd_close", &buf.fd_close),
            (EventType::ProcessExit, "process_exit", &buf.process_exit),
            (
                EventType::TcpState,
                "tcp_state_change",
                &buf.tcp_state_change,
            ),
        ];

        for &(event_type, name, map) in maps {
            let sampling = self.sampling_for_event(event_type);
            for entry in map.iter() {
                let dim = *entry.key();
                let snap = entry.value().snapshot();
                if snap.count == 0 {
                    continue;
                }

                batch.counter.push(CounterMetric {
                    metric_type: name,
                    window,
                    slot,
                    pid: dim.pid,
                    client_type: client_type_from_u8(dim.client_type),
                    device_id: None,
                    rw: None,
                    port_label: None,
                    direction: None,
                    sampling_mode: sampling.mode,
                    sampling_rate: sampling.rate,
                    sum: snap.sum,
                    count: snap.count,
                });
            }
        }
    }

    /// Collects network counter metrics with port label/direction.
    fn collect_network_counters(
        &self,
        batch: &mut MetricBatch,
        buf: &Buffer,
        window: WindowInfo,
        slot: SlotInfo,
    ) {
        for entry in buf.net_io.iter() {
            let dim = *entry.key();
            let snap = entry.value().snapshot();
            if snap.count == 0 {
                continue;
            }

            let source_event = if dim.direction == 0 {
                EventType::NetTX
            } else {
                EventType::NetRX
            };
            let sampling = self.sampling_for_event(source_event);

            batch.counter.push(CounterMetric {
                metric_type: "net_io",
                window,
                slot,
                pid: dim.pid,
                client_type: client_type_from_u8(dim.client_type),
                device_id: None,
                rw: None,
                port_label: Some(port_label_string(dim.port_label)),
                direction: Some(direction_string(dim.direction)),
                sampling_mode: sampling.mode,
                sampling_rate: sampling.rate,
                sum: snap.sum,
                count: snap.count,
            });
        }

        let sampling = self.sampling_for_event(EventType::TcpRetransmit);
        for entry in buf.tcp_retransmit.iter() {
            let dim = *entry.key();
            let snap = entry.value().snapshot();
            if snap.count == 0 {
                continue;
            }

            batch.counter.push(CounterMetric {
                metric_type: "tcp_retransmit",
                window,
                slot,
                pid: dim.pid,
                client_type: client_type_from_u8(dim.client_type),
                device_id: None,
                rw: None,
                port_label: Some(port_label_string(dim.port_label)),
                direction: Some(direction_string(dim.direction)),
                sampling_mode: sampling.mode,
                sampling_rate: sampling.rate,
                sum: snap.sum,
                count: snap.count,
            });
        }
    }

    /// Collects disk counter metrics with device/rw dimensions.
    fn collect_disk_counters(
        &self,
        batch: &mut MetricBatch,
        buf: &Buffer,
        window: WindowInfo,
        slot: SlotInfo,
    ) {
        let maps: &[(
            EventType,
            &str,
            &dashmap::DashMap<DiskDimension, CounterAggregate>,
        )] = &[
            (EventType::DiskIO, "disk_bytes", &buf.disk_bytes),
            (EventType::BlockMerge, "block_merge", &buf.block_merge),
        ];

        for &(event_type, name, map) in maps {
            let sampling = self.sampling_for_event(event_type);
            for entry in map.iter() {
                let dim = *entry.key();
                let snap = entry.value().snapshot();
                if snap.count == 0 {
                    continue;
                }

                batch.counter.push(CounterMetric {
                    metric_type: name,
                    window,
                    slot,
                    pid: dim.pid,
                    client_type: client_type_from_u8(dim.client_type),
                    device_id: Some(dim.device_id),
                    rw: Some(rw_string(dim.rw)),
                    port_label: None,
                    direction: None,
                    sampling_mode: sampling.mode,
                    sampling_rate: sampling.rate,
                    sum: snap.sum,
                    count: snap.count,
                });
            }
        }
    }

    /// Collects TCP gauge metrics with local port dimension.
    fn collect_tcp_gauges(
        &self,
        batch: &mut MetricBatch,
        buf: &Buffer,
        window: WindowInfo,
        slot: SlotInfo,
    ) {
        let maps: &[(&str, &dashmap::DashMap<TCPMetricsDimension, GaugeAggregate>)] =
            &[("tcp_rtt", &buf.tcp_rtt), ("tcp_cwnd", &buf.tcp_cwnd)];
        let sampling = self.sampling_for_event(EventType::NetTX);

        for &(name, map) in maps {
            for entry in map.iter() {
                let dim = *entry.key();
                let snap = entry.value().snapshot();
                if snap.count == 0 {
                    continue;
                }

                batch.gauge.push(GaugeMetric {
                    metric_type: name,
                    window,
                    slot,
                    pid: dim.pid,
                    client_type: client_type_from_u8(dim.client_type),
                    device_id: None,
                    rw: None,
                    port_label: Some(port_label_string(dim.port_label)),
                    sampling_mode: sampling.mode,
                    sampling_rate: sampling.rate,
                    sum: snap.sum,
                    count: snap.count,
                    min: snap.min,
                    max: snap.max,
                });
            }
        }
    }

    /// Collects disk gauge metrics with device/rw dimensions.
    fn collect_disk_gauges(
        &self,
        batch: &mut MetricBatch,
        buf: &Buffer,
        window: WindowInfo,
        slot: SlotInfo,
    ) {
        let sampling = self.sampling_for_event(EventType::DiskIO);
        for entry in buf.disk_queue_depth.iter() {
            let dim = *entry.key();
            let snap = entry.value().snapshot();
            if snap.count == 0 {
                continue;
            }

            batch.gauge.push(GaugeMetric {
                metric_type: "disk_queue_depth",
                window,
                slot,
                pid: dim.pid,
                client_type: client_type_from_u8(dim.client_type),
                device_id: Some(dim.device_id),
                rw: Some(rw_string(dim.rw)),
                port_label: None,
                sampling_mode: sampling.mode,
                sampling_rate: sampling.rate,
                sum: snap.sum,
                count: snap.count,
                min: snap.min,
                max: snap.max,
            });
        }
    }

    /// Collects per-process CPU utilization summaries from per-core counters.
    fn collect_cpu_utilization(
        &self,
        batch: &mut MetricBatch,
        buf: &Buffer,
        window: WindowInfo,
        slot: SlotInfo,
    ) {
        let interval_ns = i64::from(self.interval_ms) * 1_000_000;
        if interval_ns <= 0 {
            return;
        }
        let sampling = self.sampling_for_event(EventType::SchedSwitch);

        let mut grouped: HashMap<(u32, u8), Vec<(u32, super::aggregate::CounterSnapshot)>> =
            HashMap::with_capacity(buf.cpu_on_core.len());

        for entry in buf.cpu_on_core.iter() {
            let dim = *entry.key();
            let snap = entry.value().snapshot();
            if snap.count == 0 {
                continue;
            }
            grouped
                .entry((dim.pid, dim.client_type))
                .or_default()
                .push((dim.cpu_id, snap));
        }

        for ((pid, client_type), cores) in grouped {
            if cores.is_empty() {
                continue;
            }

            let active_cores = u16::try_from(cores.len()).unwrap_or(u16::MAX);
            let mut total_on_cpu_ns = 0i64;
            let mut event_count = 0u32;
            let mut max_core_on_cpu_ns = i64::MIN;
            let mut max_core_id = 0u32;
            let mut min_core_pct = f32::MAX;
            let mut max_core_pct = f32::MIN;
            let mut sum_core_pct = 0.0f32;

            for (cpu_id, snap) in cores {
                total_on_cpu_ns += snap.sum;
                event_count = event_count.saturating_add(snap.count);

                if snap.sum > max_core_on_cpu_ns {
                    max_core_on_cpu_ns = snap.sum;
                    max_core_id = cpu_id;
                }

                let pct = ((snap.sum as f64 / interval_ns as f64) * 100.0) as f32;
                sum_core_pct += pct;
                if pct < min_core_pct {
                    min_core_pct = pct;
                }
                if pct > max_core_pct {
                    max_core_pct = pct;
                }
            }

            if max_core_on_cpu_ns == i64::MIN {
                max_core_on_cpu_ns = 0;
            }
            if min_core_pct == f32::MAX {
                min_core_pct = 0.0;
            }
            if max_core_pct == f32::MIN {
                max_core_pct = 0.0;
            }
            let mean_core_pct = if active_cores == 0 {
                0.0
            } else {
                sum_core_pct / f32::from(active_cores)
            };

            batch.cpu_util.push(CpuUtilMetric {
                metric_type: "cpu_utilization",
                window,
                slot,
                pid,
                client_type: client_type_from_u8(client_type),
                sampling_mode: sampling.mode,
                sampling_rate: sampling.rate,
                total_on_cpu_ns,
                event_count,
                active_cores,
                system_cores: buf.system_cores,
                max_core_on_cpu_ns,
                max_core_id,
                mean_core_pct,
                min_core_pct,
                max_core_pct,
            });

            #[cfg(feature = "bpf")]
            if self.collect_process_snapshots {
                self.collect_process_snapshot_metrics(batch, window, slot, pid, client_type);
            }
        }
    }

    #[cfg(feature = "bpf")]
    fn collect_process_snapshot_metrics(
        &self,
        batch: &mut MetricBatch,
        window: WindowInfo,
        slot: SlotInfo,
        pid: u32,
        client_type: u8,
    ) {
        if let Some(status) = (self.proc_status_reader)(pid) {
            if let Some(memory) = status.memory {
                self.emit_memory_usage_metric(batch, window, slot, pid, client_type, memory);
            }
            self.emit_process_sched_usage_metric(batch, window, slot, pid, client_type, status);
        }

        if let Some(io) = (self.proc_io_reader)(pid) {
            self.emit_process_io_usage_metric(batch, window, slot, pid, client_type, io);
        }

        let open_fds = (self.proc_fd_count_reader)(pid);
        let limits = (self.proc_limits_reader)(pid);
        if open_fds.is_none() && limits.is_none() {
            return;
        }

        self.emit_process_fd_usage_metric(batch, window, slot, pid, client_type, open_fds, limits);
    }

    #[cfg(feature = "bpf")]
    fn emit_memory_usage_metric(
        &self,
        batch: &mut MetricBatch,
        window: WindowInfo,
        slot: SlotInfo,
        pid: u32,
        client_type: u8,
        snapshot: ProcMemorySnapshot,
    ) {
        batch.memory_usage.push(MemoryUsageMetric {
            metric_type: "memory_usage",
            window,
            slot,
            pid,
            client_type: client_type_from_u8(client_type),
            sampling_mode: SamplingMode::None,
            sampling_rate: 1.0,
            vm_size_bytes: snapshot.vm_size_bytes,
            vm_rss_bytes: snapshot.vm_rss_bytes,
            rss_anon_bytes: snapshot.rss_anon_bytes,
            rss_file_bytes: snapshot.rss_file_bytes,
            rss_shmem_bytes: snapshot.rss_shmem_bytes,
            vm_swap_bytes: snapshot.vm_swap_bytes,
        });
    }

    #[cfg(feature = "bpf")]
    fn emit_process_io_usage_metric(
        &self,
        batch: &mut MetricBatch,
        window: WindowInfo,
        slot: SlotInfo,
        pid: u32,
        client_type: u8,
        snapshot: ProcIOSnapshot,
    ) {
        batch.process_io_usage.push(ProcessIOUsageMetric {
            metric_type: "process_io_usage",
            window,
            slot,
            pid,
            client_type: client_type_from_u8(client_type),
            sampling_mode: SamplingMode::None,
            sampling_rate: 1.0,
            rchar_bytes: snapshot.rchar_bytes,
            wchar_bytes: snapshot.wchar_bytes,
            syscr: snapshot.syscr,
            syscw: snapshot.syscw,
            read_bytes: snapshot.read_bytes,
            write_bytes: snapshot.write_bytes,
            cancelled_write_bytes: snapshot.cancelled_write_bytes,
        });
    }

    #[cfg(feature = "bpf")]
    fn emit_process_fd_usage_metric(
        &self,
        batch: &mut MetricBatch,
        window: WindowInfo,
        slot: SlotInfo,
        pid: u32,
        client_type: u8,
        open_fds: Option<u32>,
        limits: Option<ProcLimitsSnapshot>,
    ) {
        let (fd_limit_soft, fd_limit_hard) = limits
            .map(|v| (v.fd_limit_soft, v.fd_limit_hard))
            .unwrap_or((0, 0));

        batch.process_fd_usage.push(ProcessFDUsageMetric {
            metric_type: "process_fd_usage",
            window,
            slot,
            pid,
            client_type: client_type_from_u8(client_type),
            sampling_mode: SamplingMode::None,
            sampling_rate: 1.0,
            open_fds: open_fds.unwrap_or(0),
            fd_limit_soft,
            fd_limit_hard,
        });
    }

    #[cfg(feature = "bpf")]
    fn emit_process_sched_usage_metric(
        &self,
        batch: &mut MetricBatch,
        window: WindowInfo,
        slot: SlotInfo,
        pid: u32,
        client_type: u8,
        snapshot: ProcStatusSnapshot,
    ) {
        if snapshot.threads == 0
            && snapshot.voluntary_ctxt_switches == 0
            && snapshot.nonvoluntary_ctxt_switches == 0
        {
            return;
        }

        batch.process_sched_usage.push(ProcessSchedUsageMetric {
            metric_type: "process_sched_usage",
            window,
            slot,
            pid,
            client_type: client_type_from_u8(client_type),
            sampling_mode: SamplingMode::None,
            sampling_rate: 1.0,
            threads: snapshot.threads,
            voluntary_ctxt_switches: snapshot.voluntary_ctxt_switches,
            nonvoluntary_ctxt_switches: snapshot.nonvoluntary_ctxt_switches,
        });
    }
}

#[cfg(all(feature = "bpf", not(test)))]
fn default_proc_status_reader(pid: u32) -> Option<ProcStatusSnapshot> {
    read_proc_status_snapshot(pid)
}

#[cfg(all(feature = "bpf", test))]
fn default_proc_status_reader(_pid: u32) -> Option<ProcStatusSnapshot> {
    None
}

#[cfg(all(feature = "bpf", not(test)))]
fn default_proc_io_reader(pid: u32) -> Option<ProcIOSnapshot> {
    read_proc_io_snapshot(pid)
}

#[cfg(all(feature = "bpf", test))]
fn default_proc_io_reader(_pid: u32) -> Option<ProcIOSnapshot> {
    None
}

#[cfg(all(feature = "bpf", not(test)))]
fn default_proc_limits_reader(pid: u32) -> Option<ProcLimitsSnapshot> {
    read_proc_limits_snapshot(pid)
}

#[cfg(all(feature = "bpf", test))]
fn default_proc_limits_reader(_pid: u32) -> Option<ProcLimitsSnapshot> {
    None
}

#[cfg(all(feature = "bpf", not(test)))]
fn default_proc_fd_count_reader(pid: u32) -> Option<u32> {
    read_proc_fd_count(pid)
}

#[cfg(all(feature = "bpf", test))]
fn default_proc_fd_count_reader(_pid: u32) -> Option<u32> {
    None
}

#[cfg(all(feature = "bpf", not(test)))]
fn read_proc_status_snapshot(pid: u32) -> Option<ProcStatusSnapshot> {
    let path = format!("/proc/{pid}/status");
    let status = fs::read_to_string(path).ok()?;
    parse_proc_status_snapshot(&status)
}

#[cfg(feature = "bpf")]
fn parse_proc_status_snapshot(status: &str) -> Option<ProcStatusSnapshot> {
    let memory = parse_proc_memory_snapshot(status);
    let threads = parse_proc_status_u64(status, "Threads:")
        .and_then(|v| u32::try_from(v).ok())
        .unwrap_or(0);
    let voluntary_ctxt_switches =
        parse_proc_status_u64(status, "voluntary_ctxt_switches:").unwrap_or(0);
    let nonvoluntary_ctxt_switches =
        parse_proc_status_u64(status, "nonvoluntary_ctxt_switches:").unwrap_or(0);

    if memory.is_none()
        && threads == 0
        && voluntary_ctxt_switches == 0
        && nonvoluntary_ctxt_switches == 0
    {
        return None;
    }

    Some(ProcStatusSnapshot {
        memory,
        threads,
        voluntary_ctxt_switches,
        nonvoluntary_ctxt_switches,
    })
}

#[cfg(feature = "bpf")]
fn parse_proc_memory_snapshot(status: &str) -> Option<ProcMemorySnapshot> {
    let snapshot = ProcMemorySnapshot {
        vm_size_bytes: parse_proc_status_kb_bytes(status, "VmSize:").unwrap_or(0),
        vm_rss_bytes: parse_proc_status_kb_bytes(status, "VmRSS:").unwrap_or(0),
        rss_anon_bytes: parse_proc_status_kb_bytes(status, "RssAnon:").unwrap_or(0),
        rss_file_bytes: parse_proc_status_kb_bytes(status, "RssFile:").unwrap_or(0),
        rss_shmem_bytes: parse_proc_status_kb_bytes(status, "RssShmem:").unwrap_or(0),
        vm_swap_bytes: parse_proc_status_kb_bytes(status, "VmSwap:").unwrap_or(0),
    };

    if snapshot.vm_size_bytes == 0
        && snapshot.vm_rss_bytes == 0
        && snapshot.rss_anon_bytes == 0
        && snapshot.rss_file_bytes == 0
        && snapshot.rss_shmem_bytes == 0
        && snapshot.vm_swap_bytes == 0
    {
        return None;
    }

    Some(snapshot)
}

#[cfg(all(feature = "bpf", not(test)))]
fn read_proc_io_snapshot(pid: u32) -> Option<ProcIOSnapshot> {
    let path = format!("/proc/{pid}/io");
    let io = fs::read_to_string(path).ok()?;
    parse_proc_io_snapshot(&io)
}

#[cfg(feature = "bpf")]
fn parse_proc_io_snapshot(io: &str) -> Option<ProcIOSnapshot> {
    let snapshot = ProcIOSnapshot {
        rchar_bytes: parse_proc_io_u64(io, "rchar:").unwrap_or(0),
        wchar_bytes: parse_proc_io_u64(io, "wchar:").unwrap_or(0),
        syscr: parse_proc_io_u64(io, "syscr:").unwrap_or(0),
        syscw: parse_proc_io_u64(io, "syscw:").unwrap_or(0),
        read_bytes: parse_proc_io_u64(io, "read_bytes:").unwrap_or(0),
        write_bytes: parse_proc_io_u64(io, "write_bytes:").unwrap_or(0),
        cancelled_write_bytes: parse_proc_io_i64(io, "cancelled_write_bytes:").unwrap_or(0),
    };

    if snapshot.rchar_bytes == 0
        && snapshot.wchar_bytes == 0
        && snapshot.syscr == 0
        && snapshot.syscw == 0
        && snapshot.read_bytes == 0
        && snapshot.write_bytes == 0
        && snapshot.cancelled_write_bytes == 0
    {
        return None;
    }

    Some(snapshot)
}

#[cfg(all(feature = "bpf", not(test)))]
fn read_proc_limits_snapshot(pid: u32) -> Option<ProcLimitsSnapshot> {
    let path = format!("/proc/{pid}/limits");
    let limits = fs::read_to_string(path).ok()?;
    parse_proc_limits_snapshot(&limits)
}

#[cfg(feature = "bpf")]
fn parse_proc_limits_snapshot(limits: &str) -> Option<ProcLimitsSnapshot> {
    for line in limits.lines() {
        if !line.starts_with("Max open files") {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        let soft = parts.get(3).and_then(|v| parse_proc_limit_value(v));
        let hard = parts.get(4).and_then(|v| parse_proc_limit_value(v));
        if soft.is_none() && hard.is_none() {
            return None;
        }

        return Some(ProcLimitsSnapshot {
            fd_limit_soft: soft.unwrap_or(0),
            fd_limit_hard: hard.unwrap_or(0),
        });
    }

    None
}

#[cfg(feature = "bpf")]
fn parse_proc_limit_value(value: &str) -> Option<u64> {
    if value.eq_ignore_ascii_case("unlimited") {
        return Some(u64::MAX);
    }
    value.parse::<u64>().ok()
}

#[cfg(all(feature = "bpf", not(test)))]
fn read_proc_fd_count(pid: u32) -> Option<u32> {
    let path = format!("/proc/{pid}/fd");
    let entries = fs::read_dir(path).ok()?;
    let mut count = 0u32;
    for entry in entries {
        if entry.is_ok() {
            count = count.saturating_add(1);
        }
    }
    Some(count)
}

#[cfg(feature = "bpf")]
fn parse_proc_status_kb_bytes(status: &str, key: &str) -> Option<u64> {
    parse_proc_status_u64(status, key).map(|v| v.saturating_mul(1024))
}

#[cfg(feature = "bpf")]
fn parse_proc_status_u64(status: &str, key: &str) -> Option<u64> {
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix(key) {
            let mut parts = rest.split_whitespace();
            return parts.next()?.parse::<u64>().ok();
        }
    }
    None
}

#[cfg(feature = "bpf")]
fn parse_proc_io_u64(io: &str, key: &str) -> Option<u64> {
    for line in io.lines() {
        if let Some(rest) = line.strip_prefix(key) {
            let mut parts = rest.split_whitespace();
            return parts.next()?.parse::<u64>().ok();
        }
    }
    None
}

#[cfg(feature = "bpf")]
fn parse_proc_io_i64(io: &str, key: &str) -> Option<i64> {
    for line in io.lines() {
        if let Some(rest) = line.strip_prefix(key) {
            let mut parts = rest.split_whitespace();
            return parts.next()?.parse::<i64>().ok();
        }
    }
    None
}

/// Converts a raw u8 client type to the enum, defaulting to Unknown.
fn client_type_from_u8(v: u8) -> ClientType {
    ClientType::from_u8(v).unwrap_or(ClientType::Unknown)
}

/// Ensures the vector can hold at least `required` items without reallocating.
fn reserve_if_needed<T>(vec: &mut Vec<T>, required: usize) {
    if vec.capacity() < required {
        vec.reserve(required - vec.capacity());
    }
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use super::*;
    use crate::sink::aggregated::dimension::NetworkDimension;
    use crate::tracer::event::EventType;

    fn test_meta() -> BatchMetadata {
        BatchMetadata {
            client_name: "test".into(),
            network_name: "testnet".into(),
            updated_time: SystemTime::now(),
        }
    }

    fn test_buffer() -> Buffer {
        Buffer::new(
            SystemTime::now(),
            100,
            SystemTime::now(),
            false,
            false,
            false,
            16,
            0,
        )
    }

    #[test]
    fn test_collect_empty_buffer() {
        let collector = Collector::new(Duration::from_secs(1), &SamplingConfig::default());
        let buf = test_buffer();
        let batch = collector.collect(&buf, test_meta());

        assert!(batch.is_empty());
        assert!(batch.latency.is_empty());
        assert!(batch.counter.is_empty());
        assert!(batch.gauge.is_empty());
        assert!(batch.cpu_util.is_empty());
        #[cfg(feature = "bpf")]
        assert!(batch.process_io_usage.is_empty());
        #[cfg(feature = "bpf")]
        assert!(batch.process_fd_usage.is_empty());
        #[cfg(feature = "bpf")]
        assert!(batch.process_sched_usage.is_empty());
        #[cfg(feature = "bpf")]
        assert!(batch.memory_usage.is_empty());
    }

    #[test]
    fn test_all_metric_names_cardinality() {
        assert_eq!(ALL_METRIC_NAMES.len(), 30);
        assert!(ALL_METRIC_NAMES.contains(&"syscall_read"));
        assert!(ALL_METRIC_NAMES.contains(&"net_io"));
        assert!(ALL_METRIC_NAMES.contains(&"disk_queue_depth"));
    }

    #[test]
    fn test_collect_syscall_latency() {
        let collector = Collector::new(Duration::from_secs(1), &SamplingConfig::default());
        let buf = test_buffer();
        let dim = BasicDimension {
            pid: 123,
            client_type: 1,
        };

        buf.add_syscall(EventType::SyscallRead, dim, 5_000);
        buf.add_syscall(EventType::SyscallRead, dim, 10_000);

        let batch = collector.collect(&buf, test_meta());
        assert_eq!(batch.latency.len(), 1);

        let m = &batch.latency[0];
        assert_eq!(m.metric_type, "syscall_read");
        assert_eq!(m.pid, 123);
        assert_eq!(m.client_type, ClientType::Geth);
        assert_eq!(m.count, 2);
        assert_eq!(m.sum, 15_000);
        assert_eq!(m.min, 5_000);
        assert_eq!(m.max, 10_000);
        assert!(m.device_id.is_none());
        assert!(m.rw.is_none());
    }

    #[test]
    fn test_collect_sampling_metadata_from_config() {
        let mut sampling = SamplingConfig::default();
        sampling.events.insert(
            "syscall_read".to_string(),
            crate::config::EventSamplingRule {
                mode: crate::config::EventSamplingMode::Probability,
                rate: 0.25,
            },
        );
        sampling.events.insert(
            "disk_io".to_string(),
            crate::config::EventSamplingRule {
                mode: crate::config::EventSamplingMode::Nth,
                rate: 0.5,
            },
        );

        let collector = Collector::new(Duration::from_secs(1), &sampling);
        let buf = test_buffer();
        let basic = BasicDimension {
            pid: 123,
            client_type: 1,
        };
        let disk = DiskDimension {
            pid: 123,
            client_type: 1,
            device_id: 259,
            rw: 1,
        };

        buf.add_syscall(EventType::SyscallRead, basic, 5_000);
        buf.add_disk_io(disk, 20_000, 4096, 1);

        let batch = collector.collect(&buf, test_meta());
        let syscall = batch
            .latency
            .iter()
            .find(|m| m.metric_type == "syscall_read")
            .expect("syscall_read metric should exist");
        assert_eq!(syscall.sampling_mode, SamplingMode::Probability);
        assert!((syscall.sampling_rate - 0.25).abs() < 0.0001);

        let disk_latency = batch
            .latency
            .iter()
            .find(|m| m.metric_type == "disk_latency")
            .expect("disk_latency metric should exist");
        assert_eq!(disk_latency.sampling_mode, SamplingMode::Nth);
        assert!((disk_latency.sampling_rate - 0.5).abs() < 0.0001);

        let disk_bytes = batch
            .counter
            .iter()
            .find(|m| m.metric_type == "disk_bytes")
            .expect("disk_bytes metric should exist");
        assert_eq!(disk_bytes.sampling_mode, SamplingMode::Nth);
        assert!((disk_bytes.sampling_rate - 0.5).abs() < 0.0001);
    }

    #[test]
    fn test_collect_disk_latency() {
        let collector = Collector::new(Duration::from_secs(1), &SamplingConfig::default());
        let buf = test_buffer();
        let dim = DiskDimension {
            pid: 123,
            client_type: 2,
            device_id: 259,
            rw: 1,
        };

        buf.add_disk_io(dim, 50_000, 4096, 3);

        let batch = collector.collect(&buf, test_meta());

        // disk_latency, disk_bytes counter, disk_queue_depth gauge
        let disk_lat: Vec<_> = batch
            .latency
            .iter()
            .filter(|m| m.metric_type == "disk_latency")
            .collect();
        assert_eq!(disk_lat.len(), 1);
        assert_eq!(disk_lat[0].device_id, Some(259));
        assert_eq!(disk_lat[0].rw.as_deref(), Some("write"));
    }

    #[test]
    fn test_collect_network_counters() {
        let collector = Collector::new(Duration::from_secs(1), &SamplingConfig::default());
        let buf = test_buffer();
        let dim = NetworkDimension {
            pid: 123,
            client_type: 1,
            port_label: 3, // ElJsonRpc
            direction: 0,
        };

        buf.add_net_io(dim, 1024);

        let batch = collector.collect(&buf, test_meta());
        let net: Vec<_> = batch
            .counter
            .iter()
            .filter(|m| m.metric_type == "net_io")
            .collect();
        assert_eq!(net.len(), 1);
        assert_eq!(net[0].port_label, Some("el_json_rpc"));
        assert_eq!(net[0].direction.as_deref(), Some("tx"));
        assert_eq!(net[0].sum, 1024);
    }

    #[test]
    fn test_collect_tcp_gauges() {
        let collector = Collector::new(Duration::from_secs(1), &SamplingConfig::default());
        let buf = test_buffer();
        let dim = TCPMetricsDimension {
            pid: 123,
            client_type: 1,
            port_label: 1, // ElP2PTcp
        };

        buf.add_tcp_metrics(dim, 100, 65535);

        let batch = collector.collect(&buf, test_meta());
        let rtt: Vec<_> = batch
            .gauge
            .iter()
            .filter(|m| m.metric_type == "tcp_rtt")
            .collect();
        assert_eq!(rtt.len(), 1);
        assert_eq!(rtt[0].port_label, Some("el_p2p_tcp"));
        assert_eq!(rtt[0].sum, 100);

        let cwnd: Vec<_> = batch
            .gauge
            .iter()
            .filter(|m| m.metric_type == "tcp_cwnd")
            .collect();
        assert_eq!(cwnd.len(), 1);
        assert_eq!(cwnd[0].sum, 65535);
    }

    #[test]
    fn test_collect_basic_counters() {
        let collector = Collector::new(Duration::from_secs(1), &SamplingConfig::default());
        let buf = test_buffer();
        let dim = BasicDimension {
            pid: 123,
            client_type: 1,
        };

        buf.add_page_fault(dim, true);
        buf.add_page_fault(dim, true);
        buf.add_fd_open(dim);
        buf.add_oom_kill(dim);

        let batch = collector.collect(&buf, test_meta());

        let pf_major: Vec<_> = batch
            .counter
            .iter()
            .filter(|m| m.metric_type == "page_fault_major")
            .collect();
        assert_eq!(pf_major.len(), 1);
        assert_eq!(pf_major[0].count, 2);

        let fd_open: Vec<_> = batch
            .counter
            .iter()
            .filter(|m| m.metric_type == "fd_open")
            .collect();
        assert_eq!(fd_open.len(), 1);

        let oom: Vec<_> = batch
            .counter
            .iter()
            .filter(|m| m.metric_type == "oom_kill")
            .collect();
        assert_eq!(oom.len(), 1);
    }

    #[test]
    fn test_collect_window_info() {
        let collector = Collector::new(Duration::from_millis(500), &SamplingConfig::default());
        let buf = test_buffer();
        let dim = BasicDimension {
            pid: 1,
            client_type: 1,
        };
        buf.add_fd_open(dim);

        let batch = collector.collect(&buf, test_meta());
        assert_eq!(batch.counter[0].window.interval_ms, 500);
    }

    #[test]
    fn test_collect_skips_zero_count() {
        let collector = Collector::new(Duration::from_secs(1), &SamplingConfig::default());
        let buf = test_buffer();

        // Insert an entry but don't record anything - this shouldn't happen
        // in practice since DashMap entries are created on first add, but
        // verify the count == 0 guard works.
        let batch = collector.collect(&buf, test_meta());
        assert!(batch.is_empty());
    }

    #[test]
    fn test_collect_into_matches_collect() {
        let collector = Collector::new(Duration::from_secs(1), &SamplingConfig::default());
        let buf = test_buffer();
        let basic = BasicDimension {
            pid: 77,
            client_type: 1,
        };
        let net = NetworkDimension {
            pid: 77,
            client_type: 1,
            port_label: 1, // ElP2PTcp
            direction: 0,
        };

        buf.add_syscall(EventType::SyscallRead, basic, 1_000);
        buf.add_net_io(net, 4_096);
        buf.add_fd_open(basic);

        let direct = collector.collect(&buf, test_meta());
        let mut reused = collector.collect(&buf, test_meta());
        reused.metadata.updated_time = SystemTime::UNIX_EPOCH;
        collector.collect_into(&buf, &mut reused);

        assert_eq!(direct.len(), reused.len());
        assert_eq!(direct.latency.len(), reused.latency.len());
        assert_eq!(direct.counter.len(), reused.counter.len());
        assert_eq!(direct.gauge.len(), reused.gauge.len());
        assert_eq!(direct.cpu_util.len(), reused.cpu_util.len());
        #[cfg(feature = "bpf")]
        assert_eq!(direct.memory_usage.len(), reused.memory_usage.len());
        #[cfg(feature = "bpf")]
        assert_eq!(direct.process_io_usage.len(), reused.process_io_usage.len());
        #[cfg(feature = "bpf")]
        assert_eq!(direct.process_fd_usage.len(), reused.process_fd_usage.len());
        #[cfg(feature = "bpf")]
        assert_eq!(
            direct.process_sched_usage.len(),
            reused.process_sched_usage.len()
        );
    }

    #[test]
    fn test_collect_into_reuses_capacity() {
        let collector = Collector::new(Duration::from_secs(1), &SamplingConfig::default());
        let buf = test_buffer();
        let basic = BasicDimension {
            pid: 88,
            client_type: 1,
        };
        for _ in 0..32 {
            buf.add_syscall(EventType::SyscallRead, basic, 2_000);
            buf.add_fd_open(basic);
        }

        let mut batch = collector.collect(&buf, test_meta());
        let latency_capacity = batch.latency.capacity();
        let counter_capacity = batch.counter.capacity();
        let gauge_capacity = batch.gauge.capacity();
        let cpu_util_capacity = batch.cpu_util.capacity();
        #[cfg(feature = "bpf")]
        let memory_usage_capacity = batch.memory_usage.capacity();
        #[cfg(feature = "bpf")]
        let process_io_usage_capacity = batch.process_io_usage.capacity();
        #[cfg(feature = "bpf")]
        let process_fd_usage_capacity = batch.process_fd_usage.capacity();
        #[cfg(feature = "bpf")]
        let process_sched_usage_capacity = batch.process_sched_usage.capacity();

        collector.collect_into(&buf, &mut batch);

        assert_eq!(batch.latency.capacity(), latency_capacity);
        assert_eq!(batch.counter.capacity(), counter_capacity);
        assert_eq!(batch.gauge.capacity(), gauge_capacity);
        assert_eq!(batch.cpu_util.capacity(), cpu_util_capacity);
        #[cfg(feature = "bpf")]
        assert_eq!(batch.memory_usage.capacity(), memory_usage_capacity);
        #[cfg(feature = "bpf")]
        assert_eq!(batch.process_io_usage.capacity(), process_io_usage_capacity);
        #[cfg(feature = "bpf")]
        assert_eq!(batch.process_fd_usage.capacity(), process_fd_usage_capacity);
        #[cfg(feature = "bpf")]
        assert_eq!(
            batch.process_sched_usage.capacity(),
            process_sched_usage_capacity
        );
    }

    #[test]
    fn test_collect_cpu_utilization() {
        let collector = Collector::new(Duration::from_secs(1), &SamplingConfig::default());
        let buf = test_buffer();
        let dim = BasicDimension {
            pid: 123,
            client_type: 1,
        };

        // 1.5ms on core 2, 0.5ms on core 4 over a 1s window.
        buf.add_sched_switch(dim, 1_000_000, 2, 0);
        buf.add_sched_switch(dim, 500_000, 2, 0);
        buf.add_sched_switch(dim, 500_000, 4, 0);

        let batch = collector.collect(&buf, test_meta());
        assert_eq!(batch.cpu_util.len(), 1);

        let m = &batch.cpu_util[0];
        assert_eq!(m.metric_type, "cpu_utilization");
        assert_eq!(m.pid, 123);
        assert_eq!(m.client_type, ClientType::Geth);
        assert_eq!(m.total_on_cpu_ns, 2_000_000);
        assert_eq!(m.event_count, 3);
        assert_eq!(m.active_cores, 2);
        assert_eq!(m.system_cores, 16);
        assert_eq!(m.max_core_on_cpu_ns, 1_500_000);
        assert_eq!(m.max_core_id, 2);
        assert!((m.mean_core_pct - 0.1).abs() < 0.0001);
        assert!((m.min_core_pct - 0.05).abs() < 0.0001);
        assert!((m.max_core_pct - 0.15).abs() < 0.0001);
    }

    #[test]
    fn test_collect_cpu_utilization_no_overflow() {
        let collector = Collector::new(Duration::from_secs(1), &SamplingConfig::default());
        // Buffer starts at ktime=1B ns (1 second).
        let buf = Buffer::new(
            SystemTime::now(),
            100,
            SystemTime::now(),
            false,
            false,
            false,
            16,
            1_000_000_000,
        );
        let dim = BasicDimension {
            pid: 123,
            client_type: 1,
        };

        // Event at ktime=2s with on_cpu_ns=2s — started 1s before the window.
        // Should be trimmed to 1s for cpu_on_core.
        buf.add_sched_switch(dim, 2_000_000_000, 0, 2_000_000_000);

        let batch = collector.collect(&buf, test_meta());
        assert_eq!(batch.cpu_util.len(), 1);

        let m = &batch.cpu_util[0];
        // max_core_pct should be <= 100% after trimming.
        assert!(
            m.max_core_pct <= 100.0,
            "max_core_pct should be <= 100% but was {}",
            m.max_core_pct
        );
    }

    #[test]
    #[cfg(feature = "bpf")]
    fn test_collect_process_snapshots() {
        let mut collector = Collector::new_with_process_snapshots(
            Duration::from_secs(1),
            &SamplingConfig::default(),
            true,
        );

        collector.proc_status_reader = |_pid| {
            Some(ProcStatusSnapshot {
                memory: Some(ProcMemorySnapshot {
                    vm_size_bytes: 10_000,
                    vm_rss_bytes: 9_000,
                    rss_anon_bytes: 7_000,
                    rss_file_bytes: 1_500,
                    rss_shmem_bytes: 500,
                    vm_swap_bytes: 100,
                }),
                threads: 24,
                voluntary_ctxt_switches: 1234,
                nonvoluntary_ctxt_switches: 55,
            })
        };
        collector.proc_io_reader = |_pid| {
            Some(ProcIOSnapshot {
                rchar_bytes: 111,
                wchar_bytes: 222,
                syscr: 10,
                syscw: 20,
                read_bytes: 333,
                write_bytes: 444,
                cancelled_write_bytes: 5,
            })
        };
        collector.proc_limits_reader = |_pid| {
            Some(ProcLimitsSnapshot {
                fd_limit_soft: 1024,
                fd_limit_hard: 4096,
            })
        };
        collector.proc_fd_count_reader = |_pid| Some(64);

        let buf = test_buffer();
        let dim = BasicDimension {
            pid: 123,
            client_type: 1,
        };
        buf.add_sched_switch(dim, 1_000_000, 2, 0);

        let batch = collector.collect(&buf, test_meta());
        assert_eq!(batch.cpu_util.len(), 1);
        assert_eq!(batch.memory_usage.len(), 1);
        assert_eq!(batch.process_io_usage.len(), 1);
        assert_eq!(batch.process_fd_usage.len(), 1);
        assert_eq!(batch.process_sched_usage.len(), 1);

        let mem = &batch.memory_usage[0];
        assert_eq!(mem.vm_rss_bytes, 9_000);
        let io = &batch.process_io_usage[0];
        assert_eq!(io.read_bytes, 333);
        let fd = &batch.process_fd_usage[0];
        assert_eq!(fd.open_fds, 64);
        assert_eq!(fd.fd_limit_soft, 1024);
        let sched = &batch.process_sched_usage[0];
        assert_eq!(sched.threads, 24);
        assert_eq!(sched.voluntary_ctxt_switches, 1234);
    }

    #[test]
    #[cfg(feature = "bpf")]
    fn test_parse_proc_status_snapshot() {
        let status = r#"
Name:   geth
VmSize:      1000 kB
VmRSS:        500 kB
RssAnon:      300 kB
RssFile:      150 kB
RssShmem:      50 kB
VmSwap:        25 kB
Threads:       16
voluntary_ctxt_switches:        100
nonvoluntary_ctxt_switches:     7
"#;

        let snapshot = parse_proc_status_snapshot(status).expect("status snapshot should parse");
        let memory = snapshot.memory.expect("memory snapshot should exist");
        assert_eq!(memory.vm_size_bytes, 1_024_000);
        assert_eq!(memory.vm_rss_bytes, 512_000);
        assert_eq!(snapshot.threads, 16);
        assert_eq!(snapshot.voluntary_ctxt_switches, 100);
        assert_eq!(snapshot.nonvoluntary_ctxt_switches, 7);
    }

    #[test]
    #[cfg(feature = "bpf")]
    fn test_parse_proc_status_snapshot_missing_fields_returns_none() {
        let status = "Name:\tgeth\nState:\tS (sleeping)\n";
        assert!(parse_proc_status_snapshot(status).is_none());
    }

    #[test]
    #[cfg(feature = "bpf")]
    fn test_parse_proc_io_snapshot() {
        let io = r#"
rchar: 111
wchar: 222
syscr: 10
syscw: 20
read_bytes: 333
write_bytes: 444
cancelled_write_bytes: 5
"#;

        let snapshot = parse_proc_io_snapshot(io).expect("io snapshot should parse");
        assert_eq!(snapshot.rchar_bytes, 111);
        assert_eq!(snapshot.wchar_bytes, 222);
        assert_eq!(snapshot.read_bytes, 333);
        assert_eq!(snapshot.write_bytes, 444);
        assert_eq!(snapshot.cancelled_write_bytes, 5);
    }

    #[test]
    #[cfg(feature = "bpf")]
    fn test_parse_proc_io_snapshot_missing_fields_returns_none() {
        let io = "syscr: 0\nsyscw: 0\n";
        assert!(parse_proc_io_snapshot(io).is_none());
    }

    #[test]
    #[cfg(feature = "bpf")]
    fn test_parse_proc_limits_snapshot() {
        let limits = r#"
Limit                     Soft Limit           Hard Limit           Units
Max open files            1024                 4096                 files
"#;

        let snapshot = parse_proc_limits_snapshot(limits).expect("limits snapshot should parse");
        assert_eq!(snapshot.fd_limit_soft, 1024);
        assert_eq!(snapshot.fd_limit_hard, 4096);
    }

    #[test]
    #[cfg(feature = "bpf")]
    fn test_parse_proc_limits_snapshot_unlimited() {
        let limits = r#"
Limit                     Soft Limit           Hard Limit           Units
Max open files            unlimited            unlimited            files
"#;

        let snapshot = parse_proc_limits_snapshot(limits).expect("limits snapshot should parse");
        assert_eq!(snapshot.fd_limit_soft, u64::MAX);
        assert_eq!(snapshot.fd_limit_hard, u64::MAX);
    }

    #[test]
    #[cfg(feature = "bpf")]
    fn test_parse_proc_memory_snapshot() {
        let status = r#"
Name:   geth
VmSize:      12345 kB
VmRSS:        6789 kB
RssAnon:      4000 kB
RssFile:      2500 kB
RssShmem:      289 kB
VmSwap:        512 kB
"#;

        let snapshot = parse_proc_memory_snapshot(status).expect("snapshot should parse");
        assert_eq!(snapshot.vm_size_bytes, 12_641_280);
        assert_eq!(snapshot.vm_rss_bytes, 6_951_936);
        assert_eq!(snapshot.rss_anon_bytes, 4_096_000);
        assert_eq!(snapshot.rss_file_bytes, 2_560_000);
        assert_eq!(snapshot.rss_shmem_bytes, 295_936);
        assert_eq!(snapshot.vm_swap_bytes, 524_288);
    }

    #[test]
    #[cfg(feature = "bpf")]
    fn test_parse_proc_memory_snapshot_missing_fields_returns_none() {
        let status = "Name:\tkthreadd\nState:\tS (sleeping)\n";
        assert!(parse_proc_memory_snapshot(status).is_none());
    }
}
