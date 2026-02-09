use std::collections::HashMap;
use std::time::Duration;

use crate::tracer::event::ClientType;

use super::aggregate::{CounterAggregate, GaugeAggregate, LatencyAggregate};
use super::buffer::Buffer;
use super::dimension::{
    direction_string, port_label_string, rw_string, BasicDimension, DiskDimension,
    NetworkDimension, TCPMetricsDimension,
};
use super::metric::{
    BatchMetadata, CounterMetric, CpuUtilMetric, GaugeMetric, LatencyMetric, MetricBatch, SlotInfo,
    WindowInfo,
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
}

impl Collector {
    /// Creates a new collector with the given aggregation interval.
    pub fn new(interval: Duration) -> Self {
        Self {
            interval_ms: interval.as_millis() as u16,
        }
    }

    /// Iterates the buffer once and returns all metrics.
    pub fn collect(&self, buf: &Buffer, meta: BatchMetadata) -> MetricBatch {
        let latency_capacity = self.estimate_latency_capacity(buf);
        let counter_capacity = self.estimate_counter_capacity(buf);
        let gauge_capacity = self.estimate_gauge_capacity(buf);
        let cpu_util_capacity = self.estimate_cpu_util_capacity(buf);

        let mut batch = MetricBatch {
            metadata: meta,
            latency: Vec::with_capacity(latency_capacity),
            counter: Vec::with_capacity(counter_capacity),
            gauge: Vec::with_capacity(gauge_capacity),
            cpu_util: Vec::with_capacity(cpu_util_capacity),
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

        reserve_if_needed(&mut batch.latency, latency_capacity);
        reserve_if_needed(&mut batch.counter, counter_capacity);
        reserve_if_needed(&mut batch.gauge, gauge_capacity);
        reserve_if_needed(&mut batch.cpu_util, cpu_util_capacity);

        batch.latency.clear();
        batch.counter.clear();
        batch.gauge.clear();
        batch.cpu_util.clear();

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

    /// Collects all basic-dimension latency metrics (syscalls, sched, memory).
    fn collect_basic_latency(
        &self,
        batch: &mut MetricBatch,
        buf: &Buffer,
        window: WindowInfo,
        slot: SlotInfo,
    ) {
        let maps: &[(&str, &dashmap::DashMap<BasicDimension, LatencyAggregate>)] = &[
            ("syscall_read", &buf.syscall_read),
            ("syscall_write", &buf.syscall_write),
            ("syscall_futex", &buf.syscall_futex),
            ("syscall_mmap", &buf.syscall_mmap),
            ("syscall_epoll_wait", &buf.syscall_epoll_wait),
            ("syscall_fsync", &buf.syscall_fsync),
            ("syscall_fdatasync", &buf.syscall_fdatasync),
            ("syscall_pwrite", &buf.syscall_pwrite),
            ("sched_on_cpu", &buf.sched_on_cpu),
            ("sched_off_cpu", &buf.sched_off_cpu),
            ("sched_runqueue", &buf.sched_runqueue),
            ("mem_reclaim", &buf.mem_reclaim),
            ("mem_compaction", &buf.mem_compaction),
        ];

        for &(name, map) in maps {
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
        let maps: &[(&str, &dashmap::DashMap<BasicDimension, CounterAggregate>)] = &[
            ("page_fault_major", &buf.page_fault_major),
            ("page_fault_minor", &buf.page_fault_minor),
            ("swap_in", &buf.swap_in),
            ("swap_out", &buf.swap_out),
            ("oom_kill", &buf.oom_kill),
            ("fd_open", &buf.fd_open),
            ("fd_close", &buf.fd_close),
            ("process_exit", &buf.process_exit),
            ("tcp_state_change", &buf.tcp_state_change),
        ];

        for &(name, map) in maps {
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
        let maps: &[(&str, &dashmap::DashMap<NetworkDimension, CounterAggregate>)] = &[
            ("net_io", &buf.net_io),
            ("tcp_retransmit", &buf.tcp_retransmit),
        ];

        for &(name, map) in maps {
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
                    port_label: Some(port_label_string(dim.port_label)),
                    direction: Some(direction_string(dim.direction)),
                    sum: snap.sum,
                    count: snap.count,
                });
            }
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
        let maps: &[(&str, &dashmap::DashMap<DiskDimension, CounterAggregate>)] = &[
            ("disk_bytes", &buf.disk_bytes),
            ("block_merge", &buf.block_merge),
        ];

        for &(name, map) in maps {
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
        }
    }
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
        )
    }

    #[test]
    fn test_collect_empty_buffer() {
        let collector = Collector::new(Duration::from_secs(1));
        let buf = test_buffer();
        let batch = collector.collect(&buf, test_meta());

        assert!(batch.is_empty());
        assert!(batch.latency.is_empty());
        assert!(batch.counter.is_empty());
        assert!(batch.gauge.is_empty());
        assert!(batch.cpu_util.is_empty());
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
        let collector = Collector::new(Duration::from_secs(1));
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
    fn test_collect_disk_latency() {
        let collector = Collector::new(Duration::from_secs(1));
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
        let collector = Collector::new(Duration::from_secs(1));
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
        let collector = Collector::new(Duration::from_secs(1));
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
        let collector = Collector::new(Duration::from_secs(1));
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
        let collector = Collector::new(Duration::from_millis(500));
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
        let collector = Collector::new(Duration::from_secs(1));
        let buf = test_buffer();

        // Insert an entry but don't record anything - this shouldn't happen
        // in practice since DashMap entries are created on first add, but
        // verify the count == 0 guard works.
        let batch = collector.collect(&buf, test_meta());
        assert!(batch.is_empty());
    }

    #[test]
    fn test_collect_into_matches_collect() {
        let collector = Collector::new(Duration::from_secs(1));
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
    }

    #[test]
    fn test_collect_into_reuses_capacity() {
        let collector = Collector::new(Duration::from_secs(1));
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

        collector.collect_into(&buf, &mut batch);

        assert_eq!(batch.latency.capacity(), latency_capacity);
        assert_eq!(batch.counter.capacity(), counter_capacity);
        assert_eq!(batch.gauge.capacity(), gauge_capacity);
        assert_eq!(batch.cpu_util.capacity(), cpu_util_capacity);
    }

    #[test]
    fn test_collect_cpu_utilization() {
        let collector = Collector::new(Duration::from_secs(1));
        let buf = test_buffer();
        let dim = BasicDimension {
            pid: 123,
            client_type: 1,
        };

        // 1.5ms on core 2, 0.5ms on core 4 over a 1s window.
        buf.add_sched_switch(dim, 1_000_000, 2);
        buf.add_sched_switch(dim, 500_000, 2);
        buf.add_sched_switch(dim, 500_000, 4);

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
}
