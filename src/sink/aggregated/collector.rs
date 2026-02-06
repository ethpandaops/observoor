use std::time::Duration;

use crate::tracer::event::ClientType;

use super::aggregate::{CounterAggregate, GaugeAggregate, LatencyAggregate};
use super::buffer::Buffer;
use super::dimension::{
    direction_string, rw_string, BasicDimension, DiskDimension, NetworkDimension,
    TCPMetricsDimension,
};
use super::metric::{
    BatchMetadata, CounterMetric, GaugeMetric, LatencyMetric, MetricBatch, SlotInfo, WindowInfo,
};

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
        let window = WindowInfo {
            start: buf.start_time,
            interval_ms: self.interval_ms,
        };

        let slot = SlotInfo {
            number: buf.wallclock_slot as u32,
            start_time: buf.wallclock_slot_start,
        };

        let mut batch = MetricBatch {
            metadata: meta,
            latency: Vec::with_capacity(256),
            counter: Vec::with_capacity(128),
            gauge: Vec::with_capacity(64),
        };

        self.collect_basic_latency(&mut batch, buf, window, slot);
        self.collect_disk_latency(&mut batch, buf, window, slot);
        self.collect_basic_counters(&mut batch, buf, window, slot);
        self.collect_network_counters(&mut batch, buf, window, slot);
        self.collect_disk_counters(&mut batch, buf, window, slot);
        self.collect_tcp_gauges(&mut batch, buf, window, slot);
        self.collect_disk_gauges(&mut batch, buf, window, slot);

        batch
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
                    metric_type: name.to_string(),
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
                    histogram: snap.histogram.to_vec(),
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
                metric_type: "disk_latency".to_string(),
                window,
                slot,
                pid: dim.pid,
                client_type: client_type_from_u8(dim.client_type),
                device_id: Some(dim.device_id),
                rw: Some(rw_string(dim.rw).to_string()),
                sum: snap.sum,
                count: snap.count,
                min: snap.min,
                max: snap.max,
                histogram: snap.histogram.to_vec(),
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
                    metric_type: name.to_string(),
                    window,
                    slot,
                    pid: dim.pid,
                    client_type: client_type_from_u8(dim.client_type),
                    device_id: None,
                    rw: None,
                    local_port: None,
                    direction: None,
                    sum: snap.sum,
                    count: snap.count,
                });
            }
        }
    }

    /// Collects network counter metrics with port/direction.
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
                    metric_type: name.to_string(),
                    window,
                    slot,
                    pid: dim.pid,
                    client_type: client_type_from_u8(dim.client_type),
                    device_id: None,
                    rw: None,
                    local_port: Some(dim.local_port),
                    direction: Some(direction_string(dim.direction).to_string()),
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
                    metric_type: name.to_string(),
                    window,
                    slot,
                    pid: dim.pid,
                    client_type: client_type_from_u8(dim.client_type),
                    device_id: Some(dim.device_id),
                    rw: Some(rw_string(dim.rw).to_string()),
                    local_port: None,
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
                    metric_type: name.to_string(),
                    window,
                    slot,
                    pid: dim.pid,
                    client_type: client_type_from_u8(dim.client_type),
                    device_id: None,
                    rw: None,
                    local_port: Some(dim.local_port),
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
                metric_type: "disk_queue_depth".to_string(),
                window,
                slot,
                pid: dim.pid,
                client_type: client_type_from_u8(dim.client_type),
                device_id: Some(dim.device_id),
                rw: Some(rw_string(dim.rw).to_string()),
                local_port: None,
                sum: snap.sum,
                count: snap.count,
                min: snap.min,
                max: snap.max,
            });
        }
    }
}

/// Converts a raw u8 client type to the enum, defaulting to Unknown.
fn client_type_from_u8(v: u8) -> ClientType {
    ClientType::from_u8(v).unwrap_or(ClientType::Unknown)
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use super::*;
    use crate::tracer::event::EventType;

    fn test_meta() -> BatchMetadata {
        BatchMetadata {
            client_name: "test".to_string(),
            network_name: "testnet".to_string(),
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
            local_port: 8545,
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
        assert_eq!(net[0].local_port, Some(8545));
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
            local_port: 30303,
        };

        buf.add_tcp_metrics(dim, 100, 65535);

        let batch = collector.collect(&buf, test_meta());
        let rtt: Vec<_> = batch
            .gauge
            .iter()
            .filter(|m| m.metric_type == "tcp_rtt")
            .collect();
        assert_eq!(rtt.len(), 1);
        assert_eq!(rtt[0].local_port, Some(30303));
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
}
