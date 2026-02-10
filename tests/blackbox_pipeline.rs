use std::time::{Duration, SystemTime};

use observoor::config::SamplingConfig;
use observoor::sink::aggregated::buffer::Buffer;
use observoor::sink::aggregated::collector::Collector;
use observoor::sink::aggregated::dimension::{
    BasicDimension, DiskDimension, NetworkDimension, TCPMetricsDimension,
};
use observoor::sink::aggregated::metric::{BatchMetadata, MetricBatch};
use observoor::tracer::event::{Direction, EventType, ParsedEvent, TypedEvent};
use observoor::tracer::parse::parse_event;

const HEADER_SIZE: usize = 24;

fn header(ts: u64, pid: u32, tid: u32, event_type: u8, client_type: u8) -> Vec<u8> {
    let mut buf = Vec::with_capacity(HEADER_SIZE);
    buf.extend_from_slice(&ts.to_le_bytes());
    buf.extend_from_slice(&pid.to_le_bytes());
    buf.extend_from_slice(&tid.to_le_bytes());
    buf.push(event_type);
    buf.push(client_type);
    buf.extend_from_slice(&[0u8; 6]);
    buf
}

fn syscall_payload(event_type: EventType, pid: u32, tid: u32, latency_ns: u64) -> Vec<u8> {
    let mut data = header(123_456_789, pid, tid, event_type as u8, 1);
    data.extend_from_slice(&latency_ns.to_le_bytes());
    data.extend_from_slice(&0i64.to_le_bytes());
    data.extend_from_slice(&202u32.to_le_bytes());
    data.extend_from_slice(&12i32.to_le_bytes());
    data
}

fn sched_switch_payload(pid: u32, tid: u32, on_cpu_ns: u64, voluntary: bool) -> Vec<u8> {
    let mut data = header(123_456_789, pid, tid, EventType::SchedSwitch as u8, 1);
    data.extend_from_slice(&on_cpu_ns.to_le_bytes());
    data.push(u8::from(voluntary));
    data.extend_from_slice(&[0u8; 7]);
    data
}

fn sched_runqueue_payload(pid: u32, tid: u32, runqueue_ns: u64, off_cpu_ns: u64) -> Vec<u8> {
    let mut data = header(123_456_789, pid, tid, EventType::SchedRunqueue as u8, 1);
    data.extend_from_slice(&runqueue_ns.to_le_bytes());
    data.extend_from_slice(&off_cpu_ns.to_le_bytes());
    data
}

fn disk_payload(
    pid: u32,
    tid: u32,
    latency_ns: u64,
    bytes: u32,
    rw: u8,
    queue_depth: u32,
    device_id: u32,
) -> Vec<u8> {
    let mut data = header(123_456_789, pid, tid, EventType::DiskIO as u8, 1);
    data.extend_from_slice(&latency_ns.to_le_bytes());
    data.extend_from_slice(&bytes.to_le_bytes());
    data.push(rw);
    data.extend_from_slice(&[0u8; 3]);
    data.extend_from_slice(&queue_depth.to_le_bytes());
    data.extend_from_slice(&device_id.to_le_bytes());
    data
}

fn block_merge_payload(pid: u32, tid: u32, bytes: u32, rw: u8) -> Vec<u8> {
    let mut data = header(123_456_789, pid, tid, EventType::BlockMerge as u8, 1);
    data.extend_from_slice(&bytes.to_le_bytes());
    data.push(rw);
    data.extend_from_slice(&[0u8; 3]);
    data
}

fn net_payload(
    event_type: EventType,
    pid: u32,
    tid: u32,
    bytes: u32,
    src_port: u16,
    dst_port: u16,
    direction: Direction,
    has_metrics: bool,
    srtt_us: u32,
    cwnd: u32,
) -> Vec<u8> {
    let mut data = header(123_456_789, pid, tid, event_type as u8, 1);
    data.extend_from_slice(&bytes.to_le_bytes());
    data.extend_from_slice(&src_port.to_le_bytes());
    data.extend_from_slice(&dst_port.to_le_bytes());
    data.push(direction as u8);
    data.push(u8::from(has_metrics));
    data.extend_from_slice(&[0u8; 2]);
    data.extend_from_slice(&srtt_us.to_le_bytes());
    data.extend_from_slice(&cwnd.to_le_bytes());
    data
}

fn tcp_retransmit_payload(pid: u32, tid: u32, bytes: u32, src_port: u16, dst_port: u16) -> Vec<u8> {
    let mut data = header(123_456_789, pid, tid, EventType::TcpRetransmit as u8, 1);
    data.extend_from_slice(&bytes.to_le_bytes());
    data.extend_from_slice(&src_port.to_le_bytes());
    data.extend_from_slice(&dst_port.to_le_bytes());
    data.extend_from_slice(&[0u8; 8]);
    data
}

fn tcp_state_payload(
    pid: u32,
    tid: u32,
    src_port: u16,
    dst_port: u16,
    new_state: u8,
    old_state: u8,
) -> Vec<u8> {
    let mut data = header(123_456_789, pid, tid, EventType::TcpState as u8, 1);
    data.extend_from_slice(&src_port.to_le_bytes());
    data.extend_from_slice(&dst_port.to_le_bytes());
    data.push(new_state);
    data.push(old_state);
    data.extend_from_slice(&[0u8; 10]);
    data
}

fn page_fault_payload(pid: u32, tid: u32, major: bool) -> Vec<u8> {
    let mut data = header(123_456_789, pid, tid, EventType::PageFault as u8, 1);
    data.extend_from_slice(&0xdeadbeefu64.to_le_bytes());
    data.push(u8::from(major));
    data.extend_from_slice(&[0u8; 7]);
    data
}

fn fd_payload(event_type: EventType, pid: u32, tid: u32) -> Vec<u8> {
    let mut data = header(123_456_789, pid, tid, event_type as u8, 1);
    data.extend_from_slice(&12i32.to_le_bytes());
    data.extend_from_slice(&[0u8; 4]);
    let mut filename = [0u8; 64];
    let raw = b"/var/lib/nethermind/current/logs/trace.log";
    filename[..raw.len()].copy_from_slice(raw);
    data.extend_from_slice(&filename);
    data
}

fn mem_latency_payload(event_type: EventType, pid: u32, tid: u32, duration_ns: u64) -> Vec<u8> {
    let mut data = header(123_456_789, pid, tid, event_type as u8, 1);
    data.extend_from_slice(&duration_ns.to_le_bytes());
    data
}

fn swap_payload(event_type: EventType, pid: u32, tid: u32, pages: u64) -> Vec<u8> {
    let mut data = header(123_456_789, pid, tid, event_type as u8, 1);
    data.extend_from_slice(&pages.to_le_bytes());
    data
}

fn oom_kill_payload(pid: u32, tid: u32, target_pid: u32) -> Vec<u8> {
    let mut data = header(123_456_789, pid, tid, EventType::OOMKill as u8, 1);
    data.extend_from_slice(&target_pid.to_le_bytes());
    data.extend_from_slice(&[0u8; 4]);
    data
}

fn process_exit_payload(pid: u32, tid: u32, exit_code: u32) -> Vec<u8> {
    let mut data = header(123_456_789, pid, tid, EventType::ProcessExit as u8, 1);
    data.extend_from_slice(&exit_code.to_le_bytes());
    data.extend_from_slice(&[0u8; 4]);
    data
}

fn process_parsed_event(buf: &Buffer, event: &ParsedEvent) {
    let basic_dim = BasicDimension {
        pid: event.raw.pid,
        client_type: event.raw.client_type as u8,
    };

    match &event.typed {
        TypedEvent::Syscall(e) => {
            buf.add_syscall(event.raw.event_type, basic_dim, e.latency_ns);
        }
        TypedEvent::DiskIO(e) => {
            let disk = DiskDimension {
                pid: event.raw.pid,
                client_type: event.raw.client_type as u8,
                device_id: e.device_id,
                rw: e.rw,
            };
            buf.add_disk_io(disk, e.latency_ns, e.bytes, e.queue_depth);
        }
        TypedEvent::NetIO(e) => {
            // In production, port_label is resolved via config's port_label_map.
            // Here we use 0 (Unknown) since we don't have a port map.
            let net = NetworkDimension {
                pid: event.raw.pid,
                client_type: event.raw.client_type as u8,
                port_label: 0,
                direction: e.direction as u8,
            };
            buf.add_net_io(net, i64::from(e.bytes));
            if e.has_metrics {
                let tcp = TCPMetricsDimension {
                    pid: event.raw.pid,
                    client_type: event.raw.client_type as u8,
                    port_label: 0,
                };
                buf.add_tcp_metrics(tcp, e.srtt_us, e.cwnd);
            }
        }
        TypedEvent::TcpRetransmit(e) => {
            let net = NetworkDimension {
                pid: event.raw.pid,
                client_type: event.raw.client_type as u8,
                port_label: 0,
                direction: Direction::TX as u8,
            };
            buf.add_tcp_retransmit(net, i64::from(e.bytes));
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
        TypedEvent::BlockMerge(e) => {
            let disk = DiskDimension {
                pid: event.raw.pid,
                client_type: event.raw.client_type as u8,
                device_id: 0,
                rw: e.rw,
            };
            buf.add_block_merge(disk, e.bytes);
        }
        TypedEvent::TcpState(_) => {
            buf.add_tcp_state_change(basic_dim);
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

fn latency_totals(batch: &MetricBatch, metric_type: &str) -> (u32, i64) {
    batch
        .latency
        .iter()
        .filter(|m| m.metric_type == metric_type)
        .fold((0u32, 0i64), |acc, m| (acc.0 + m.count, acc.1 + m.sum))
}

fn counter_totals(batch: &MetricBatch, metric_type: &str) -> (u32, i64) {
    batch
        .counter
        .iter()
        .filter(|m| m.metric_type == metric_type)
        .fold((0u32, 0i64), |acc, m| (acc.0 + m.count, acc.1 + m.sum))
}

fn gauge_totals(batch: &MetricBatch, metric_type: &str) -> (u32, i64) {
    batch
        .gauge
        .iter()
        .filter(|m| m.metric_type == metric_type)
        .fold((0u32, 0i64), |acc, m| (acc.0 + m.count, acc.1 + m.sum))
}

#[test]
fn pipeline_blackbox_correctness_and_invariants() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let collector = Collector::new(Duration::from_millis(200), &SamplingConfig::default());
    let buffer = Buffer::new(now, 42, now, false, false, false, 16);

    let p1 = 2_001;
    let p2 = 2_002;
    let mut payloads = vec![
        syscall_payload(EventType::SyscallRead, p1, p1, 100),
        syscall_payload(EventType::SyscallRead, p1, p1, 200),
        syscall_payload(EventType::SyscallRead, p1, p1, 300),
        syscall_payload(EventType::SyscallWrite, p2, p2, 400),
        syscall_payload(EventType::SyscallWrite, p2, p2, 100),
        sched_switch_payload(p1, p1, 5_000, true),
        sched_runqueue_payload(p1, p1, 1_000, 2_000),
        disk_payload(p1, p1, 40_000, 4_096, 1, 4, 259),
        disk_payload(p1, p1, 20_000, 8_192, 1, 8, 259),
        block_merge_payload(p1, p1, 4_096, 1),
        net_payload(
            EventType::NetTX,
            p1,
            p1,
            1_000,
            30_303,
            9_000,
            Direction::TX,
            true,
            120,
            100_000,
        ),
        net_payload(
            EventType::NetRX,
            p1,
            p1,
            2_000,
            9_000,
            30_303,
            Direction::RX,
            false,
            0,
            0,
        ),
        tcp_retransmit_payload(p1, p1, 128, 30_303, 9_000),
        page_fault_payload(p1, p1, true),
        page_fault_payload(p1, p1, false),
        page_fault_payload(p1, p1, false),
        fd_payload(EventType::FDOpen, p1, p1),
        fd_payload(EventType::FDOpen, p1, p1),
        fd_payload(EventType::FDClose, p1, p1),
        mem_latency_payload(EventType::MemReclaim, p2, p2, 700),
        mem_latency_payload(EventType::MemReclaim, p2, p2, 900),
        mem_latency_payload(EventType::MemCompaction, p2, p2, 300),
        swap_payload(EventType::SwapIn, p2, p2, 9),
        swap_payload(EventType::SwapOut, p2, p2, 2),
        tcp_state_payload(p2, p2, 30_303, 9_000, 4, 3),
        oom_kill_payload(p2, p2, 9_999),
        process_exit_payload(p2, p2, 0),
    ];

    for payload in payloads.drain(..) {
        let parsed = parse_event(&payload).expect("parse payload");
        process_parsed_event(&buffer, &parsed);
    }

    let batch = collector.collect(
        &buffer,
        BatchMetadata {
            client_name: "blackbox-node".into(),
            network_name: "hoodi".into(),
            updated_time: now,
        },
    );

    assert_eq!(batch.latency.len(), 8);
    assert_eq!(batch.counter.len(), 14);
    assert_eq!(batch.gauge.len(), 3);
    assert_eq!(batch.cpu_util.len(), 1);
    assert_eq!(batch.len(), 26);

    for metric in &batch.latency {
        assert!(metric.count > 0, "latency count must be positive");
        assert!(metric.min <= metric.max, "latency min/max must be ordered");
        let histogram_total: u32 = metric.histogram.iter().copied().sum();
        assert_eq!(
            histogram_total, metric.count,
            "histogram count mismatch for {}",
            metric.metric_type
        );
    }

    for metric in &batch.counter {
        assert!(metric.count > 0, "counter count must be positive");
    }

    for metric in &batch.gauge {
        assert!(metric.count > 0, "gauge count must be positive");
        assert!(metric.min <= metric.max, "gauge min/max must be ordered");
    }

    assert_eq!(latency_totals(&batch, "syscall_read"), (3, 600));
    assert_eq!(latency_totals(&batch, "syscall_write"), (2, 500));
    assert_eq!(latency_totals(&batch, "sched_on_cpu"), (1, 5_000));
    assert_eq!(latency_totals(&batch, "sched_runqueue"), (1, 1_000));
    assert_eq!(latency_totals(&batch, "sched_off_cpu"), (1, 2_000));
    assert_eq!(latency_totals(&batch, "disk_latency"), (2, 60_000));
    assert_eq!(latency_totals(&batch, "mem_reclaim"), (2, 1_600));
    assert_eq!(latency_totals(&batch, "mem_compaction"), (1, 300));

    assert_eq!(counter_totals(&batch, "net_io"), (2, 3_000));
    assert_eq!(counter_totals(&batch, "tcp_retransmit"), (1, 128));
    assert_eq!(counter_totals(&batch, "disk_bytes"), (2, 12_288));
    assert_eq!(counter_totals(&batch, "block_merge"), (1, 4_096));
    assert_eq!(counter_totals(&batch, "page_fault_major"), (1, 0));
    assert_eq!(counter_totals(&batch, "page_fault_minor"), (2, 0));
    assert_eq!(counter_totals(&batch, "fd_open"), (2, 0));
    assert_eq!(counter_totals(&batch, "fd_close"), (1, 0));
    assert_eq!(counter_totals(&batch, "swap_in"), (1, 9));
    assert_eq!(counter_totals(&batch, "swap_out"), (1, 2));
    assert_eq!(counter_totals(&batch, "tcp_state_change"), (1, 0));
    assert_eq!(counter_totals(&batch, "oom_kill"), (1, 0));
    assert_eq!(counter_totals(&batch, "process_exit"), (1, 0));

    assert_eq!(gauge_totals(&batch, "tcp_rtt"), (1, 120));
    assert_eq!(gauge_totals(&batch, "tcp_cwnd"), (1, 100_000));
    assert_eq!(gauge_totals(&batch, "disk_queue_depth"), (2, 12));
}
