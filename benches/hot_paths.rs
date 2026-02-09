use std::time::{Duration, SystemTime};

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use observoor::sink::aggregated::buffer::Buffer;
use observoor::sink::aggregated::collector::Collector;
use observoor::sink::aggregated::dimension::{
    BasicDimension, DiskDimension, NetworkDimension, TCPMetricsDimension,
};
use observoor::sink::aggregated::metric::BatchMetadata;
use observoor::tracer::event::EventType;
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

fn syscall_payload() -> Vec<u8> {
    let mut data = header(123_456_789, 1337, 1337, EventType::SyscallFutex as u8, 1);
    data.extend_from_slice(&2_500u64.to_le_bytes());
    data.extend_from_slice(&0i64.to_le_bytes());
    data.extend_from_slice(&202u32.to_le_bytes());
    data.extend_from_slice(&12i32.to_le_bytes());
    data
}

fn fd_payload() -> Vec<u8> {
    let mut data = header(123_456_789, 1337, 1337, EventType::FDOpen as u8, 1);
    data.extend_from_slice(&12i32.to_le_bytes());
    data.extend_from_slice(&[0u8; 4]);
    let mut filename = [0u8; 64];
    let raw = b"/var/lib/nethermind/current/logs/trace.log";
    filename[..raw.len()].copy_from_slice(raw);
    data.extend_from_slice(&filename);
    data
}

fn build_collector_input() -> (Collector, Buffer, BatchMetadata) {
    let now = SystemTime::now();
    let collector = Collector::new(Duration::from_millis(200));
    let buffer = Buffer::new(now, 42, now, false, false, false);

    for i in 0..128u32 {
        let pid = 4_000 + i;
        let basic = BasicDimension {
            pid,
            client_type: 1,
        };
        let net = NetworkDimension {
            pid,
            client_type: 1,
            local_port: 30303,
            direction: (i % 2) as u8,
        };
        let tcp = TCPMetricsDimension {
            pid,
            client_type: 1,
            local_port: 30303,
        };
        let disk = DiskDimension {
            pid,
            client_type: 1,
            device_id: 259,
            rw: (i % 2) as u8,
        };

        buffer.add_syscall(EventType::SyscallRead, basic, 1_200);
        buffer.add_syscall(EventType::SyscallFutex, basic, 450);
        buffer.add_sched_switch(basic, 2_000);
        buffer.add_sched_runqueue(basic, 500, 1_000);
        buffer.add_page_fault(basic, i % 7 == 0);
        buffer.add_fd_open(basic);
        buffer.add_fd_close(basic);
        buffer.add_process_exit(basic);

        buffer.add_net_io(net, 1_500);
        buffer.add_tcp_retransmit(net, 128);
        buffer.add_tcp_metrics(tcp, 120, 64_000);

        buffer.add_disk_io(disk, 35_000, 4_096, 8);
        buffer.add_block_merge(disk, 8_192);
    }

    let meta = BatchMetadata {
        client_name: "bench-node".into(),
        network_name: "hoodi".into(),
        updated_time: now,
    };

    (collector, buffer, meta)
}

fn bench_parse_event(c: &mut Criterion) {
    let syscall = syscall_payload();
    let fd = fd_payload();

    c.bench_function("parse_event/syscall_futex", |b| {
        b.iter(|| parse_event(black_box(&syscall)).expect("parse syscall"))
    });

    c.bench_function("parse_event/fd_open", |b| {
        b.iter(|| parse_event(black_box(&fd)).expect("parse fd"))
    });
}

fn bench_collect(c: &mut Criterion) {
    let (collector, buffer, meta) = build_collector_input();

    c.bench_function("collector/collect_medium_window", |b| {
        b.iter(|| {
            let batch = collector.collect(black_box(&buffer), black_box(meta.clone()));
            black_box(batch.len())
        })
    });
}

fn bench_suite(c: &mut Criterion) {
    bench_parse_event(c);
    bench_collect(c);
}

criterion_group!(benches, bench_suite);
criterion_main!(benches);
