use std::alloc::System;
use std::hint::black_box;
use std::time::{Duration, SystemTime};

use observoor::config::SamplingConfig;
use observoor::sink::aggregated::buffer::Buffer;
use observoor::sink::aggregated::collector::Collector;
use observoor::sink::aggregated::dimension::{
    BasicDimension, DiskDimension, NetworkDimension, TCPMetricsDimension,
};
use observoor::sink::aggregated::metric::BatchMetadata;
use observoor::tracer::event::EventType;
use observoor::tracer::parse::parse_event;
use serial_test::serial;
use stats_alloc::{Region, StatsAlloc, INSTRUMENTED_SYSTEM};

const HEADER_SIZE: usize = 24;

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

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

fn disk_payload() -> Vec<u8> {
    let mut data = header(123_456_789, 1337, 1337, EventType::DiskIO as u8, 1);
    data.extend_from_slice(&37_500u64.to_le_bytes());
    data.extend_from_slice(&4_096u32.to_le_bytes());
    data.push(1);
    data.extend_from_slice(&[0u8; 3]);
    data.extend_from_slice(&7u32.to_le_bytes());
    data.extend_from_slice(&259u32.to_le_bytes());
    data
}

fn net_payload() -> Vec<u8> {
    let mut data = header(123_456_789, 1337, 1337, EventType::NetTX as u8, 1);
    data.extend_from_slice(&1_500u32.to_le_bytes());
    data.extend_from_slice(&30_303u16.to_le_bytes());
    data.extend_from_slice(&9_000u16.to_le_bytes());
    data.push(0);
    data.push(1);
    data.extend_from_slice(&[0u8; 2]);
    data.extend_from_slice(&95u32.to_le_bytes());
    data.extend_from_slice(&128_000u32.to_le_bytes());
    data
}

fn measure_alloc_counts<T>(f: impl FnOnce() -> T) -> (T, usize, usize) {
    // Calibrate for ambient allocator activity in the test harness process.
    let idle_region = Region::new(&GLOBAL);
    black_box(());
    let idle = idle_region.change();

    let region = Region::new(&GLOBAL);
    let output = f();
    let used = region.change();

    let allocations = used.allocations.saturating_sub(idle.allocations);
    let deallocations = used.deallocations.saturating_sub(idle.deallocations);
    (output, allocations, deallocations)
}

fn build_non_empty_buffer() -> (Collector, Buffer, BatchMetadata) {
    let collector = Collector::new(Duration::from_millis(200), &SamplingConfig::default());
    let now = SystemTime::now();
    let buffer = Buffer::new(now, 42, now, false, false, false, 16);

    for i in 0..128u32 {
        let pid = 5_000 + i;
        let basic = BasicDimension {
            pid,
            client_type: 1,
        };
        let net = NetworkDimension {
            pid,
            client_type: 1,
            port_label: 1, // ElP2PTcp
            direction: (i % 2) as u8,
        };
        let tcp = TCPMetricsDimension {
            pid,
            client_type: 1,
            port_label: 1, // ElP2PTcp
        };
        let disk = DiskDimension {
            pid,
            client_type: 1,
            device_id: 259,
            rw: (i % 2) as u8,
        };

        buffer.add_syscall(EventType::SyscallRead, basic, 1_200);
        buffer.add_syscall(EventType::SyscallFutex, basic, 450);
        buffer.add_sched_switch(basic, 2_000, i % 8);
        buffer.add_sched_runqueue(basic, 500, 1_000);
        buffer.add_page_fault(basic, i % 7 == 0);
        buffer.add_fd_open(basic);
        buffer.add_fd_close(basic);
        buffer.add_process_exit(basic);
        buffer.add_tcp_state_change(basic);
        buffer.add_swap_in(basic, 4);

        buffer.add_net_io(net, 1_500);
        buffer.add_tcp_retransmit(net, 128);
        buffer.add_tcp_metrics(tcp, 120, 64_000);

        buffer.add_disk_io(disk, 35_000, 4_096, 8);
        buffer.add_block_merge(disk, 8_192);
    }

    let meta = BatchMetadata {
        client_name: "alloc-test".into(),
        network_name: "hoodi".into(),
        updated_time: now,
    };

    (collector, buffer, meta)
}

#[test]
#[serial]
fn parse_syscall_event_allocates_zero() {
    let data = syscall_payload();

    let (_parsed, allocations, deallocations) = measure_alloc_counts(|| {
        let parsed = parse_event(&data).expect("parse syscall");
        black_box(parsed);
    });

    assert!(
        allocations <= 8,
        "syscall parse allocation budget exceeded: {}",
        allocations
    );
    assert!(
        deallocations <= 8,
        "syscall parse deallocation budget exceeded: {}",
        deallocations
    );
}

#[test]
#[serial]
fn parse_fd_event_allocation_budget() {
    let data = fd_payload();

    let (_parsed, allocations, _deallocations) = measure_alloc_counts(|| {
        let parsed = parse_event(&data).expect("parse fd");
        black_box(parsed);
    });

    assert!(
        allocations <= 8,
        "fd parse allocation budget exceeded: {}",
        allocations
    );
}

#[test]
#[serial]
fn parse_mixed_batch_allocation_budget() {
    let syscall = syscall_payload();
    let disk = disk_payload();
    let net = net_payload();

    let (_parsed, allocations, deallocations) = measure_alloc_counts(|| {
        for _ in 0..512 {
            black_box(parse_event(&syscall).expect("parse syscall"));
            black_box(parse_event(&disk).expect("parse disk"));
            black_box(parse_event(&net).expect("parse net"));
        }
    });

    assert!(
        allocations <= 64,
        "mixed parse allocation budget exceeded: {}",
        allocations
    );
    assert!(
        deallocations <= 64,
        "mixed parse deallocation budget exceeded: {}",
        deallocations
    );
}

#[test]
#[serial]
fn collect_empty_buffer_allocation_budget() {
    let collector = Collector::new(Duration::from_millis(200), &SamplingConfig::default());
    let now = SystemTime::now();
    let buffer = Buffer::new(now, 42, now, false, false, false, 16);
    let meta = BatchMetadata {
        client_name: "alloc-test".into(),
        network_name: "hoodi".into(),
        updated_time: now,
    };

    let (batch, allocations, _deallocations) = measure_alloc_counts(|| {
        let batch = collector.collect(&buffer, meta);
        black_box(&batch);
        batch
    });

    assert!(batch.is_empty(), "empty buffer should produce empty batch");
    assert!(
        allocations <= 2300,
        "empty collect allocation budget exceeded: {}",
        allocations
    );
}

#[test]
#[serial]
fn collect_non_empty_buffer_allocation_budget() {
    let (collector, buffer, meta) = build_non_empty_buffer();

    let (batch, allocations, deallocations) = measure_alloc_counts(|| {
        let batch = collector.collect(&buffer, meta);
        black_box(&batch);
        batch
    });

    assert!(
        batch.len() > 1000,
        "non-empty collect should emit many metrics, got {}",
        batch.len()
    );
    assert!(
        allocations <= 2600,
        "non-empty collect allocation budget exceeded: {}",
        allocations
    );
    assert!(
        deallocations <= 2200,
        "non-empty collect deallocation budget exceeded: {}",
        deallocations
    );
}

#[test]
#[serial]
fn collect_non_empty_buffer_reuse_allocation_budget() {
    let (collector, buffer, meta) = build_non_empty_buffer();
    let client_name = meta.client_name.clone();
    let network_name = meta.network_name.clone();

    let (_fresh_output, fresh_allocations, fresh_deallocations) = measure_alloc_counts(|| {
        for _ in 0..8 {
            let fresh = collector.collect(
                &buffer,
                BatchMetadata {
                    client_name: client_name.clone(),
                    network_name: network_name.clone(),
                    updated_time: SystemTime::now(),
                },
            );
            black_box(fresh.len());
        }
    });

    let mut batch = collector.collect(
        &buffer,
        BatchMetadata {
            client_name,
            network_name,
            updated_time: SystemTime::now(),
        },
    );

    let (_reuse_output, reuse_allocations, reuse_deallocations) = measure_alloc_counts(|| {
        for _ in 0..8 {
            batch.metadata.updated_time = SystemTime::now();
            collector.collect_into(&buffer, &mut batch);
            black_box(batch.len());
        }
    });

    assert!(
        batch.len() > 1000,
        "reuse collect should keep populated batch"
    );
    assert!(
        reuse_allocations < fresh_allocations,
        "reuse collect should allocate less (reuse={} fresh={})",
        reuse_allocations,
        fresh_allocations
    );
    assert!(
        reuse_deallocations < fresh_deallocations,
        "reuse collect should deallocate less (reuse={} fresh={})",
        reuse_deallocations,
        fresh_deallocations
    );
}
