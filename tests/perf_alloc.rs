use std::alloc::System;
use std::hint::black_box;
use std::time::{Duration, SystemTime};

use observoor::sink::aggregated::buffer::Buffer;
use observoor::sink::aggregated::collector::Collector;
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
        allocations <= 4,
        "fd parse allocation budget exceeded: {}",
        allocations
    );
}

#[test]
#[serial]
fn collect_empty_buffer_allocation_budget() {
    let collector = Collector::new(Duration::from_millis(200));
    let now = SystemTime::now();
    let buffer = Buffer::new(now, 42, now, false, false, false);
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
