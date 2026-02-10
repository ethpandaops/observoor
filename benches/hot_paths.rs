use std::collections::HashMap;
use std::time::{Duration, SystemTime};

use criterion::{
    black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput,
};
use observoor::sink::aggregated::buffer::Buffer;
use observoor::sink::aggregated::collector::Collector;
use observoor::sink::aggregated::dimension::{
    BasicDimension, DiskDimension, NetworkDimension, TCPMetricsDimension,
};
use observoor::sink::aggregated::metric::{
    BatchMetadata, CounterMetric, GaugeMetric, LatencyMetric, SamplingMode, SlotInfo, WindowInfo,
};
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

fn syscall_payload(pid: u32, tid: u32, latency_ns: u64) -> Vec<u8> {
    let mut data = header(123_456_789, pid, tid, EventType::SyscallFutex as u8, 1);
    data.extend_from_slice(&latency_ns.to_le_bytes());
    data.extend_from_slice(&0i64.to_le_bytes());
    data.extend_from_slice(&202u32.to_le_bytes());
    data.extend_from_slice(&12i32.to_le_bytes());
    data
}

fn fd_payload(pid: u32, tid: u32) -> Vec<u8> {
    let mut data = header(123_456_789, pid, tid, EventType::FDOpen as u8, 1);
    data.extend_from_slice(&12i32.to_le_bytes());
    data.extend_from_slice(&[0u8; 4]);
    let mut filename = [0u8; 64];
    let raw = b"/var/lib/nethermind/current/logs/trace.log";
    filename[..raw.len()].copy_from_slice(raw);
    data.extend_from_slice(&filename);
    data
}

fn disk_payload(pid: u32, tid: u32, rw: u8) -> Vec<u8> {
    let mut data = header(123_456_789, pid, tid, EventType::DiskIO as u8, 1);
    data.extend_from_slice(&37_500u64.to_le_bytes());
    data.extend_from_slice(&4_096u32.to_le_bytes());
    data.push(rw);
    data.extend_from_slice(&[0u8; 3]);
    data.extend_from_slice(&7u32.to_le_bytes());
    data.extend_from_slice(&259u32.to_le_bytes());
    data
}

fn net_payload(pid: u32, tid: u32, direction: Direction, has_metrics: bool) -> Vec<u8> {
    let event_type = if direction == Direction::TX {
        EventType::NetTX
    } else {
        EventType::NetRX
    };
    let mut data = header(123_456_789, pid, tid, event_type as u8, 1);
    data.extend_from_slice(&1_500u32.to_le_bytes());
    data.extend_from_slice(&30_303u16.to_le_bytes());
    data.extend_from_slice(&9_000u16.to_le_bytes());
    data.push(direction as u8);
    data.push(u8::from(has_metrics));
    data.extend_from_slice(&[0u8; 2]);
    data.extend_from_slice(&95u32.to_le_bytes());
    data.extend_from_slice(&128_000u32.to_le_bytes());
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
            let net = NetworkDimension {
                pid: event.raw.pid,
                client_type: event.raw.client_type as u8,
                port_label: 0, // Unknown in bench context
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

fn build_collector_input(cardinality: u32, repeats: usize) -> (Collector, Buffer, BatchMetadata) {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let collector = Collector::new(Duration::from_millis(200));
    let buffer = Buffer::new(now, 42, now, false, false, false, 16);

    for i in 0..cardinality {
        let pid = 4_000 + i;
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

        for _ in 0..repeats {
            buffer.add_syscall(EventType::SyscallRead, basic, 1_200);
            buffer.add_syscall(EventType::SyscallFutex, basic, 450);
            buffer.add_sched_switch(basic, 2_000, i % 8);
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
    }

    let meta = BatchMetadata {
        client_name: "bench-node".into(),
        network_name: "hoodi".into(),
        updated_time: now,
    };

    (collector, buffer, meta)
}

fn bench_parse_event(c: &mut Criterion) {
    let payloads = [
        ("syscall_futex", syscall_payload(1_337, 1_337, 2_500)),
        ("fd_open", fd_payload(1_337, 1_337)),
        ("disk_io", disk_payload(2_001, 2_001, 1)),
        ("net_tx", net_payload(2_777, 2_777, Direction::TX, true)),
    ];

    let mut group = c.benchmark_group("parse_event");
    for (name, payload) in payloads {
        group.bench_function(name, |b| {
            b.iter(|| parse_event(black_box(&payload)).expect("parse event"))
        });
    }
    group.finish();
}

fn bench_buffer_ingest(c: &mut Criterion) {
    let mut group = c.benchmark_group("buffer");
    for events in [1_024usize, 16_384usize] {
        group.throughput(Throughput::Elements(events as u64));
        group.bench_with_input(
            BenchmarkId::new("ingest_mixed_events", events),
            &events,
            |b, &events| {
                b.iter_batched(
                    || {
                        Buffer::new(
                            SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
                            42,
                            SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
                            false,
                            false,
                            false,
                            16,
                        )
                    },
                    |buffer| {
                        for i in 0..events {
                            let pid = 10_000 + (i as u32 % 128);
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

                            buffer.add_syscall(EventType::SyscallRead, basic, 800);
                            buffer.add_net_io(net, 1_500);
                            buffer.add_tcp_metrics(tcp, 100, 128_000);
                            buffer.add_disk_io(disk, 20_000, 4_096, 4);
                            buffer.add_page_fault(basic, false);
                        }
                        black_box(buffer.net_io.len() + buffer.disk_latency.len());
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }
    group.finish();
}

fn bench_collect(c: &mut Criterion) {
    let mut group = c.benchmark_group("collector");
    for cardinality in [32u32, 128u32, 512u32] {
        let (collector, buffer, meta) = build_collector_input(cardinality, 1);
        group.throughput(Throughput::Elements(cardinality as u64));
        group.bench_with_input(
            BenchmarkId::new("collect_window_allocating", cardinality),
            &cardinality,
            |b, _| {
                b.iter(|| {
                    let batch = collector.collect(black_box(&buffer), black_box(meta.clone()));
                    black_box(batch.len())
                })
            },
        );
        let mut reusable_batch = collector.collect(&buffer, meta.clone());
        group.bench_with_input(
            BenchmarkId::new("collect_window_reuse", cardinality),
            &cardinality,
            |b, _| {
                b.iter(|| {
                    reusable_batch.metadata.updated_time = SystemTime::UNIX_EPOCH;
                    collector.collect_into(black_box(&buffer), black_box(&mut reusable_batch));
                    black_box(reusable_batch.len())
                })
            },
        );
    }
    group.finish();

    // Legacy benchmark name kept for cross-commit perf gating compatibility.
    let (collector, buffer, meta) = build_collector_input(128, 1);
    c.bench_function("collector/collect_medium_window", |b| {
        b.iter(|| {
            let batch = collector.collect(black_box(&buffer), black_box(meta.clone()));
            black_box(batch.len())
        })
    });
}

fn bench_pipeline(c: &mut Criterion) {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let collector = Collector::new(Duration::from_millis(200));
    let meta = BatchMetadata {
        client_name: "bench-node".into(),
        network_name: "hoodi".into(),
        updated_time: now,
    };

    let mut payloads = Vec::with_capacity(256);
    for i in 0..256u32 {
        payloads.push(syscall_payload(
            20_000 + i,
            20_000 + i,
            400 + u64::from(i % 32),
        ));
        payloads.push(fd_payload(20_000 + i, 20_000 + i));
        payloads.push(disk_payload(20_000 + i, 20_000 + i, (i % 2) as u8));
        payloads.push(net_payload(
            20_000 + i,
            20_000 + i,
            if i % 2 == 0 {
                Direction::TX
            } else {
                Direction::RX
            },
            true,
        ));
    }

    c.bench_function("pipeline/parse_aggregate_collect_1024", |b| {
        b.iter_batched(
            || Buffer::new(now, 42, now, false, false, false, 16),
            |buffer| {
                for raw in &payloads {
                    let parsed = parse_event(raw).expect("parse pipeline event");
                    process_parsed_event(&buffer, &parsed);
                }
                let batch = collector.collect(&buffer, meta.clone());
                black_box(batch.len())
            },
            BatchSize::SmallInput,
        );
    });
}

fn build_export_grouping_input(
    rows_per_table: usize,
) -> (Vec<LatencyMetric>, Vec<CounterMetric>, Vec<GaugeMetric>) {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let window = WindowInfo {
        start: now,
        interval_ms: 200,
    };
    let slot = SlotInfo {
        number: 42,
        start_time: now,
    };

    let mut latency = Vec::with_capacity(rows_per_table * 2);
    for i in 0..rows_per_table {
        latency.push(LatencyMetric {
            metric_type: "syscall_read",
            window,
            slot,
            pid: 1_000 + i as u32,
            client_type: observoor::tracer::event::ClientType::Geth,
            device_id: None,
            rw: None,
            sampling_mode: SamplingMode::None,
            sampling_rate: 1.0,
            sum: 5_000,
            count: 1,
            min: 5_000,
            max: 5_000,
            histogram: [0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
        });
    }
    for i in 0..rows_per_table {
        latency.push(LatencyMetric {
            metric_type: "disk_latency",
            window,
            slot,
            pid: 2_000 + i as u32,
            client_type: observoor::tracer::event::ClientType::Geth,
            device_id: Some(259),
            rw: Some("read"),
            sampling_mode: SamplingMode::None,
            sampling_rate: 1.0,
            sum: 8_000,
            count: 1,
            min: 8_000,
            max: 8_000,
            histogram: [0, 0, 1, 0, 0, 0, 0, 0, 0, 0],
        });
    }

    let mut counter = Vec::with_capacity(rows_per_table * 2);
    for i in 0..rows_per_table {
        counter.push(CounterMetric {
            metric_type: "page_fault_minor",
            window,
            slot,
            pid: 3_000 + i as u32,
            client_type: observoor::tracer::event::ClientType::Geth,
            device_id: None,
            rw: None,
            port_label: None,
            direction: None,
            sampling_mode: SamplingMode::None,
            sampling_rate: 1.0,
            sum: 1,
            count: 1,
        });
    }
    for i in 0..rows_per_table {
        counter.push(CounterMetric {
            metric_type: "net_io",
            window,
            slot,
            pid: 4_000 + i as u32,
            client_type: observoor::tracer::event::ClientType::Geth,
            device_id: None,
            rw: None,
            port_label: Some("el_p2p_tcp"),
            direction: Some("tx"),
            sampling_mode: SamplingMode::None,
            sampling_rate: 1.0,
            sum: 1_500,
            count: 1,
        });
    }

    let mut gauge = Vec::with_capacity(rows_per_table * 2);
    for i in 0..rows_per_table {
        gauge.push(GaugeMetric {
            metric_type: "tcp_rtt",
            window,
            slot,
            pid: 5_000 + i as u32,
            client_type: observoor::tracer::event::ClientType::Geth,
            device_id: None,
            rw: None,
            port_label: Some("el_p2p_tcp"),
            sampling_mode: SamplingMode::None,
            sampling_rate: 1.0,
            sum: 110,
            count: 1,
            min: 110,
            max: 110,
        });
    }
    for i in 0..rows_per_table {
        gauge.push(GaugeMetric {
            metric_type: "disk_queue_depth",
            window,
            slot,
            pid: 6_000 + i as u32,
            client_type: observoor::tracer::event::ClientType::Geth,
            device_id: Some(259),
            rw: Some("write"),
            port_label: None,
            sampling_mode: SamplingMode::None,
            sampling_rate: 1.0,
            sum: 8,
            count: 1,
            min: 8,
            max: 8,
        });
    }

    (latency, counter, gauge)
}

fn group_batch_hashmap(
    latency: &[LatencyMetric],
    counter: &[CounterMetric],
    gauge: &[GaugeMetric],
) -> usize {
    let mut latency_map: HashMap<&str, Vec<&LatencyMetric>> = HashMap::with_capacity(16);
    for metric in latency {
        latency_map
            .entry(metric.metric_type)
            .or_default()
            .push(metric);
    }

    let mut counter_map: HashMap<&str, Vec<&CounterMetric>> = HashMap::with_capacity(16);
    for metric in counter {
        counter_map
            .entry(metric.metric_type)
            .or_default()
            .push(metric);
    }

    let mut gauge_map: HashMap<&str, Vec<&GaugeMetric>> = HashMap::with_capacity(8);
    for metric in gauge {
        gauge_map
            .entry(metric.metric_type)
            .or_default()
            .push(metric);
    }

    latency_map.values().map(Vec::len).sum::<usize>()
        + counter_map.values().map(Vec::len).sum::<usize>()
        + gauge_map.values().map(Vec::len).sum::<usize>()
}

fn group_batch_contiguous(
    latency: &[LatencyMetric],
    counter: &[CounterMetric],
    gauge: &[GaugeMetric],
) -> usize {
    fn count_grouped<T>(items: &[T], metric_type: impl Fn(&T) -> &'static str) -> usize {
        let mut i = 0;
        let mut rows = 0;
        while i < items.len() {
            let current = metric_type(&items[i]);
            let mut j = i + 1;
            while j < items.len() && metric_type(&items[j]) == current {
                j += 1;
            }
            rows += j - i;
            i = j;
        }
        rows
    }

    count_grouped(latency, |m| m.metric_type)
        + count_grouped(counter, |m| m.metric_type)
        + count_grouped(gauge, |m| m.metric_type)
}

fn bench_export_grouping(c: &mut Criterion) {
    let mut group = c.benchmark_group("export_grouping");
    for rows_per_table in [128usize, 1024usize, 4096usize] {
        let (latency, counter, gauge) = build_export_grouping_input(rows_per_table);
        group.throughput(Throughput::Elements((rows_per_table * 6) as u64));

        group.bench_with_input(
            BenchmarkId::new("hashmap", rows_per_table),
            &rows_per_table,
            |b, _| {
                b.iter(|| {
                    black_box(group_batch_hashmap(
                        black_box(&latency),
                        black_box(&counter),
                        black_box(&gauge),
                    ))
                })
            },
        );

        group.bench_with_input(
            BenchmarkId::new("contiguous", rows_per_table),
            &rows_per_table,
            |b, _| {
                b.iter(|| {
                    black_box(group_batch_contiguous(
                        black_box(&latency),
                        black_box(&counter),
                        black_box(&gauge),
                    ))
                })
            },
        );
    }
    group.finish();
}

fn bench_suite(c: &mut Criterion) {
    bench_parse_event(c);
    bench_buffer_ingest(c);
    bench_collect(c);
    bench_pipeline(c);
    bench_export_grouping(c);
}

criterion_group!(benches, bench_suite);
criterion_main!(benches);
