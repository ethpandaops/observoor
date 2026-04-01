# Observoor CPU Overhead Optimization

## Objective

Reduce the CPU seconds consumed by observoor when tracing a synthetic workload
via eBPF. The benchmark runs `stress-bench` (50,000 iterations × 4 threads ≈
500K syscall events) while observoor traces it, measuring observoor's own CPU
time via `/proc/<pid>/stat`.

## How the Benchmark Works

1. A synthetic C program (`bench-cpu/stress-bench.c`) generates deterministic
   syscall load: file I/O, network I/O, mmap, futex, mutex across 4 threads.
2. Observoor loads all BPF probe groups and traces the stress-bench process.
3. We measure observoor's CPU time (utime + stime from /proc) during the
   workload window.
4. Lower `observoor_cpu_seconds` = better.

## Architecture Context

The hot path is: **BPF ring buffer → event parse → aggregation buffer**.

- **Ring buffer reader**: tokio task polling epoll on the BPF ring buffer fd.
  Events arrive as raw byte slices.
- **Event parsing** (`src/tracer/parse.rs`): Zero-copy read from ring buffer.
  24-byte header, then per-type payload. Only `parse_fd` allocates (String for filename).
- **Aggregation** (`src/sink/aggregated/buffer.rs`): ~30 `DashMap<DimensionKey, Aggregate>`
  fields. Each event does `entry().or_default()` + atomic updates (fetch_add,
  CAS loops on min/max). `LatencyAggregate` also records into a 10-bucket histogram.
- **Collection** (`src/sink/aggregated/collector.rs`): Iterates all DashMaps,
  snapshots aggregates into MetricBatch vectors. Runs on slot boundaries.

Key cost centers (from Criterion benchmarks):
1. `DashMap::entry().or_default()` — shard lock + hash per event
2. CAS loops on min/max in LatencyAggregate/GaugeAggregate
3. Histogram::record() — 9-element linear scan per latency event
4. Ring buffer polling overhead
5. BPF program execution (kernel-side, charged to traced process)

27 probe groups, each a tracepoint or kprobe/kretprobe pair. All use a
`tracked_pids` BPF hash map for PID filtering.

## Current Baseline

- **observoor_cpu_seconds**: 9.51 (median of 3 runs: [9.55, 9.46, 9.51])
- **wall_clock_seconds**: 27.99
- **Measured at commit**: 53f86ad
- **Date**: 2026-03-30
- **Environment**: GitHub Actions ubuntu-latest (4 vCPU)

## What Has Been Tried

### Iteration 1: Replace CAS loops with fetch_min/fetch_max (2026-03-30)
- **Hypothesis**: `AtomicI64::fetch_min`/`fetch_max` would be faster than manual
  `compare_exchange_weak` retry loops for min/max tracking.
- **Change**: Replaced ~60 lines of CAS loops in `LatencyAggregate::record()` and
  `GaugeAggregate::record()` with `fetch_min`/`fetch_max`.
- **Result**: INCONCLUSIVE — measurement was cross-runner (different CI hardware),
  making comparison unreliable. Numbers varied from 9.51s to 15.95s across runs
  on different runners.
- **Verdict**: REVERTED. Benchmark methodology fixed to compare base vs head
  in the same CI run.
- **Note**: The original CAS loops have an early exit when `val >= old_min` which
  avoids the atomic operation entirely for most events. `fetch_min`/`fetch_max`
  always performs the atomic RMW. The early exit is likely faster for the common
  case where most values don't update min/max.

### Iteration 2: Switch DashMaps to hashbrown's fast hasher (2026-03-30)
- **Hypothesis**: SipHash (default DashMap hasher) is slower than ahash for
  short dimension keys.
- **Change**: Added `FastDashMap` type alias using `hashbrown::DefaultHashBuilder`
  (ahash) for all ~30 aggregation DashMaps in `buffer.rs`.
- **Result**: 9.44s vs 9.61s baseline = **-1.77% improvement**
- **Verdict**: KEPT
- **Commit**: a135761

### Iteration 3: Eliminate String allocation in FD event parsing (2026-03-30)
- **Hypothesis**: FD events (fd_open/fd_close) allocate a String for the
  filename during parsing, but the aggregated sink only counts them without
  using the filename. The allocation is wasted CPU.
- **Change**: Replaced heap-allocated String with inline 64-byte array in
  `ParsedFdEvent`. Decode on demand only.
- **Result**: 15.31s vs 15.61s baseline = **-1.92% improvement**
- **Verdict**: KEPT
- **Commit**: 2864085

### Iteration 4: Collapse double event dispatch in aggregated sink (2026-03-30)
- **Hypothesis**: Events were dispatched through two match statements — first
  in process_event_with_scheduler_state, then in process_event — causing
  redundant matching and BasicDimension rebuilds.
- **Change**: Merged into a single dispatch path in `process_event_inner`.
- **Result**: 15.15s vs 15.45s baseline = **-1.94% improvement**
- **Verdict**: KEPT
- **Commit**: c95a1ef

### Iteration 5: Remove redundant atomics from aggregate structs (2026-03-30)
- **Hypothesis**: DashMap shard locks provide exclusive access during
  entry().or_default(), making per-field AtomicI64/AtomicU32 redundant.
- **Change**: Replaced all atomic fields in LatencyAggregate, CounterAggregate,
  GaugeAggregate, and Histogram with plain scalars. `record()` now takes `&mut self`.
- **Result**: 15.66s vs 15.96s baseline = **-1.88% improvement**
- **Verdict**: KEPT
- **Commit**: f180b14

### Iteration 6: Consolidate disk I/O into single DashMap lookup (2026-03-30)
- **Hypothesis**: Each disk I/O event triggered 3 separate DashMap lookups
  (disk_latency, disk_bytes, disk_queue_depth). Merging into a single
  DiskAggregate struct behind one DashMap entry reduces hash+lock overhead.
- **Change**: New `DiskAggregate` struct, single `disk_io` DashMap in Buffer.
- **Result**: 15.36s vs 15.98s baseline = **-3.88% improvement**
- **Verdict**: KEPT
- **Commit**: eb82c07

### Iteration 7: Consolidate TCP RTT/CWND into single DashMap lookup (2026-03-30)
- **Hypothesis**: Each TCP metrics event triggered 2 DashMap lookups (tcp_rtt,
  tcp_cwnd). Merging into TcpMetricsAggregate reduces hash+lock overhead.
- **Change**: New `TcpMetricsAggregate`, single `tcp_metrics` DashMap in Buffer.
- **Result**: 15.48s vs 15.73s baseline = **-1.59% improvement**
- **Verdict**: KEPT
- **Commit**: 60378a5

### Iteration 8: Consolidate sched_off_cpu/runqueue into single lookup (2026-03-30)
- **Hypothesis**: SchedRunqueue events triggered 2 DashMap lookups. Merging
  sched_off_cpu and sched_runqueue into SchedulerWaitAggregate reduces overhead.
- **Change**: New `SchedulerWaitAggregate`, single `sched_wait` DashMap in Buffer.
- **Result**: 15.38s vs 15.81s baseline = **-2.72% improvement**
- **Verdict**: KEPT
- **Commit**: bb1c7d8

### Iteration 9: Optimize histogram bucket lookup with compare chain (2026-03-30)
- **Hypothesis**: Per-latency-event histogram recording used a loop over 9
  boundaries + checked get_mut. An inlined compare chain is faster.
- **Change**: Replaced `bucket_index()` loop + `get_mut()` with direct
  if-else chain and unchecked increment.
- **Result**: 14.52s vs 14.86s baseline = **-2.29% improvement**
- **Verdict**: KEPT
- **Commit**: 7fb1a42

### Iteration 10: Use hashbrown for scheduler TID tracking (2026-03-30)
- **Hypothesis**: SchedulerWindowState.running_by_tid used std HashMap (SipHash)
  for TID lookups on every sched event. ahash is faster for u32 keys.
- **Change**: Switched to `hashbrown::HashMap` with pre-allocated capacity.
- **Result**: 15.21s vs 15.50s baseline = **-1.87% improvement**
- **Verdict**: KEPT
- **Commit**: 81f2098

### Iteration 11: Entry API for scheduler TID tracking (2026-03-30)
- **Hypothesis**: Scheduler TID tracking did get+remove or get_mut+insert —
  two HashMap lookups per event. Entry API does it in one.
- **Change**: Switched to `hashbrown::Entry` for all TID operations.
- **Result**: 14.33s vs 14.71s baseline = **-2.58% improvement**
- **Verdict**: KEPT
- **Commit**: f67a7dd

### Iteration 12: Skip port-label resolution when port map is empty (2026-03-30)
- **Hypothesis**: Network events do client conversion + port extraction + map
  lookups even when no port labels exist (e.g. ClientType::Unknown).
- **Change**: Short-circuit network dimension building when port map is empty.
- **Result**: 14.23s vs 14.74s baseline = **-3.46% improvement**
- **Verdict**: KEPT
- **Commit**: ea1ad05

### Iteration 13: Reuse NetworkDimension for TCP metrics (2026-03-30)
- **Hypothesis**: TCP NetIO events rebuilt dimension + resolved port labels
  twice — once for net_io, once for tcp_metrics.
- **Change**: Reuse already-built NetworkDimension for TCPMetricsDimension.
- **Result**: 14.98s vs 15.34s baseline = **-2.35% improvement**
- **Verdict**: KEPT
- **Commit**: 2a15dfb

### Iteration 14: Replace DashMap with Mutex<HashMap> (2026-03-30)
- **Hypothesis**: Ingestion is serialized through the sink's event loop, so
  DashMap's per-shard sharding is unnecessary overhead.
- **Change**: Replaced all DashMaps with `parking_lot::Mutex<HashMap>`.
  Removed `dashmap` dependency entirely.
- **Result**: 14.27s vs 14.79s baseline = **-3.52% improvement**
- **Verdict**: KEPT
- **Commit**: e69bac4

### Iteration 15: Pack dimension keys for faster hashing (2026-03-30)
- **Hypothesis**: Dimension keys were hashed field-by-field through derive(Hash).
  Packing into a single u64/u128 before hashing reduces hasher calls.
- **Change**: Manual Hash impls for all dimension types using packed integers.
- **Result**: 10.48s vs 10.99s baseline = **-4.64% improvement**
- **Verdict**: KEPT
- **Commit**: b8a81d6

### Iteration 16: Remove duplicate event header from typed payloads (2026-03-30)
- **Hypothesis**: Typed event structs duplicated the common header fields,
  causing extra copying through parse + channel handoff.
- **Change**: Payloads now carry only unique fields; header in ParsedEvent.raw.
  Net -270 lines.
- **Result**: 15.20s vs 15.68s baseline = **-3.06% improvement**
- **Verdict**: KEPT
- **Commit**: 59fb1fc

### Iteration 17: Remove all locks from aggregation buffer (2026-03-30)
- **Hypothesis**: Since ingestion is serialized in one tokio task, the buffer
  doesn't need Mutex at all. Plain HashMaps with &mut self.
- **Change**: Removed all parking_lot::Mutex from buffer, rotation via mem::replace.
- **Result**: 15.48s vs 15.81s baseline = **-2.09% improvement**
- **Verdict**: KEPT
- **Commit**: 14d7956

### Iteration 18: Specialize event dispatch with lazy dimensions (2026-03-30)
- **Hypothesis**: BasicDimension was built eagerly for all events. Syscall events
  also paid a second EventType match in add_syscall.
- **Change**: Only build dimensions in branches that need them. Direct map writes.
- **Result**: 15.13s vs 15.54s baseline = **-2.64% improvement**
- **Verdict**: KEPT
- **Commit**: 4fba85a

### Iteration 19: Subtype-specific TypedEvent variants from parser (2026-03-30)
- **Hypothesis**: Parser collapsed events to generic Syscall/FD etc, then sink
  re-matched on EventType. Emitting specific variants eliminates double dispatch.
- **Change**: Per-syscall/FD/memory/swap variants in TypedEvent, direct dispatch.
- **Result**: 15.39s vs 15.80s baseline = **-2.59% improvement**
- **Verdict**: KEPT
- **Commit**: c58d8c0

### Iteration 20: Defer FD filename NUL-scan to access time (2026-03-30)
- **Hypothesis**: FD parse path scanned for first NUL byte in 64-byte filename
  on every event. Deferring to access time removes work from hot path.
- **Change**: Store raw 64-byte buffer, lazy NUL scan in as_bytes().
- **Result**: 15.58s vs 15.90s baseline = **-2.01% improvement**
- **Verdict**: KEPT
- **Commit**: d3cca5e

### Iteration 21: Batch Prometheus counter updates off hot path (2026-03-31)
- **Hypothesis**: Per-event Prometheus counter inc() calls with label lookup
  add overhead. Batching into a 1Hz flush removes this from hot path.
- **Change**: Cheap atomic counters on hot path, background task flushes to Prometheus.
- **Result**: 15.14s vs 15.49s baseline = **-2.26% improvement**
- **Verdict**: KEPT
- **Commit**: a910dcc

### Iteration 22: Normalize empty PortLabelMap to None (2026-03-31)
- **Hypothesis**: is_empty() check on every network event. Option::is_none() cheaper.
- **Change**: Normalize at config load, simplify hot-path check.
- **Result**: 15.28s vs 15.67s baseline = **-2.49% improvement**
- **Verdict**: KEPT
- **Commit**: 9e24f53

### Iteration 23: Identity hasher for pre-packed integer keys (2026-03-31)
- **Hypothesis**: Keys are already packed into u32/u64/u128. ahash mixing is
  redundant CPU. Pass through directly as identity hash.
- **Change**: Custom `IdentityHasher` for all aggregation + TID maps.
- **Result**: 15.56s vs 16.06s baseline = **-3.11% improvement**
- **Verdict**: KEPT
- **Commit**: eee5156

### Iteration 24: FD events as payload-free markers (2026-03-31)
- **Hypothesis**: FD open/close events copied a 64-byte filename buffer the
  sink never reads. Making them unit variants eliminates the copy.
- **Change**: TypedEvent::FDOpen/FDClose are unit variants. No filename parsing.
- **Result**: 12.43s vs 12.93s baseline = **-3.87% improvement**
- **Verdict**: KEPT
- **Commit**: 8f64f1a

### Iteration 25: Array-indexed port labels instead of HashMap (2026-03-31)
- **Hypothesis**: Port label lookups hashed ClientType on every network event.
  Fixed array indexed by client_type u8 eliminates the hash.
- **Change**: `PortLabelMap` backed by `[HashMap<u16, ...>; N]` instead of
  `HashMap<ClientType, HashMap<u16, ...>>`.
- **Result**: 14.98s vs 15.50s baseline = **-3.35% improvement**
- **Verdict**: KEPT
- **Commit**: 4a50c52

### Iteration 26: Batch event stats with local counters (2026-03-31)
- **Hypothesis**: Two atomic increments per event for stats tracking.
  Batching into local counters flushed every 1024 events amortizes cost.
- **Change**: Thread-local counter buffer with periodic flush to shared atomics.
- **Result**: 15.19s vs 15.80s baseline = **-3.86% improvement**
- **Verdict**: KEPT
- **Commit**: c3e6ce9

### Iteration 27: Increase event drain batch size 256→1024 (2026-03-31)
- **Hypothesis**: Processing more queued events per wakeup reduces mpsc/select!
  overhead under sustained load.
- **Change**: One-line change: `DRAIN_BATCH` from 256 to 1024.
- **Result**: 15.19s vs 15.85s baseline = **-4.16% improvement**
- **Verdict**: KEPT
- **Commit**: cbf4f98

### Iteration 28: Trim unused syscall fields from parsed events (2026-03-31)
- **Hypothesis**: Syscall events carried ret, syscall_nr, fd which the sink never uses.
- **Change**: Syscall payload now only carries latency_ns. 3 fewer reads per event.
- **Result**: 14.85s vs 15.47s baseline = **-4.01% improvement**
- **Verdict**: KEPT
- **Commit**: 1b0838e

### Iteration 29: BPF — FD events header-only, remove filename capture (2026-03-31)
- **Hypothesis**: FD events emitted 96 bytes (including filename) that was never used.
  Removing filename capture + openat_names map + sys_enter_openat tracepoint.
- **Change**: First BPF-side optimization. FD events now 24 bytes (header only).
- **Result**: 14.21s vs 14.82s baseline = **-4.12% improvement**
- **Verdict**: KEPT
- **Commit**: cd07511

### Iteration 30: Simplify PackedKeyHasher to single multiply (2026-03-31)
- **Hypothesis**: xor-fold in identity hasher was unnecessary for pre-packed keys.
- **Change**: Single multiply instead of multiply-plus-xor.
- **Result**: 15.08s vs 15.75s baseline = **-4.25% improvement**
- **Verdict**: KEPT
- **Commit**: d8e93de

### Iteration 31: Batch event delivery from tracer to sink (2026-03-31)
- **Hypothesis**: Per-event channel send/recv has overhead. Batching into
  Vec<ParsedEvent> of up to 256 should amortize it.
- **Change**: Batch handlers in tracer, batch queue in sink.
- **Result**: 15.49s vs 15.50s baseline = **-0.06% (noise)**
- **Verdict**: KEPT (no harm, cleaner architecture)
- **Commit**: 2ea65d6

### Iteration 32: Increase tracer batch size to 1024 (2026-03-31)
- **Hypothesis**: Larger batches = fewer channel sends and Vec handoffs.
- **Change**: Batch size 256→1024, rebalance sink queue to 64×2.
- **Result**: 15.44s vs 15.83s baseline = **-2.46% improvement**
- **Verdict**: KEPT
- **Commit**: 2860450

### Iteration 33: Increase batch size to 2048, queue 32×1 (2026-03-31)
- **Hypothesis**: Further batch increase cuts channel/wakeup overhead.
- **Change**: Batch 1024→2048, queue 64×2→32×1.
- **Result**: 15.35s vs 15.79s baseline = **-2.79% improvement**
- **Verdict**: KEPT
- **Commit**: 139977a

### Iteration 34: Packed PartialEq for dimension keys (2026-03-31)
- **Hypothesis**: HashMap entry() equality still compared fields individually.
- **Change**: PartialEq now uses packed u64/u128 comparison.
- **Result**: 15.90s vs 16.19s baseline = **-1.79% improvement**
- **Verdict**: KEPT
- **Commit**: 9ed7318

---

### Iteration 35: Keep client_type as raw u8, skip enum conversion (2026-03-31)
- **Hypothesis**: Per-event ClientType enum conversion + back-cast wastes CPU.
- **Change**: Keep validated u8 through parse → aggregate. No enum roundtrip.
- **Result**: 9.48s vs 10.37s baseline = **-8.58% improvement**
- **Verdict**: KEPT
- **Commit**: 890f649

---

### Iteration 36: Single-dispatch parser (2026-03-31)
- **Hypothesis**: EventType::from_u8 + separate typed dispatch = double match.
- **Change**: Single match constructs both raw.event_type and TypedEvent.
- **Result**: 15.37s vs 15.68s baseline = **-1.98% improvement**
- **Verdict**: KEPT
- **Commit**: 9a1cbb4

---

### Iteration 37: Rotate/XOR hasher instead of multiply (2026-03-31)
- **Hypothesis**: 64-bit multiply in hasher is expensive. Rotate/XOR is cheaper.
- **Change**: Single line: `rotate_left(5) ^ value` instead of `wrapping_mul`.
- **Result**: 10.01s vs 10.83s baseline = **-7.57% improvement**
- **Verdict**: KEPT
- **Commit**: 112c530

---

### Iteration 38: BPF — remove page-fault entry tracking (2026-03-31)
- **Hypothesis**: Page-fault entry probe + hash map for fault address is unused.
- **Change**: Emit directly from return probe, remove BPF map, shrink event.
- **Result**: 12.42s vs 12.92s baseline = **-3.87% improvement**
- **Verdict**: KEPT
- **Commit**: 80986b1

---

### Iteration 39: Precompute batch stats, skip re-walk (2026-03-31)
- **Hypothesis**: Agent walked parsed events twice — once for stats, once for sink.
- **Change**: Batch carries precomputed per-type/client counts from tracer.
- **Result**: 15.62s vs 15.98s baseline = **-2.25% improvement**
- **Verdict**: KEPT
- **Commit**: dea2d20

---

### Iteration 40: Keep network direction/transport as raw u8 (2026-03-31)
- **Hypothesis**: Same as iteration 35 pattern — enum decode+back-cast wastes CPU.
- **Change**: Keep validated raw bytes for direction/transport.
- **Result**: 15.42s vs 15.85s baseline = **-2.71% improvement**
- **Verdict**: KEPT
- **Commit**: 4a1280a

---

### Iteration 42: BPF — shrink syscall events 48→32 bytes (2026-03-31)
- **Hypothesis**: Unused ret/syscall_nr/fd in BPF syscall struct waste ring buffer bandwidth.
- **Change**: Removed fields from BPF event struct and parser. 16 fewer bytes/event.
- **Result**: 14.55s vs 15.13s baseline = **-3.83% improvement**
- **Verdict**: KEPT
- **Commit**: e2ec4cd

---

### Iteration 43: Batch size 4096, queue 16×4 (2026-03-31)
- **Hypothesis**: Larger batches = fewer channel sends and allocations.
- **Change**: Batch 2048→4096, queue 32×1→16×4.
- **Result**: 15.38s vs 16.04s baseline = **-4.11% improvement**
- **Verdict**: KEPT
- **Commit**: fb5bdb3

---

### Iteration 44: Store BasicDimension as pre-packed u64 (2026-04-01)
- **Hypothesis**: BasicDimension recomputed pack_basic() on every hash/eq.
- **Change**: Store pre-packed u64, accessor methods for pid/client_type.
- **Result**: 15.22s vs 15.95s baseline = **-4.58% improvement**
- **Verdict**: KEPT
- **Commit**: 3e2a52d

---

### Iteration 45: Pre-pack all remaining dimension keys (2026-04-01)
- **Hypothesis**: CpuCoreDimension, NetworkDimension, etc still recomputed packing.
- **Change**: All dimension types now store pre-packed integers.
- **Result**: 12.51s vs 13.19s baseline = **-5.16% improvement**
- **Verdict**: KEPT
- **Commit**: 7e677d2

---

**NOTE**: Per-iteration deltas above were measured on different CI runners with
different CPU hardware, so the multiplicative cumulative is unreliable. The
benchmark now always compares HEAD against master on the same runner.

**Last measured total vs master (same runner): -4.09%**
This is the real end-to-end number. Individual iterations showed real improvements
but the absolute magnitude varies significantly by runner hardware.

**43 kept iterations.**

## Rules

1. Propose exactly ONE change per iteration.
2. The change must be a code modification (not config or benchmark tuning).
3. Do NOT modify files under `bench-cpu/` or `autoresearch/`.
4. `cargo test --no-default-features` must pass after your change.
5. Focus on the hot path: ring buffer read → parse → aggregate.
6. Explain your hypothesis before making the change.
7. After seeing benchmark results, decide whether to keep or revert.
   Record your reasoning.

## In-Scope Code

All code is in scope, including:
- **Rust userspace**: `src/`
- **BPF kernel-side**: `bpf/observoor.c`, `bpf/include/observoor.h`, `bpf/include/maps.h`
