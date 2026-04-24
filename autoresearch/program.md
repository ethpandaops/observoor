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

### Iteration 46: Compact block_merge events 32→11 bytes (2026-04-24)
- **Hypothesis**: `EVENT_BLOCK_MERGE` still emitted a full 32-byte header event
  (24B header + 8B payload) even though the sink only uses pid/bytes/rw. Dropping
  the full header in favour of an 11-byte compact record (pid + bytes + type +
  client + rw) reduces ring-buffer bandwidth and parser work, matching the
  compact shape already used for net/disk events.
- **Change**: New `COMPACT_BLOCK_MERGE` path in BPF + parser; legacy header
  variant retained as a fallback.
- **Result (old methodology, noise-inflated)**: 9.01s vs 10.14s baseline =
  -11.14% (median of 3: [9.02, 9.01, 8.95])
- **Result (new methodology, 5×interleaved + warmup, 2026-04-24)**: 12.26s vs
  13.30s master, CV 0.6% vs 0.3% — **-7.82% improvement**
- **Verdict**: KEPT — this is the current high-water mark.
- **Commit**: ea8e205 (measured in isolation on `4c9d784`)
- **Author**: gpt-5.5 / xhigh reasoning (first iteration from this model)

### Iteration 47: Compact TCP retransmit events 40→14 bytes (2026-04-24) — REVERTED
- **Hypothesis**: Drop 24B header from TCP retransmit ring-buffer records.
- **Change**: Compact 14B record + parser fallback. (commit `bce8cff`)
- **Result**: -8.36% vs master — **worse cumulative than iter 46** (-11.14%).
- **Verdict**: REVERTED retroactively (2026-04-24). Orchestrator misread the
  keep/revert rule and approved three regressions in a row before the trend
  was spotted. Branch reset to iter 46 tip (`9f330f3`).

### Iteration 48: Prioritize compact syscall parsing (2026-04-24) — REVERTED
- **Hypothesis**: Move compact-syscall size check ahead of compact-marker check.
- **Change**: Reorder dispatch in `parse.rs`. (commit `e3b0bc8`)
- **Result**: -7.20% vs master — another ~1pp regression on top of iter 47.
- **Verdict**: REVERTED retroactively (same reset as iter 47).

### Iteration 49: Match-dispatch compact parser lengths (2026-04-24) — DISCARDED
- **Hypothesis**: Replace length-check chain with a single `match data.len()`.
- **Change**: (commit `3cfcdff`, never pushed)
- **Result**: never measured — discarded before push because the loop was
  halted to audit the benchmark plumbing.
- **Verdict**: DISCARDED (code dropped on hard reset).

### Iteration 50: Shrink compact FD events 8→6 bytes (2026-04-24) — REVERTED
- **Hypothesis**: FD open/close compact records carried 2 pad bytes the sink
  doesn't read; dropping them cuts ring-buffer bandwidth and per-event pad
  zeroing in BPF.
- **Change**: BPF emits 6-byte FD marker + parser variant; legacy 8-byte path
  retained. (commits `bbf1552`, `fd80c7e`)
- **Result (new methodology)**: 14.71s vs 15.82s master, CV 0.3%/0.3% —
  **-7.02% vs master**. High-water mark is -7.82% (iter 46), so this is a
  ~0.80pp regression despite being faster than master in absolute terms.
- **Verdict**: REVERTED. Branch reset to `4c9d784`.
- **Author**: gpt-5.5 / xhigh reasoning

### Iteration 51: Portless net I/O when no port labels (2026-04-24) — REVERTED
- **Hypothesis**: When startup finds no active port-label map, BPF still emits
  15-byte net I/O records carrying ports/transport that the sink will never
  resolve. Emitting a 10-byte byte-only variant cuts ring-buffer bandwidth.
- **Change**: New 10-byte `NetIOTxBytes`/`NetIORxBytes` compact variants +
  BPF/parser plumbing; legacy 15-byte path retained. (commits `a171f15`,
  `3738c81`)
- **Result (new methodology)**: 14.94s vs 16.13s master, CV 0.3%/0.4% —
  **-7.38% vs master**. High-water mark is -7.82%, so this is a ~0.44pp
  regression. Within plausible between-runner noise, but doesn't beat HWM.
- **Verdict**: REVERTED. Branch reset to `df8f14c`.
- **Author**: gpt-5.5 / xhigh reasoning

### Iteration 52: Fold hot BasicDimension events in parsed batches (2026-04-24) — REVERTED
- **Hypothesis**: Parser can pre-fold repeated syscall/FD/page-fault events for
  a dominant pid/client inside `ParsedEventBatch`; the sink merges the single
  fold into buffer maps instead of doing per-event `entry().or_default()`.
- **Change**: New `basic_fold` on `ParsedEventBatch`, parser writes to it for
  matching events, sink consumes. (commits `4203c6e`, `1dbcd1a`)
- **Result (new methodology)**: 15.10s vs 16.06s master, CV 0.8%/0.6% —
  **-5.98% vs master**, 1.84pp worse than HWM -7.82%. Clear regression — the
  extra per-event fold work plus dominant-pid bookkeeping cost more than the
  saved map lookups for this workload.
- **Verdict**: REVERTED. Branch reset to `003f6e1`.
- **Author**: gpt-5.5 / xhigh reasoning

### Iteration 53: Compact tcp_state events 24→8 bytes (2026-04-24)
- **Hypothesis**: `EVENT_TCP_STATE` only increments a per-pid/client counter in
  the aggregated sink, so timestamp and tid from the generic 24-byte header are
  unused. Reusing the existing compact BasicDimension marker shape should cut
  ring-buffer bandwidth and parser work for TCP state transitions without
  changing aggregation semantics.
- **Change**: Emit `tcp_state` as an 8-byte compact marker and parse it through
  the existing compact basic-marker path.
- **Result (new methodology)**: 9.16s vs 10.17s master, CV 0.2%/0.4% —
  **-9.93% vs master**. Beats HWM -7.82% by 2.11pp.
- **Verdict**: KEPT (tentatively — note this run landed on a fast-runner class:
  master=10.17s here vs 13.30s when HWM was measured. Per-runner % delta seems
  to vary; iter 54 on a slow-runner class will confirm/deny.)
- **Commit**: 8ef28eb
- **Author**: gpt-5.5 / xhigh reasoning

### Iteration 54: Split tcp_state off cold map into own inline-hot map (2026-04-24) — REVERTED
- **Hypothesis**: `tcp_state_change` writes into the larger `basic_cold_metrics`
  map; moving it to a dedicated count-only map avoids disturbing the cold
  aggregate's layout on every TCP state event.
- **Change**: New `tcp_state_metrics` DashMap + collector wiring in
  buffer/aggregate/collector. (commits `a0b0ce3`, `e04990d`)
- **Result (new methodology)**: 14.94s vs 16.16s master, CV 0.6%/0.5% —
  **-7.55% vs master** (slow runner). Slow-runner iter 46 HWM is -7.82%, so
  0.27pp regression in same class; globally below HWM -9.93%.
- **Verdict**: REVERTED. Branch reset to `ed90e5c`. tcp_state events are not
  hot in stress-bench, so the change is effectively neutral and the code
  complexity isn't justified.
- **Author**: gpt-5.5 / xhigh reasoning

### Iteration 55: Reuse known pid in BPF syscall exit handlers (2026-04-24) — REVERTED
- **Hypothesis**: BPF syscall exit handlers call `bpf_get_current_pid_tgid()`
  a second time when emitting the event, even though the first call's value
  is still available. Passing the PID through avoids a redundant helper call.
- **Change**: `emit_syscall_event` now takes `pid` as a parameter; each exit
  handler passes the PID it already extracted. (commits `8ab5a20`, `58b4848`)
- **Result (new methodology)**: 14.93s vs 16.08s master, CV 0.8%/0.6% —
  **-7.15% vs master** (slow runner). Slow-runner HWM -7.82%, so 0.67pp
  regression. Globally below HWM -9.93%.
- **Verdict**: REVERTED. Branch reset to `30e82b2`. The saved helper call is
  likely swamped by noise since syscall exits already do map lookup+delete.
- **Author**: gpt-5.5 / xhigh reasoning

### Iteration 56: Trust BPF client types in batch parser (2026-04-24) — REVERTED
- **Hypothesis**: `parse_event_into_batch` re-validates every event's
  `client_type` byte even though BPF only emits values we already control.
  Specializing a trusted-BPF variant compiles those bounds checks out of the
  hot path while keeping the public `parse_event` fully validated.
- **Change**: Const-generic `TRUSTED_BPF_CLIENT_TYPES` branch + batch-parser
  wiring. (commits `7a4c926`, `680de37`)
- **Result (new methodology)**: 15.29s vs 16.44s master, CV 0.6%/0.2% —
  **-7.00% vs master** (slow runner). Slow-runner HWM -7.82%, so 0.82pp
  regression. Globally below HWM -9.93%.
- **Verdict**: REVERTED. Branch reset to `040c2b4`.
- **Author**: gpt-5.5 / xhigh reasoning

### Iteration 57: Inline first page-fault aggregate (2026-04-24)
- **Hypothesis**: Stress-bench's mmap path emits page-fault events repeatedly
  for the same pid/client. `page_fault_metrics` still pays a hash/probe for
  each event, unlike the hot syscall and FD maps. Keeping the first
  `BasicDimension -> PageFaultAggregate` entry inline should remove that
  overhead for the dominant single-process workload while preserving exact
  aggregation via a spill map for additional dimensions.
- **Change**: Add `HotBasicPageFaultMap` and use it for page-fault counters.
- **Result (new methodology)**: 8.86s vs 9.97s master, CV 0.4%/0.3% —
  **-11.13% vs master** on fast runner. Beats fast-runner HWM -9.93% by 1.20pp
  (just above noise floor).
- **Verdict**: KEPT. New fast-runner HWM is -11.13%.
- **Commit**: 831accc
- **Author**: gpt-5.5 / xhigh reasoning

### Iteration 58: Inline hot net_io_tx counter (2026-04-24) — REVERTED
- **Hypothesis**: Same dominant-dimension-inline pattern that worked for
  page_fault (iter 57), applied to `net_io_tx` counter map.
- **Change**: New `HotBasicNetTxMap` wrapping a fast-map spill.
  (commits `3405de4`, `4bf6b3a`)
- **Result (new methodology)**: 15.14s vs 16.24s master, CV 0.4%/0.6% —
  **-6.77% vs master** (slow runner). Slow-runner HWM -7.82%, so 1.05pp
  regression. stress-bench is syscall/FD heavy; net events aren't a hot path
  and the extra inline bookkeeping costs more than the saved lookups.
- **Verdict**: REVERTED. Branch reset to `3dd986d`.
- **Author**: gpt-5.5 / xhigh reasoning

### Iteration 59: Primary-only parsed events fast path in batch stats (2026-04-24) — REVERTED
- **Hypothesis**: Only scheduler events emit a secondary accounting event;
  every non-scheduler parser call still pays for the combined/primary+secondary
  shape. Primary-only path skips the secondary bookkeeping.
- **Change**: Parser signals primary-only variant; tracer batch stats fast-
  paths it. (commits `9b44d25`, `a98f65d`)
- **Result (new methodology)**: 14.90s vs 15.91s master, CV 0.4%/0.4% —
  **-6.35% vs master** (slow runner). Slow-runner HWM -7.82%, so 1.47pp
  regression.
- **Verdict**: REVERTED. Branch reset to `47ef5a1`.
- **Author**: gpt-5.5 / xhigh reasoning

### Iteration 60: Split page-fault Major/Minor typed variants (2026-04-24) — REVERTED
- **Hypothesis**: Page-fault events carry a `major` bool and the aggregate
  branches on it inside the hot path. Splitting into `PageFaultMajor` and
  `PageFaultMinor` typed variants lets the sink dispatch directly into the
  specific counter without the per-event branch.
- **Change**: Parser emits split variants; sink wires `add_page_fault_major`
  /`add_page_fault_minor`. (commits `095cc18`, `dce32fa`)
- **Result (new methodology)**: 12.29s vs 13.32s master, CV 0.6%/0.7% —
  **-7.73% vs master** on master=13.32s runner. iter 46 sanity check on
  master=13.30s was -7.82%, so this is essentially tied (-0.09pp, well within
  noise). Strict rule: does not beat HWM.
- **Verdict**: REVERTED. Branch reset to `36e0d0b`.
- **Author**: gpt-5.5 / xhigh reasoning

### Iteration 61: Gate inactive BPF sampling lookup (2026-04-24) — REVERTED
- **Hypothesis**: `event_sampling` map lookup runs on every event even when
  no per-event-type sampling is configured. Short-circuiting via a
  `sampling_enabled` global (set at startup) skips the map lookup on the
  common case.
- **Change**: Add `sampling_enabled` global + gate in BPF; set via
  `EbpfLoader::set_global` based on resolved sampling config.
  (commits `b3fd8e5`, `0d02fe5`)
- **Result (new methodology)**: 12.71s vs 13.71s master, CV 0.6%/0.5% —
  **-7.29% vs master** on medium runner (master ~13.7s). Medium-runner HWM
  is -7.82% (iter 46 sanity, master 13.30s), so 0.53pp regression.
- **Verdict**: REVERTED. Branch reset to `c42daeb`.
- **Author**: gpt-5.5 / xhigh reasoning

### Iteration 62: Indexed major/minor counters in PageFaultAggregate (2026-04-24) — REVERTED
- **Hypothesis**: `PageFaultAggregate` branched on `major` to pick major_count
  vs minor_count field. Indexed `[u32; 2]` removes branch via direct index.
- **Change**: `[u32; 2] counts` + `#[inline(always)]` helper. (commits `1598e2c`,
  `fbabc94`)
- **Result (new methodology)**: 15.00s vs 16.13s master, CV 0.8%/0.3% —
  **-7.01% vs master** (slow runner). HWM -7.82%, so 0.81pp regression.
- **Verdict**: REVERTED. Branch reset to `3b18b2d`.
- **Author**: gpt-5.5 / xhigh reasoning

### Iteration 63: Direct-load compact syscall parser (2026-04-24) — REVERTED
- **Hypothesis**: Compact syscall parser currently copies the packed
  `RawCompactSyscallEvent` via unaligned read, then re-extracts fields.
  Direct-loading the three fields from the byte slice avoids the copy.
- **Change**: Inline u32/u8 decodes from `data[..]` in parse.rs. (commits
  `cba2ce0`, `b42d117`)
- **Result (new methodology)**: 10.95s vs 12.02s master, CV 0.6%/1.3% —
  **-8.90% vs master** on master=12.02s runner (unusual wall time 98s vs
  normal ~35s, base CV 1.3% higher than usual → less trustworthy). Linear
  interpolation of known HWMs predicts neutral ≈ -9.09% at this master time,
  so -8.90% is 0.19pp WORSE than expected neutral — tiny regression within
  noise, does not beat HWM.
- **Verdict**: REVERTED. Branch reset to `5d289dd`.
- **Author**: gpt-5.5 / xhigh reasoning

### Iteration 64: Recycle dropped sink event batches (2026-04-24) — REVERTED
- **Hypothesis**: When the aggregated sink channel is full, the 16k-event
  batch Vec is dropped instead of returning to the batch pool. Recycling
  avoids reallocation churn when backpressure happens.
- **Change**: Call `events.recycle()` on the dropped batch in the try_send
  Err path. (commits `91d9514`, `3bba2d4`)
- **Result (new methodology)**: 15.38s vs 16.65s master, CV 1.0%/0.9% —
  **-7.63% vs master** (slow runner). Slow-runner HWM -7.82%, so 0.19pp
  regression within noise. In stress-bench the sink keeps up so the
  try_send Err path is rarely hit — change is effectively a no-op.
- **Verdict**: REVERTED. Branch reset to `ff26b23`.
- **Author**: gpt-5.5 / xhigh reasoning

### Iteration 65: Word-decode compact 8-byte basic markers (2026-04-24) — REVERTED
- **Hypothesis**: Compact 8-byte FD/page-fault/TCP-state markers are
  currently decoded byte-by-byte. Loading all 8 bytes as a single u64 and
  extracting fields with shifts should be faster on x86.
- **Change**: Single `u64::from_le_bytes` + bit-shift extraction in
  `parse_compact_basic_marker_event`. (commits `abbf1c2`, `29d01fd`)
- **Result (new methodology)**: 14.73s vs 15.85s master, CV 0.4%/0.3% —
  **-7.07% vs master** (slow runner). Slow-runner HWM -7.82%, so 0.75pp
  regression. Compiler probably already does this optimization under the hood.
- **Verdict**: REVERTED. Branch reset to `43d1c66`.
- **Author**: gpt-5.5 / xhigh reasoning

### Iteration 66: Skip basic-dimension mask on non-scheduler events (2026-04-24) — REVERTED
- **Hypothesis**: Only scheduler events pack CPU-id bits above the basic
  dimension key; non-scheduler dispatch can use the raw `basic_dimension` u64
  directly and skip the masking work.
- **Change**: New `non_scheduler_basic_dimension_key()` accessor; sink dispatch
  uses it for non-scheduler branches. (commits `baf22ff`, `eb2d7cd`)
- **Result (new methodology)**: 11.00s vs 12.01s master, CV 0.9%/0.2% —
  **-8.41% vs master** at master=12.01s. Linear interpolation of known HWMs
  predicts neutral ≈ -9.10% at this master time; actual is 0.69pp WORSE.
- **Verdict**: REVERTED. Branch reset to `8821a76`.
- **Author**: gpt-5.5 / xhigh reasoning

### Iteration 67: Inline hot scheduler-wait aggregate (2026-04-24) — REVERTED
- **Hypothesis**: Same dominant-dimension-inline pattern as iter 57 (page_fault),
  applied to `sched_wait` aggregation.
- **Change**: `HotBasicSchedWaitMap` + wiring. (commits `2272a6c`, `eff6637`)
- **Result (new methodology)**: 15.22s vs 16.31s master, CV 0.8%/0.3% —
  **-6.68% vs master** (slow runner). HWM -7.82%, so 1.14pp regression.
- **Verdict**: REVERTED. Branch reset to `ca27702`. Scheduler events are not
  the hot path in stress-bench (syscalls dominate).
- **Author**: gpt-5.5 / xhigh reasoning

### Iteration 68: Pack compact syscall tags 10→9 bytes (2026-04-24) — REVERTED
- **Hypothesis**: Compact syscall records carry event kind and client type
  as separate bytes. Packing both into a single byte (4 bits each) shrinks
  the record 10→9 bytes.
- **Change**: Packed tag byte in BPF emitter + parser decode. (commits
  `f7a5367`, `cfec023`)
- **Result (new methodology, workflow_dispatch as synchronize didn't
  trigger after force-push sequence)**: 15.31s vs 16.68s master, CV
  0.7%/3.2% (base had a 17.92s outlier) — **-8.21% vs master** on slow
  runner. HWM -7.82%, so 0.39pp improvement, within 1-2pp noise floor
  given the elevated base CV.
- **Verdict**: REVERTED. Branch reset to `83f3c55`. Change is probably
  a tiny real win but not detectable above this noise.
- **Author**: gpt-5.5 / xhigh reasoning

### Iteration 69: Shrink page-fault markers 8→7 bytes (2026-04-24)
- **Hypothesis**: `EVENT_PAGE_FAULT` is hot in stress-bench's mmap loop and
  currently shares the generic 8-byte compact marker shape, including one pad
  byte the parser never reads. Emitting a dedicated 7-byte page-fault record
  should shave ring-buffer bandwidth and remove the BPF pad write while keeping
  the legacy 8-byte marker parser as a fallback.
- **Change**: Dedicated 7-byte compact page-fault record in BPF and parser.
- **Result (new methodology)**: 14.71s vs 16.17s master, CV 0.2%/0.6% —
  **-9.03% vs master** on slow runner (master=16.17s). Every prior slow-runner
  attempt after iter 46 landed in -6.35%..-7.63%; iter 69 at -9.03% is
  1.2-2.7pp better than all of them. Clear of the noise floor in
  same-runner-class terms.
- **Verdict**: KEPT. New slow-runner HWM: -9.03%.
- **Commit**: f29a9ba
- **Author**: gpt-5.5 / xhigh reasoning

### Iteration 70: Skip first-sample check on hot inline syscall-latency (2026-04-24) — REVERTED
- **Hypothesis**: After the first syscall, the inline hot-entry
  `LatencyAggregate` is guaranteed non-empty, so subsequent record calls
  don't need the `count == 0` branch that handles the first-sample case.
- **Change**: New `record_nonempty` steady-state path in `LatencyAggregate`;
  inline path uses it after the first sample. (commits `a4b259e`, `dd72169`)
- **Result (new methodology)**: 14.64s vs 16.12s master, CV 0.3%/0.4% —
  **-9.18% vs master** (master=16.12s, same class as iter 69's 16.17s).
  Slow-runner HWM (iter 69) -9.03%, so 0.15pp improvement — within noise.
- **Verdict**: REVERTED. Branch reset to `724975a`.
- **Author**: gpt-5.5 / xhigh reasoning

### Iteration 71: Pack syscall start state in BPF (2026-04-24) — REVERTED
- **Hypothesis**: `syscall_start` BPF map stores `{ts, client_type}` in a
  struct with alignment padding. Packing both into a single u64 should cut
  per-syscall map write/read cost.
- **Change**: `syscall_val.packed = (ts << 8) | client_type` + unpack on exit.
  (commits `1d7fd82`, `c153c3d`)
- **Result (new methodology)**: 14.66s vs 16.00s master, CV 0.5%/0.6% —
  **-8.38% vs master** on slow runner. Slow-runner HWM -9.03%, so 0.65pp
  regression. Packing likely costs more in shifts than the alignment saves.
- **Verdict**: REVERTED. Branch reset to `b926768`.
- **Author**: gpt-5.5 / xhigh reasoning

### Iteration 72: Raw pid_tgid BPF map keys (2026-04-24) — REVERTED
- **Hypothesis**: `syscall_start`/socket maps use `struct { pid_tgid }` keys.
  Using raw `__u64 pid_tgid` directly as the key removes the wrapper.
- **Change**: Maps now key on `__u64`; all lookups/inserts/deletes use
  `pid_tgid` directly. (commits `e8f1634`, `35a9b85`)
- **Result (new methodology)**: 13.93s vs 15.21s master, CV 0.9%/1.2% —
  **-8.42% vs master** at master=15.21s. Interpolation of slow/medium HWMs
  (-7.82% at 13.30s, -9.03% at 16.17s) predicts neutral ≈ -8.63% at 15.21s.
  Actual is 0.21pp worse than neutral — within noise.
- **Verdict**: REVERTED. Branch reset to `cdaeed0`.
- **Author**: gpt-5.5 / xhigh reasoning

### Iteration 73: Drop event tag from compact page-fault records (2026-04-24)
- **Hypothesis**: Page-fault records are already identified by their compact
  record length, so carrying `EVENT_PAGE_FAULT` inside every 7-byte sample is
  redundant. Making the tag implicit should reduce ring-buffer bandwidth and
  parser work on the hot mmap/page-fault path without changing aggregation
  semantics.
- **Change**: Emit 6-byte page-fault records (`pid + client_type + major`) and
  parse the previous 7-byte shape as a legacy fallback.
- **Result (new methodology)**: 9.11s vs 10.40s master, CV 3.5%/0.5% (head had
  one outlier at 9.88s among [9.04, 9.05, 9.11, 9.13, 9.88]) — **-12.40% vs
  master** on fast runner. Fast-runner HWM -11.13% → 1.27pp better (just above
  noise floor). head/master ratio 0.876 vs HWM's 0.889 is a consistent
  improvement across fast runners.
- **Verdict**: KEPT. New fast-runner HWM: -12.40%.
- **Commit**: 32bce1f
- **Author**: gpt-5.5 / xhigh reasoning

### Iteration 74: Compact block-merge records 11→9 bytes (2026-04-25) — REVERTED
- **Hypothesis**: Pack `rw` into the high bit of the client byte and drop
  the event tag (record length identifies `EVENT_BLOCK_MERGE`). 11→9 bytes.
- **Change**: BPF emitter + parser + legacy 11-byte fallback. (commits
  `8cd84b5`, `5fe787f`)
- **Result (new methodology, after one cancelled bench re-dispatch)**: 14.44s
  vs 15.94s master, CV 0.2%/0.2% — **-9.41% vs master** on slow runner.
  Interpolation of slow/medium HWMs predicts neutral ≈ -8.93% at master=15.94s;
  iter 74 at -9.41% is 0.48pp better than neutral — within noise floor.
- **Verdict**: REVERTED. Branch reset to `0abbea5`.
- **Author**: gpt-5.5 / xhigh reasoning

### Iteration 75: Pack major into client byte in page-fault records (2026-04-25) — REVERTED
- **Hypothesis**: 6-byte compact page-fault record still uses a dedicated
  byte for `major`. Packing it into the high bit of the client byte shrinks
  records 6→5 bytes, cutting ring-buffer bandwidth further on mmap-heavy
  workloads.
- **Change**: BPF emitter packs `major << 7 | client_type`; parser unpacks.
  6-byte and 7-byte legacy paths retained. (commits `547eccc`, `13c218a`)
- **Result (new methodology)**: 15.11s vs 16.67s master, CV 0.5%/0.6% —
  **-9.36% vs master** on slow runner. Extrapolating slow HWM (-9.03% at
  16.17s) to master=16.67s predicts neutral ≈ -9.24%; iter 75 at -9.36%
  is only 0.12pp better — well within noise.
- **Verdict**: REVERTED. Branch reset to `fb8a259`.
- **Author**: gpt-5.5 / xhigh reasoning

### Iteration 76: Drop 7-byte page-fault parser fallback (2026-04-25)
- **Hypothesis**: Current BPF emits 6-byte page-fault records, while the older
  8-byte compact marker path still handles marker-style compatibility. The
  intermediate 7-byte fallback from iter 73 is dead on the benchmark hot path,
  but its length check still runs before every syscall/FD/network/disk compact
  parse. Removing it should shave a predictable parser branch from the dominant
  non-page-fault event stream.
- **Change**: Remove the obsolete 7-byte compact page-fault parser fallback.
- **Result**: TBD (CI pending)
- **Verdict**: TBD
- **Commit**: d787318
- **Author**: Codex / gpt-5

---

**NOTE**: Per-iteration deltas above were measured on different CI runners with
different CPU hardware. Absolute CPU times vary ~60% across runs (master has
been seen at 10.14s and 15.98s across two back-to-back runs). The meaningful
signal is HEAD-vs-base on the **same** runner. As of 2026-04-24 the bench runs
5 interleaved base/head pairs plus a discarded warmup, and reports min/max/stdev.

**Runner-class caveat**: the % delta itself appears runner-dependent — iter 46
code measured -11.14% on fast runner (master ~10s) and -7.82% on slow runner
(master ~13s). So cross-iteration comparisons need a runner-class disclaimer
until we get multi-runner medians.

**High-water mark: -12.40%** vs master (iter 73, commit `32bce1f`, fast runner).
**Slow-runner HWM: -9.03%** (iter 69, commit `f29a9ba`, master=16.17s).
**47 kept iterations.**

## Rules

1. Propose exactly ONE change per iteration.
2. The change must be a code modification (not config or benchmark tuning).
3. Do NOT modify files under `bench-cpu/`. You MAY (and should) append your
   iteration entry to `autoresearch/program.md` — include a new
   `### Iteration N:` block under the existing list with:
   - **Hypothesis**: what you expect to improve and why
   - **Change**: one-line summary of the code change
   - **Result**: `TBD (CI pending)` — the orchestrator fills this in
   - **Verdict**: `TBD` — the orchestrator fills this in
   - **Commit**: the short SHA of your commit
4. `cargo test --no-default-features` must pass after your change.
5. Focus on the hot path: ring buffer read → parse → aggregate.
6. Explain your hypothesis in the iteration entry before making the change.
7. The orchestrator (not you) records Result/Verdict after CI benchmark completes.
8. **Keep criterion (orchestrator-enforced)**: an iteration is KEPT only if the
   cumulative delta vs master is *more negative than the current high-water
   mark by more than the noise floor* (~1-2pp on this runner). A delta that
   merely remains negative but worsens the high-water mark is a REGRESSION
   and must be reverted. Review the `High-water mark:` line before comparing.

## In-Scope Code

All code is in scope, including:
- **Rust userspace**: `src/`
- **BPF kernel-side**: `bpf/observoor.c`, `bpf/include/observoor.h`, `bpf/include/maps.h`
