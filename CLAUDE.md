# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Observoor is an eBPF-based agent that monitors Ethereum execution and consensus layer processes at the kernel level. It captures syscalls, disk I/O, network I/O, scheduler events, memory faults, and file descriptor activity - aggregated per Ethereum slot and exported to ClickHouse. Zero client modifications required. **Linux only.**

Written in Rust using `aya` for eBPF, `tokio` for async, `axum` for HTTP, and `clickhouse-rs` for native ClickHouse protocol.

## Build Commands

```bash
# Build release binary (BPF compilation via build.rs on Linux)
make build

# Run tests
make test

# Lint (fmt check + clippy)
make lint

# Format code
make fmt

# Clean build artifacts
make clean

# Build Docker image
make docker-build

# E2E testing
make e2e-up      # Start test environment
make e2e-test    # Run E2E tests
make e2e-down    # Tear down
```

**Build Requirements:** Linux with kernel headers, clang, and libbpf for BPF compilation. On macOS, builds with `--no-default-features` (skips BPF).

## Running

```bash
sudo ./target/release/observoor --config config.yaml
```

Root or `CAP_BPF` + `CAP_PERFMON` capabilities required for eBPF program loading.

## Architecture

```
Cargo.toml              Single crate binary
build.rs                BPF C compilation via clang, embeds .o
src/
  main.rs               CLI entry point (clap derive), signal handling, tokio runtime
  config.rs             YAML configuration + validation (serde_yaml)
  agent/
    mod.rs              Top-level orchestrator - startup sequence, monitors
    ports.rs            Well-known port discovery for Ethereum clients
  tracer/
    mod.rs              Tracer trait (Start, Stop, UpdatePIDs, OnEvent)
    event.rs            EventType (1-25), ClientType (0-11), parsed event structs
    bpf.rs              aya: load .o, attach (required vs optional), ring buffer
    parse.rs            Zero-copy event parsing (byte-slice reads)
    stats.rs            Atomic per-event-type counters
  sink/
    mod.rs              Sink trait
    aggregated/
      mod.rs            Event loop, buffer rotation, flush
      config.rs         Resolution, dimensions config
      aggregate.rs      LatencyAggregate, CounterAggregate, GaugeAggregate
      buffer.rs         Per-event-type HashMaps keyed by dimension
      collector.rs      Buffer -> MetricBatch (single pass)
      dimension.rs      BasicDimension, NetworkDimension, DiskDimension
      histogram.rs      10-bucket latency histogram
      metric.rs         MetricBatch, LatencyMetric, CounterMetric, GaugeMetric
      exporter.rs       Exporter enum (ClickHouse | Http)
      clickhouse.rs     ClickHouse batch exporter (native TCP protocol)
      http.rs           HTTP NDJSON exporter (5 compression modes)
  export/
    mod.rs              ClickHouseWriter, connection pool management
    health.rs           Prometheus metrics (40+) + axum server + pprof endpoints
  beacon/
    mod.rs              Beacon node client (genesis, spec, sync status)
  clock/
    mod.rs              Ethereum wall clock (slot timing from genesis)
  pid/
    mod.rs              Composite PID discovery (process name + cgroup)
  migrate/
    mod.rs              Embedded SQL migrations, golang-migrate compatible
bpf/
  observoor.c           Main eBPF program (syscalls, block I/O, net, sched, etc.)
  include/observoor.h   Event struct definitions (must match Rust constants)
  include/maps.h        BPF map definitions
  headers/              vmlinux.h and libbpf helpers
deploy/
  kubernetes/           DaemonSet deployment
```

## Data Flow

1. **Agent** fetches genesis/spec from beacon node, waits for sync
2. **PID Discovery** finds Ethereum client processes by name or cgroup
3. **Tracer** loads BPF programs, attaches to tracepoints/kprobes, populates PID map
4. **Ring Buffer** receives events from kernel, parsed in Rust
5. **Sinks** consume events: aggregated (configurable time windows)
6. **ClickHouse** stores metrics in batches via native TCP protocol

## Key Interfaces

**Tracer** (`src/tracer/mod.rs`):
- `start(cancel)` - Load BPF, attach hooks, start reading
- `update_pids(pids, client_types)` - Update tracked processes in BPF map
- `on_event(handler)` - Register event callback

**Sink** (`src/sink/mod.rs`):
- `handle_event(event)` - Process a single event
- `on_slot_changed(slot, slot_start)` - Called at slot boundaries

**Exporter** (`src/sink/aggregated/exporter.rs`):
- `Exporter::ClickHouse(...)` / `Exporter::Http(...)` - Enum dispatch
- `start(cancel)`, `export(batch)`, `stop()` - Lifecycle methods

## BPF Code Conventions

- Event type constants in `bpf/include/observoor.h` must match `src/tracer/event.rs`
- All event structs use 8-byte alignment with explicit padding
- Event header is 24 bytes: timestamp(8) + pid(4) + tid(4) + type(1) + client(1) + pad(6)

## Supported Clients

**Execution Layer:** Geth, Reth, Besu, Nethermind, Erigon

**Consensus Layer:** Prysm, Lighthouse, Teku, Lodestar, Nimbus

## Event Types

Syscalls: read, write, futex, mmap, epoll_wait, fsync, fdatasync, pwrite
Block I/O: disk_io, block_merge
Network: net_tx, net_rx, tcp_retransmit, tcp_state
Scheduler: sched_switch, sched_runqueue
Memory: page_fault, mem_reclaim, mem_compaction, swap_in, swap_out, oom_kill
FD: fd_open, fd_close
Process: process_exit

## ClickHouse Migrations

Migrations are embedded in the binary (`src/migrate/`) and run when `sinks.aggregated.clickhouse.migrations.enabled` is true. Uses a `schema_migrations` table compatible with golang-migrate.

## Feature Flags

- `bpf` (default) - eBPF support via aya (Linux only)
- `profiling` (default) - pprof CPU profiling endpoints (Linux only)

Build without BPF for macOS development:
```bash
cargo build --no-default-features
cargo test --no-default-features
```
