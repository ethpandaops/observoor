# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Observoor is an eBPF-based agent that monitors Ethereum execution and consensus layer processes at the kernel level. It captures syscalls, disk I/O, network I/O, scheduler events, memory faults, and file descriptor activity - aggregated per Ethereum slot and exported to ClickHouse. Zero client modifications required. **Linux only.**

## Build Commands

```bash
# Generate BPF Go bindings (runs bpf2go)
make generate

# Build the binary (includes generate)
make build

# Run tests with race detection
make test

# Run a single test
go test -race -count=1 ./internal/sink/... -run TestBucketFlush

# Lint (new changes only vs origin/master)
make lint

# Clean build artifacts
make clean

# Build Docker image
make docker-build

# E2E testing
make e2e-up      # Start test environment
make e2e-test    # Run E2E tests
make e2e-down    # Tear down
```

**Build Requirements:** Linux with kernel headers and libbpf. BPF compilation requires clang.

## Running

```bash
sudo ./bin/observoor --config config.yaml
```

Root or `CAP_BPF` + `CAP_PERFMON` capabilities required for eBPF program loading.

## Architecture

```
cmd/observoor/main.go    CLI entry point (cobra)
internal/
  agent/                 Top-level orchestrator - coordinates all components
    agent.go            Start/stop lifecycle, PID discovery, event routing
    config.go           YAML configuration loading and validation
    ports.go            Well-known port discovery for Ethereum clients
  tracer/               BPF program management
    tracer.go           Interface definition
    tracer_linux.go     BPF loading, attachment, ring buffer reading
    event.go            Event types (EventType, ClientType, parsed structs)
    gen.go              bpf2go generation directive
  sink/                 Event consumers (pluggable architecture)
    sink.go             Sink interface definition
    raw.go              Writes every event to ClickHouse in batches
    slot.go             Per-slot aggregation
    window.go           Time-window aggregation
    aggregated/         Configurable resolution aggregation
  export/
    clickhouse.go       ClickHouse connection and batch writer
    health.go           Prometheus metrics server
  beacon/               Beacon node client (genesis, spec, sync status)
  clock/                Ethereum wall clock (slot boundaries)
  pid/                  Process discovery (by name or cgroup)
bpf/
  observoor.c           Main eBPF program (syscalls, block I/O, net, sched, etc.)
  include/observoor.h   Event struct definitions (must match Go constants)
  include/maps.h        BPF map definitions
  headers/              vmlinux.h and libbpf helpers
deploy/
  migrations/clickhouse/ Database schema migrations
  kubernetes/           DaemonSet deployment
```

## Data Flow

1. **Agent** fetches genesis/spec from beacon node, waits for sync
2. **PID Discovery** finds Ethereum client processes by name or cgroup
3. **Tracer** loads BPF programs, attaches to tracepoints/kprobes, populates PID map
4. **Ring Buffer** receives events from kernel, parsed in Go
5. **Sinks** consume events: raw (all events), slot (per-slot), window (time-based), aggregated (configurable)
6. **ClickHouse** stores events in batches

## Key Interfaces

**Tracer** (`internal/tracer/tracer.go`):
- `Start(ctx)` - Load BPF, attach hooks, start reading
- `UpdatePIDs(pids, clientTypes)` - Update tracked processes in BPF map
- `OnEvent(handler)` - Register event callback

**Sink** (`internal/sink/sink.go`):
- `HandleEvent(event)` - Process a single event
- `OnSlotChanged(slot, slotStart)` - Called at slot boundaries

## BPF Code Conventions

- Event type constants in `bpf/include/observoor.h` must match `internal/tracer/event.go`
- All event structs use 8-byte alignment with explicit padding
- Event header is 24 bytes: timestamp(8) + pid(4) + tid(4) + type(1) + client(1) + pad(6)

## Supported Clients

**Execution Layer:** Geth, Reth, Besu, Nethermind, Erigon

**Consensus Layer:** Prysm, Lighthouse, Teku, Lodestar, Nimbus

## Event Types

Syscalls: read, write, futex, mmap, epoll_wait, fsync, fdatasync, pwrite
Block I/O: disk_io, block_merge
Network: net_tx, net_rx, tcp_retransmit, tcp_state, tcp_metrics
Scheduler: sched_switch, sched_runqueue
Memory: page_fault, mem_reclaim, mem_compaction, swap_in, swap_out, oom_kill
FD: fd_open, fd_close
Process: process_exit

## ClickHouse Migrations

```bash
migrate -source file://deploy/migrations/clickhouse \
  -database 'clickhouse://localhost:9000/observoor' \
  up
```
