# observoor

eBPF agent that monitors Ethereum execution and consensus layer processes at the kernel level. Captures syscalls, disk I/O, network I/O, scheduler events, memory faults, and file descriptor activity — aggregated per slot and exported via ClickHouse. Zero client modifications required. Linux only.

## Supported Clients

**Execution Layer:** Geth, Reth, Besu, Nethermind, Erigon

**Consensus Layer:** Prysm, Lighthouse, Teku, Lodestar, Nimbus

## Event Types

| Type | Description |
|------|-------------|
| `syscall_read` | read() syscall with latency |
| `syscall_write` | write() syscall with latency |
| `syscall_futex` | futex() syscall with latency |
| `syscall_mmap` | mmap() syscall with latency |
| `syscall_epoll_wait` | epoll_wait() syscall with latency |
| `syscall_fsync` | fsync() syscall with latency |
| `syscall_fdatasync` | fdatasync() syscall with latency |
| `syscall_pwrite` | pwrite64() syscall with latency |
| `disk_io` | Block I/O read/write with latency and byte count |
| `block_merge` | Block I/O request merge |
| `net_tx` | TCP send with byte count and ports |
| `net_rx` | TCP receive with byte count and ports |
| `tcp_retransmit` | TCP retransmission with byte count and ports |
| `tcp_state` | TCP state transition with ports |
| `tcp_metrics` | TCP congestion/RTT metrics (cwnd/srtt) |
| `sched_switch` | Context switch with on-CPU time |
| `sched_runqueue` | Runqueue/off-CPU latency for scheduled threads |
| `page_fault` | Page fault (major/minor) |
| `fd_open` | File descriptor opened |
| `fd_close` | File descriptor closed |
| `mem_reclaim` | Direct reclaim latency |
| `mem_compaction` | Compaction latency |
| `swap_in` | Swap-in event |
| `swap_out` | Swap-out event |
| `oom_kill` | OOM kill event |
| `process_exit` | Process exit with exit code |

## Configuration

```yaml
log_level: info

beacon:
  endpoint: http://localhost:5052
  timeout: 10s

pid:
  process_names:
    - geth
    - lighthouse

ring_buffer_size: 4194304
sync_poll_interval: 30s

sinks:
  raw:
    enabled: true
    clickhouse:
      endpoint: clickhouse:9000
      database: observoor
      table: raw_events
      batch_size: 10000
      flush_interval: 1s
    sample_rate: 1.0
    include_filenames: true

  slot:
    enabled: true

  window:
    enabled: false
    interval: 500ms

health:
  addr: ":9090"
```

## ClickHouse Migrations

Migrations live in `deploy/migrations/clickhouse/` and use [golang-migrate](https://github.com/golang-migrate/migrate) format.

Run with:

```bash
migrate -source file://deploy/migrations/clickhouse \
  -database 'clickhouse://localhost:9000/observoor' \
  up
```

## Building

```bash
# Requires Linux with kernel headers and libbpf
make build
```

## Running

```bash
sudo ./observoor --config config.yaml
```

Root (or `CAP_BPF` + `CAP_PERFMON`) is required for eBPF program loading.
