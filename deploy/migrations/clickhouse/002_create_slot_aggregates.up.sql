CREATE TABLE slot_aggregates_local on cluster '{cluster}' (
    slot UInt64 Codec(DoubleDelta, ZSTD(1)),
    slot_start_date_time DateTime Codec(DoubleDelta, ZSTD(1)),
    pid UInt32 Codec(ZSTD(1)),
    client_type LowCardinality(String),

    -- Syscall counts
    syscall_read_count UInt64 Codec(ZSTD(1)),
    syscall_write_count UInt64 Codec(ZSTD(1)),
    syscall_futex_count UInt64 Codec(ZSTD(1)),
    syscall_mmap_count UInt64 Codec(ZSTD(1)),
    syscall_epoll_wait_count UInt64 Codec(ZSTD(1)),

    -- Syscall bytes
    syscall_read_bytes Int64 Codec(ZSTD(1)),
    syscall_write_bytes Int64 Codec(ZSTD(1)),

    -- Syscall latencies (nanoseconds)
    syscall_read_latency_ns UInt64 Codec(ZSTD(1)),
    syscall_write_latency_ns UInt64 Codec(ZSTD(1)),
    syscall_futex_latency_ns UInt64 Codec(ZSTD(1)),
    syscall_mmap_latency_ns UInt64 Codec(ZSTD(1)),
    syscall_epoll_wait_latency_ns UInt64 Codec(ZSTD(1)),

    -- Disk I/O
    disk_read_count UInt64 Codec(ZSTD(1)),
    disk_write_count UInt64 Codec(ZSTD(1)),
    disk_read_bytes UInt64 Codec(ZSTD(1)),
    disk_write_bytes UInt64 Codec(ZSTD(1)),
    disk_read_latency_ns UInt64 Codec(ZSTD(1)),
    disk_write_latency_ns UInt64 Codec(ZSTD(1)),

    -- Network I/O
    net_tx_count UInt64 Codec(ZSTD(1)),
    net_rx_count UInt64 Codec(ZSTD(1)),
    net_tx_bytes UInt64 Codec(ZSTD(1)),
    net_rx_bytes UInt64 Codec(ZSTD(1)),

    -- Scheduler
    sched_switch_count UInt64 Codec(ZSTD(1)),
    sched_voluntary_count UInt64 Codec(ZSTD(1)),
    sched_involuntary_count UInt64 Codec(ZSTD(1)),
    sched_on_cpu_ns UInt64 Codec(ZSTD(1)),

    -- Memory
    page_fault_count UInt64 Codec(ZSTD(1)),
    page_fault_major_count UInt64 Codec(ZSTD(1)),

    -- File descriptors
    fd_open_count UInt64 Codec(ZSTD(1)),
    fd_close_count UInt64 Codec(ZSTD(1)),

    -- Meta
    meta_node_name LowCardinality(String),
    meta_network_name LowCardinality(String),
    meta_labels Map(String, String) Codec(ZSTD(1))
) Engine = ReplicatedMergeTree('/clickhouse/{installation}/{cluster}/tables/{shard}/{database}/{table}', '{replica}')
PARTITION BY toStartOfMonth(slot_start_date_time)
ORDER BY (slot_start_date_time, meta_network_name, client_type, pid, slot);

ALTER TABLE default.slot_aggregates_local ON CLUSTER '{cluster}'
MODIFY COMMENT 'Per-slot aggregated metrics from eBPF events, one row per slot per process.',
COMMENT COLUMN slot 'Ethereum slot number',
COMMENT COLUMN slot_start_date_time 'Wall clock time when the slot started',
COMMENT COLUMN pid 'Process ID of the traced Ethereum client',
COMMENT COLUMN client_type 'Ethereum client implementation (geth, reth, prysm, lighthouse, etc.)',
COMMENT COLUMN syscall_read_count 'Number of read() syscalls in this slot',
COMMENT COLUMN syscall_write_count 'Number of write() syscalls in this slot',
COMMENT COLUMN syscall_futex_count 'Number of futex() syscalls in this slot',
COMMENT COLUMN syscall_mmap_count 'Number of mmap() syscalls in this slot',
COMMENT COLUMN syscall_epoll_wait_count 'Number of epoll_wait() syscalls in this slot',
COMMENT COLUMN syscall_read_bytes 'Total bytes returned by read() syscalls in this slot',
COMMENT COLUMN syscall_write_bytes 'Total bytes returned by write() syscalls in this slot',
COMMENT COLUMN syscall_read_latency_ns 'Total read() latency in nanoseconds in this slot',
COMMENT COLUMN syscall_write_latency_ns 'Total write() latency in nanoseconds in this slot',
COMMENT COLUMN syscall_futex_latency_ns 'Total futex() latency in nanoseconds in this slot',
COMMENT COLUMN syscall_mmap_latency_ns 'Total mmap() latency in nanoseconds in this slot',
COMMENT COLUMN syscall_epoll_wait_latency_ns 'Total epoll_wait() latency in nanoseconds in this slot',
COMMENT COLUMN disk_read_count 'Number of block I/O reads in this slot',
COMMENT COLUMN disk_write_count 'Number of block I/O writes in this slot',
COMMENT COLUMN disk_read_bytes 'Total bytes read from disk in this slot',
COMMENT COLUMN disk_write_bytes 'Total bytes written to disk in this slot',
COMMENT COLUMN disk_read_latency_ns 'Total disk read latency in nanoseconds in this slot',
COMMENT COLUMN disk_write_latency_ns 'Total disk write latency in nanoseconds in this slot',
COMMENT COLUMN net_tx_count 'Number of TCP sends in this slot',
COMMENT COLUMN net_rx_count 'Number of TCP receives in this slot',
COMMENT COLUMN net_tx_bytes 'Total bytes sent over TCP in this slot',
COMMENT COLUMN net_rx_bytes 'Total bytes received over TCP in this slot',
COMMENT COLUMN sched_switch_count 'Number of context switches in this slot',
COMMENT COLUMN sched_voluntary_count 'Number of voluntary context switches in this slot',
COMMENT COLUMN sched_involuntary_count 'Number of involuntary context switches in this slot',
COMMENT COLUMN sched_on_cpu_ns 'Total on-CPU time in nanoseconds in this slot',
COMMENT COLUMN page_fault_count 'Number of page faults in this slot',
COMMENT COLUMN page_fault_major_count 'Number of major page faults in this slot',
COMMENT COLUMN fd_open_count 'Number of file descriptors opened in this slot',
COMMENT COLUMN fd_close_count 'Number of file descriptors closed in this slot',
COMMENT COLUMN meta_node_name 'Name of the node running the observoor agent',
COMMENT COLUMN meta_network_name 'Ethereum network name (mainnet, holesky, etc.)',
COMMENT COLUMN meta_labels 'Additional labels attached to the event';

CREATE TABLE slot_aggregates on cluster '{cluster}' AS slot_aggregates_local
ENGINE = Distributed('{cluster}', default, slot_aggregates_local, rand());
