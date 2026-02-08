-- Observoor ClickHouse Schema
-- Single consolidated migration for all tables

--------------------------------------------------------------------------------
-- SYNC STATE
-- Separate table for consensus/execution layer sync state.
-- Polled periodically (e.g., every slot) to reduce per-row overhead.
--------------------------------------------------------------------------------

CREATE TABLE sync_state_local ON CLUSTER '{cluster}' (
    updated_date_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    event_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    wallclock_slot UInt32 CODEC(DoubleDelta, ZSTD(1)),
    wallclock_slot_start_date_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    cl_syncing Bool CODEC(ZSTD(1)),
    el_optimistic Bool CODEC(ZSTD(1)),
    el_offline Bool CODEC(ZSTD(1)),
    meta_client_name LowCardinality(String),
    meta_network_name LowCardinality(String)
) ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/{installation}/{cluster}/tables/{shard}/{database}/{table}',
    '{replica}',
    updated_date_time
)
PARTITION BY toStartOfMonth(event_time)
ORDER BY (meta_network_name, event_time, meta_client_name);

ALTER TABLE sync_state_local ON CLUSTER '{cluster}'
MODIFY COMMENT 'Sync state snapshots for consensus and execution layers.',
COMMENT COLUMN updated_date_time 'Version column for ReplacingMergeTree deduplication',
COMMENT COLUMN event_time 'Time when the sync state was sampled',
COMMENT COLUMN wallclock_slot 'Ethereum slot number at sampling time',
COMMENT COLUMN wallclock_slot_start_date_time 'Wall clock time when the slot started',
COMMENT COLUMN cl_syncing 'Whether the consensus layer is syncing',
COMMENT COLUMN el_optimistic 'Whether the execution layer is in optimistic sync mode',
COMMENT COLUMN el_offline 'Whether the execution layer is unreachable',
COMMENT COLUMN meta_client_name 'Name of the node running the observoor agent',
COMMENT COLUMN meta_network_name 'Ethereum network name (mainnet, holesky, etc.)';

CREATE TABLE sync_state ON CLUSTER '{cluster}' AS sync_state_local
ENGINE = Distributed('{cluster}', currentDatabase(), sync_state_local, cityHash64(event_time, meta_network_name, meta_client_name));


--------------------------------------------------------------------------------
-- AGGREGATED METRICS: ONE TABLE PER METRIC
-- Time-windowed aggregations. No metric_name column - the table IS the metric.
-- ReplicatedReplacingMergeTree for idempotent writes, ORDER BY as composite key.
--------------------------------------------------------------------------------


--------------------------------------------------------------------------------
-- SYSCALL LATENCY TABLES (8 tables)
-- Latency histograms for system call operations
--------------------------------------------------------------------------------

CREATE TABLE syscall_read_local ON CLUSTER '{cluster}' (
    updated_date_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    window_start DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    interval_ms UInt16 CODEC(ZSTD(1)),
    wallclock_slot UInt32 CODEC(DoubleDelta, ZSTD(1)),
    wallclock_slot_start_date_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    pid UInt32 CODEC(ZSTD(1)),
    client_type LowCardinality(String),
    sum Int64 CODEC(ZSTD(1)),
    count UInt32 CODEC(ZSTD(1)),
    min Int64 CODEC(ZSTD(1)),
    max Int64 CODEC(ZSTD(1)),
    histogram Tuple(
        le_1us UInt32,
        le_10us UInt32,
        le_100us UInt32,
        le_1ms UInt32,
        le_10ms UInt32,
        le_100ms UInt32,
        le_1s UInt32,
        le_10s UInt32,
        le_100s UInt32,
        inf UInt32
    ) CODEC(ZSTD(1)),
    meta_client_name LowCardinality(String),
    meta_network_name LowCardinality(String)
) ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/{installation}/{cluster}/tables/{shard}/{database}/{table}',
    '{replica}',
    updated_date_time
)
PARTITION BY toStartOfMonth(window_start)
ORDER BY (meta_network_name, window_start, meta_client_name, pid, client_type);

CREATE TABLE syscall_read ON CLUSTER '{cluster}' AS syscall_read_local
ENGINE = Distributed('{cluster}', currentDatabase(), syscall_read_local, cityHash64(window_start, meta_network_name, meta_client_name));

CREATE TABLE syscall_write_local ON CLUSTER '{cluster}' (
    updated_date_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    window_start DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    interval_ms UInt16 CODEC(ZSTD(1)),
    wallclock_slot UInt32 CODEC(DoubleDelta, ZSTD(1)),
    wallclock_slot_start_date_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    pid UInt32 CODEC(ZSTD(1)),
    client_type LowCardinality(String),
    sum Int64 CODEC(ZSTD(1)),
    count UInt32 CODEC(ZSTD(1)),
    min Int64 CODEC(ZSTD(1)),
    max Int64 CODEC(ZSTD(1)),
    histogram Tuple(
        le_1us UInt32,
        le_10us UInt32,
        le_100us UInt32,
        le_1ms UInt32,
        le_10ms UInt32,
        le_100ms UInt32,
        le_1s UInt32,
        le_10s UInt32,
        le_100s UInt32,
        inf UInt32
    ) CODEC(ZSTD(1)),
    meta_client_name LowCardinality(String),
    meta_network_name LowCardinality(String)
) ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/{installation}/{cluster}/tables/{shard}/{database}/{table}',
    '{replica}',
    updated_date_time
)
PARTITION BY toStartOfMonth(window_start)
ORDER BY (meta_network_name, window_start, meta_client_name, pid, client_type);

CREATE TABLE syscall_write ON CLUSTER '{cluster}' AS syscall_write_local
ENGINE = Distributed('{cluster}', currentDatabase(), syscall_write_local, cityHash64(window_start, meta_network_name, meta_client_name));

CREATE TABLE syscall_futex_local ON CLUSTER '{cluster}' (
    updated_date_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    window_start DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    interval_ms UInt16 CODEC(ZSTD(1)),
    wallclock_slot UInt32 CODEC(DoubleDelta, ZSTD(1)),
    wallclock_slot_start_date_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    pid UInt32 CODEC(ZSTD(1)),
    client_type LowCardinality(String),
    sum Int64 CODEC(ZSTD(1)),
    count UInt32 CODEC(ZSTD(1)),
    min Int64 CODEC(ZSTD(1)),
    max Int64 CODEC(ZSTD(1)),
    histogram Tuple(
        le_1us UInt32,
        le_10us UInt32,
        le_100us UInt32,
        le_1ms UInt32,
        le_10ms UInt32,
        le_100ms UInt32,
        le_1s UInt32,
        le_10s UInt32,
        le_100s UInt32,
        inf UInt32
    ) CODEC(ZSTD(1)),
    meta_client_name LowCardinality(String),
    meta_network_name LowCardinality(String)
) ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/{installation}/{cluster}/tables/{shard}/{database}/{table}',
    '{replica}',
    updated_date_time
)
PARTITION BY toStartOfMonth(window_start)
ORDER BY (meta_network_name, window_start, meta_client_name, pid, client_type);

CREATE TABLE syscall_futex ON CLUSTER '{cluster}' AS syscall_futex_local
ENGINE = Distributed('{cluster}', currentDatabase(), syscall_futex_local, cityHash64(window_start, meta_network_name, meta_client_name));

CREATE TABLE syscall_mmap_local ON CLUSTER '{cluster}' (
    updated_date_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    window_start DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    interval_ms UInt16 CODEC(ZSTD(1)),
    wallclock_slot UInt32 CODEC(DoubleDelta, ZSTD(1)),
    wallclock_slot_start_date_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    pid UInt32 CODEC(ZSTD(1)),
    client_type LowCardinality(String),
    sum Int64 CODEC(ZSTD(1)),
    count UInt32 CODEC(ZSTD(1)),
    min Int64 CODEC(ZSTD(1)),
    max Int64 CODEC(ZSTD(1)),
    histogram Tuple(
        le_1us UInt32,
        le_10us UInt32,
        le_100us UInt32,
        le_1ms UInt32,
        le_10ms UInt32,
        le_100ms UInt32,
        le_1s UInt32,
        le_10s UInt32,
        le_100s UInt32,
        inf UInt32
    ) CODEC(ZSTD(1)),
    meta_client_name LowCardinality(String),
    meta_network_name LowCardinality(String)
) ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/{installation}/{cluster}/tables/{shard}/{database}/{table}',
    '{replica}',
    updated_date_time
)
PARTITION BY toStartOfMonth(window_start)
ORDER BY (meta_network_name, window_start, meta_client_name, pid, client_type);

CREATE TABLE syscall_mmap ON CLUSTER '{cluster}' AS syscall_mmap_local
ENGINE = Distributed('{cluster}', currentDatabase(), syscall_mmap_local, cityHash64(window_start, meta_network_name, meta_client_name));

CREATE TABLE syscall_epoll_wait_local ON CLUSTER '{cluster}' (
    updated_date_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    window_start DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    interval_ms UInt16 CODEC(ZSTD(1)),
    wallclock_slot UInt32 CODEC(DoubleDelta, ZSTD(1)),
    wallclock_slot_start_date_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    pid UInt32 CODEC(ZSTD(1)),
    client_type LowCardinality(String),
    sum Int64 CODEC(ZSTD(1)),
    count UInt32 CODEC(ZSTD(1)),
    min Int64 CODEC(ZSTD(1)),
    max Int64 CODEC(ZSTD(1)),
    histogram Tuple(
        le_1us UInt32,
        le_10us UInt32,
        le_100us UInt32,
        le_1ms UInt32,
        le_10ms UInt32,
        le_100ms UInt32,
        le_1s UInt32,
        le_10s UInt32,
        le_100s UInt32,
        inf UInt32
    ) CODEC(ZSTD(1)),
    meta_client_name LowCardinality(String),
    meta_network_name LowCardinality(String)
) ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/{installation}/{cluster}/tables/{shard}/{database}/{table}',
    '{replica}',
    updated_date_time
)
PARTITION BY toStartOfMonth(window_start)
ORDER BY (meta_network_name, window_start, meta_client_name, pid, client_type);

CREATE TABLE syscall_epoll_wait ON CLUSTER '{cluster}' AS syscall_epoll_wait_local
ENGINE = Distributed('{cluster}', currentDatabase(), syscall_epoll_wait_local, cityHash64(window_start, meta_network_name, meta_client_name));

CREATE TABLE syscall_fsync_local ON CLUSTER '{cluster}' (
    updated_date_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    window_start DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    interval_ms UInt16 CODEC(ZSTD(1)),
    wallclock_slot UInt32 CODEC(DoubleDelta, ZSTD(1)),
    wallclock_slot_start_date_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    pid UInt32 CODEC(ZSTD(1)),
    client_type LowCardinality(String),
    sum Int64 CODEC(ZSTD(1)),
    count UInt32 CODEC(ZSTD(1)),
    min Int64 CODEC(ZSTD(1)),
    max Int64 CODEC(ZSTD(1)),
    histogram Tuple(
        le_1us UInt32,
        le_10us UInt32,
        le_100us UInt32,
        le_1ms UInt32,
        le_10ms UInt32,
        le_100ms UInt32,
        le_1s UInt32,
        le_10s UInt32,
        le_100s UInt32,
        inf UInt32
    ) CODEC(ZSTD(1)),
    meta_client_name LowCardinality(String),
    meta_network_name LowCardinality(String)
) ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/{installation}/{cluster}/tables/{shard}/{database}/{table}',
    '{replica}',
    updated_date_time
)
PARTITION BY toStartOfMonth(window_start)
ORDER BY (meta_network_name, window_start, meta_client_name, pid, client_type);

CREATE TABLE syscall_fsync ON CLUSTER '{cluster}' AS syscall_fsync_local
ENGINE = Distributed('{cluster}', currentDatabase(), syscall_fsync_local, cityHash64(window_start, meta_network_name, meta_client_name));

CREATE TABLE syscall_fdatasync_local ON CLUSTER '{cluster}' (
    updated_date_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    window_start DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    interval_ms UInt16 CODEC(ZSTD(1)),
    wallclock_slot UInt32 CODEC(DoubleDelta, ZSTD(1)),
    wallclock_slot_start_date_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    pid UInt32 CODEC(ZSTD(1)),
    client_type LowCardinality(String),
    sum Int64 CODEC(ZSTD(1)),
    count UInt32 CODEC(ZSTD(1)),
    min Int64 CODEC(ZSTD(1)),
    max Int64 CODEC(ZSTD(1)),
    histogram Tuple(
        le_1us UInt32,
        le_10us UInt32,
        le_100us UInt32,
        le_1ms UInt32,
        le_10ms UInt32,
        le_100ms UInt32,
        le_1s UInt32,
        le_10s UInt32,
        le_100s UInt32,
        inf UInt32
    ) CODEC(ZSTD(1)),
    meta_client_name LowCardinality(String),
    meta_network_name LowCardinality(String)
) ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/{installation}/{cluster}/tables/{shard}/{database}/{table}',
    '{replica}',
    updated_date_time
)
PARTITION BY toStartOfMonth(window_start)
ORDER BY (meta_network_name, window_start, meta_client_name, pid, client_type);

CREATE TABLE syscall_fdatasync ON CLUSTER '{cluster}' AS syscall_fdatasync_local
ENGINE = Distributed('{cluster}', currentDatabase(), syscall_fdatasync_local, cityHash64(window_start, meta_network_name, meta_client_name));

CREATE TABLE syscall_pwrite_local ON CLUSTER '{cluster}' (
    updated_date_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    window_start DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    interval_ms UInt16 CODEC(ZSTD(1)),
    wallclock_slot UInt32 CODEC(DoubleDelta, ZSTD(1)),
    wallclock_slot_start_date_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    pid UInt32 CODEC(ZSTD(1)),
    client_type LowCardinality(String),
    sum Int64 CODEC(ZSTD(1)),
    count UInt32 CODEC(ZSTD(1)),
    min Int64 CODEC(ZSTD(1)),
    max Int64 CODEC(ZSTD(1)),
    histogram Tuple(
        le_1us UInt32,
        le_10us UInt32,
        le_100us UInt32,
        le_1ms UInt32,
        le_10ms UInt32,
        le_100ms UInt32,
        le_1s UInt32,
        le_10s UInt32,
        le_100s UInt32,
        inf UInt32
    ) CODEC(ZSTD(1)),
    meta_client_name LowCardinality(String),
    meta_network_name LowCardinality(String)
) ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/{installation}/{cluster}/tables/{shard}/{database}/{table}',
    '{replica}',
    updated_date_time
)
PARTITION BY toStartOfMonth(window_start)
ORDER BY (meta_network_name, window_start, meta_client_name, pid, client_type);

CREATE TABLE syscall_pwrite ON CLUSTER '{cluster}' AS syscall_pwrite_local
ENGINE = Distributed('{cluster}', currentDatabase(), syscall_pwrite_local, cityHash64(window_start, meta_network_name, meta_client_name));


--------------------------------------------------------------------------------
-- SCHEDULER LATENCY TABLES (3 tables)
-- CPU scheduling latency histograms
--------------------------------------------------------------------------------

CREATE TABLE sched_on_cpu_local ON CLUSTER '{cluster}' (
    updated_date_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    window_start DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    interval_ms UInt16 CODEC(ZSTD(1)),
    wallclock_slot UInt32 CODEC(DoubleDelta, ZSTD(1)),
    wallclock_slot_start_date_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    pid UInt32 CODEC(ZSTD(1)),
    client_type LowCardinality(String),
    sum Int64 CODEC(ZSTD(1)),
    count UInt32 CODEC(ZSTD(1)),
    min Int64 CODEC(ZSTD(1)),
    max Int64 CODEC(ZSTD(1)),
    histogram Tuple(
        le_1us UInt32,
        le_10us UInt32,
        le_100us UInt32,
        le_1ms UInt32,
        le_10ms UInt32,
        le_100ms UInt32,
        le_1s UInt32,
        le_10s UInt32,
        le_100s UInt32,
        inf UInt32
    ) CODEC(ZSTD(1)),
    meta_client_name LowCardinality(String),
    meta_network_name LowCardinality(String)
) ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/{installation}/{cluster}/tables/{shard}/{database}/{table}',
    '{replica}',
    updated_date_time
)
PARTITION BY toStartOfMonth(window_start)
ORDER BY (meta_network_name, window_start, meta_client_name, pid, client_type);

CREATE TABLE sched_on_cpu ON CLUSTER '{cluster}' AS sched_on_cpu_local
ENGINE = Distributed('{cluster}', currentDatabase(), sched_on_cpu_local, cityHash64(window_start, meta_network_name, meta_client_name));

CREATE TABLE sched_off_cpu_local ON CLUSTER '{cluster}' (
    updated_date_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    window_start DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    interval_ms UInt16 CODEC(ZSTD(1)),
    wallclock_slot UInt32 CODEC(DoubleDelta, ZSTD(1)),
    wallclock_slot_start_date_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    pid UInt32 CODEC(ZSTD(1)),
    client_type LowCardinality(String),
    sum Int64 CODEC(ZSTD(1)),
    count UInt32 CODEC(ZSTD(1)),
    min Int64 CODEC(ZSTD(1)),
    max Int64 CODEC(ZSTD(1)),
    histogram Tuple(
        le_1us UInt32,
        le_10us UInt32,
        le_100us UInt32,
        le_1ms UInt32,
        le_10ms UInt32,
        le_100ms UInt32,
        le_1s UInt32,
        le_10s UInt32,
        le_100s UInt32,
        inf UInt32
    ) CODEC(ZSTD(1)),
    meta_client_name LowCardinality(String),
    meta_network_name LowCardinality(String)
) ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/{installation}/{cluster}/tables/{shard}/{database}/{table}',
    '{replica}',
    updated_date_time
)
PARTITION BY toStartOfMonth(window_start)
ORDER BY (meta_network_name, window_start, meta_client_name, pid, client_type);

CREATE TABLE sched_off_cpu ON CLUSTER '{cluster}' AS sched_off_cpu_local
ENGINE = Distributed('{cluster}', currentDatabase(), sched_off_cpu_local, cityHash64(window_start, meta_network_name, meta_client_name));

CREATE TABLE sched_runqueue_local ON CLUSTER '{cluster}' (
    updated_date_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    window_start DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    interval_ms UInt16 CODEC(ZSTD(1)),
    wallclock_slot UInt32 CODEC(DoubleDelta, ZSTD(1)),
    wallclock_slot_start_date_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    pid UInt32 CODEC(ZSTD(1)),
    client_type LowCardinality(String),
    sum Int64 CODEC(ZSTD(1)),
    count UInt32 CODEC(ZSTD(1)),
    min Int64 CODEC(ZSTD(1)),
    max Int64 CODEC(ZSTD(1)),
    histogram Tuple(
        le_1us UInt32,
        le_10us UInt32,
        le_100us UInt32,
        le_1ms UInt32,
        le_10ms UInt32,
        le_100ms UInt32,
        le_1s UInt32,
        le_10s UInt32,
        le_100s UInt32,
        inf UInt32
    ) CODEC(ZSTD(1)),
    meta_client_name LowCardinality(String),
    meta_network_name LowCardinality(String)
) ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/{installation}/{cluster}/tables/{shard}/{database}/{table}',
    '{replica}',
    updated_date_time
)
PARTITION BY toStartOfMonth(window_start)
ORDER BY (meta_network_name, window_start, meta_client_name, pid, client_type);

CREATE TABLE sched_runqueue ON CLUSTER '{cluster}' AS sched_runqueue_local
ENGINE = Distributed('{cluster}', currentDatabase(), sched_runqueue_local, cityHash64(window_start, meta_network_name, meta_client_name));


--------------------------------------------------------------------------------
-- MEMORY LATENCY TABLES (2 tables)
-- Memory reclaim and compaction latency histograms
--------------------------------------------------------------------------------

CREATE TABLE mem_reclaim_local ON CLUSTER '{cluster}' (
    updated_date_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    window_start DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    interval_ms UInt16 CODEC(ZSTD(1)),
    wallclock_slot UInt32 CODEC(DoubleDelta, ZSTD(1)),
    wallclock_slot_start_date_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    pid UInt32 CODEC(ZSTD(1)),
    client_type LowCardinality(String),
    sum Int64 CODEC(ZSTD(1)),
    count UInt32 CODEC(ZSTD(1)),
    min Int64 CODEC(ZSTD(1)),
    max Int64 CODEC(ZSTD(1)),
    histogram Tuple(
        le_1us UInt32,
        le_10us UInt32,
        le_100us UInt32,
        le_1ms UInt32,
        le_10ms UInt32,
        le_100ms UInt32,
        le_1s UInt32,
        le_10s UInt32,
        le_100s UInt32,
        inf UInt32
    ) CODEC(ZSTD(1)),
    meta_client_name LowCardinality(String),
    meta_network_name LowCardinality(String)
) ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/{installation}/{cluster}/tables/{shard}/{database}/{table}',
    '{replica}',
    updated_date_time
)
PARTITION BY toStartOfMonth(window_start)
ORDER BY (meta_network_name, window_start, meta_client_name, pid, client_type);

CREATE TABLE mem_reclaim ON CLUSTER '{cluster}' AS mem_reclaim_local
ENGINE = Distributed('{cluster}', currentDatabase(), mem_reclaim_local, cityHash64(window_start, meta_network_name, meta_client_name));

CREATE TABLE mem_compaction_local ON CLUSTER '{cluster}' (
    updated_date_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    window_start DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    interval_ms UInt16 CODEC(ZSTD(1)),
    wallclock_slot UInt32 CODEC(DoubleDelta, ZSTD(1)),
    wallclock_slot_start_date_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    pid UInt32 CODEC(ZSTD(1)),
    client_type LowCardinality(String),
    sum Int64 CODEC(ZSTD(1)),
    count UInt32 CODEC(ZSTD(1)),
    min Int64 CODEC(ZSTD(1)),
    max Int64 CODEC(ZSTD(1)),
    histogram Tuple(
        le_1us UInt32,
        le_10us UInt32,
        le_100us UInt32,
        le_1ms UInt32,
        le_10ms UInt32,
        le_100ms UInt32,
        le_1s UInt32,
        le_10s UInt32,
        le_100s UInt32,
        inf UInt32
    ) CODEC(ZSTD(1)),
    meta_client_name LowCardinality(String),
    meta_network_name LowCardinality(String)
) ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/{installation}/{cluster}/tables/{shard}/{database}/{table}',
    '{replica}',
    updated_date_time
)
PARTITION BY toStartOfMonth(window_start)
ORDER BY (meta_network_name, window_start, meta_client_name, pid, client_type);

CREATE TABLE mem_compaction ON CLUSTER '{cluster}' AS mem_compaction_local
ENGINE = Distributed('{cluster}', currentDatabase(), mem_compaction_local, cityHash64(window_start, meta_network_name, meta_client_name));


--------------------------------------------------------------------------------
-- DISK LATENCY TABLE (1 table)
-- Block I/O latency histogram with device and rw dimensions
--------------------------------------------------------------------------------

CREATE TABLE disk_latency_local ON CLUSTER '{cluster}' (
    updated_date_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    window_start DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    interval_ms UInt16 CODEC(ZSTD(1)),
    wallclock_slot UInt32 CODEC(DoubleDelta, ZSTD(1)),
    wallclock_slot_start_date_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    pid UInt32 CODEC(ZSTD(1)),
    client_type LowCardinality(String),
    device_id UInt32 CODEC(ZSTD(1)),
    rw LowCardinality(String),
    sum Int64 CODEC(ZSTD(1)),
    count UInt32 CODEC(ZSTD(1)),
    min Int64 CODEC(ZSTD(1)),
    max Int64 CODEC(ZSTD(1)),
    histogram Tuple(
        le_1us UInt32,
        le_10us UInt32,
        le_100us UInt32,
        le_1ms UInt32,
        le_10ms UInt32,
        le_100ms UInt32,
        le_1s UInt32,
        le_10s UInt32,
        le_100s UInt32,
        inf UInt32
    ) CODEC(ZSTD(1)),
    meta_client_name LowCardinality(String),
    meta_network_name LowCardinality(String)
) ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/{installation}/{cluster}/tables/{shard}/{database}/{table}',
    '{replica}',
    updated_date_time
)
PARTITION BY toStartOfMonth(window_start)
ORDER BY (meta_network_name, window_start, meta_client_name, pid, client_type, device_id, rw);

CREATE TABLE disk_latency ON CLUSTER '{cluster}' AS disk_latency_local
ENGINE = Distributed('{cluster}', currentDatabase(), disk_latency_local, cityHash64(window_start, meta_network_name, meta_client_name));


--------------------------------------------------------------------------------
-- COUNTER TABLES - MEMORY (5 tables)
-- Simple count/sum aggregations for memory events
--------------------------------------------------------------------------------

CREATE TABLE page_fault_major_local ON CLUSTER '{cluster}' (
    updated_date_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    window_start DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    interval_ms UInt16 CODEC(ZSTD(1)),
    wallclock_slot UInt32 CODEC(DoubleDelta, ZSTD(1)),
    wallclock_slot_start_date_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    pid UInt32 CODEC(ZSTD(1)),
    client_type LowCardinality(String),
    sum Int64 CODEC(ZSTD(1)),
    count UInt32 CODEC(ZSTD(1)),
    meta_client_name LowCardinality(String),
    meta_network_name LowCardinality(String)
) ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/{installation}/{cluster}/tables/{shard}/{database}/{table}',
    '{replica}',
    updated_date_time
)
PARTITION BY toStartOfMonth(window_start)
ORDER BY (meta_network_name, window_start, meta_client_name, pid, client_type);

CREATE TABLE page_fault_major ON CLUSTER '{cluster}' AS page_fault_major_local
ENGINE = Distributed('{cluster}', currentDatabase(), page_fault_major_local, cityHash64(window_start, meta_network_name, meta_client_name));

CREATE TABLE page_fault_minor_local ON CLUSTER '{cluster}' (
    updated_date_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    window_start DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    interval_ms UInt16 CODEC(ZSTD(1)),
    wallclock_slot UInt32 CODEC(DoubleDelta, ZSTD(1)),
    wallclock_slot_start_date_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    pid UInt32 CODEC(ZSTD(1)),
    client_type LowCardinality(String),
    sum Int64 CODEC(ZSTD(1)),
    count UInt32 CODEC(ZSTD(1)),
    meta_client_name LowCardinality(String),
    meta_network_name LowCardinality(String)
) ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/{installation}/{cluster}/tables/{shard}/{database}/{table}',
    '{replica}',
    updated_date_time
)
PARTITION BY toStartOfMonth(window_start)
ORDER BY (meta_network_name, window_start, meta_client_name, pid, client_type);

CREATE TABLE page_fault_minor ON CLUSTER '{cluster}' AS page_fault_minor_local
ENGINE = Distributed('{cluster}', currentDatabase(), page_fault_minor_local, cityHash64(window_start, meta_network_name, meta_client_name));

CREATE TABLE swap_in_local ON CLUSTER '{cluster}' (
    updated_date_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    window_start DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    interval_ms UInt16 CODEC(ZSTD(1)),
    wallclock_slot UInt32 CODEC(DoubleDelta, ZSTD(1)),
    wallclock_slot_start_date_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    pid UInt32 CODEC(ZSTD(1)),
    client_type LowCardinality(String),
    sum Int64 CODEC(ZSTD(1)),
    count UInt32 CODEC(ZSTD(1)),
    meta_client_name LowCardinality(String),
    meta_network_name LowCardinality(String)
) ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/{installation}/{cluster}/tables/{shard}/{database}/{table}',
    '{replica}',
    updated_date_time
)
PARTITION BY toStartOfMonth(window_start)
ORDER BY (meta_network_name, window_start, meta_client_name, pid, client_type);

CREATE TABLE swap_in ON CLUSTER '{cluster}' AS swap_in_local
ENGINE = Distributed('{cluster}', currentDatabase(), swap_in_local, cityHash64(window_start, meta_network_name, meta_client_name));

CREATE TABLE swap_out_local ON CLUSTER '{cluster}' (
    updated_date_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    window_start DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    interval_ms UInt16 CODEC(ZSTD(1)),
    wallclock_slot UInt32 CODEC(DoubleDelta, ZSTD(1)),
    wallclock_slot_start_date_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    pid UInt32 CODEC(ZSTD(1)),
    client_type LowCardinality(String),
    sum Int64 CODEC(ZSTD(1)),
    count UInt32 CODEC(ZSTD(1)),
    meta_client_name LowCardinality(String),
    meta_network_name LowCardinality(String)
) ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/{installation}/{cluster}/tables/{shard}/{database}/{table}',
    '{replica}',
    updated_date_time
)
PARTITION BY toStartOfMonth(window_start)
ORDER BY (meta_network_name, window_start, meta_client_name, pid, client_type);

CREATE TABLE swap_out ON CLUSTER '{cluster}' AS swap_out_local
ENGINE = Distributed('{cluster}', currentDatabase(), swap_out_local, cityHash64(window_start, meta_network_name, meta_client_name));

CREATE TABLE oom_kill_local ON CLUSTER '{cluster}' (
    updated_date_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    window_start DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    interval_ms UInt16 CODEC(ZSTD(1)),
    wallclock_slot UInt32 CODEC(DoubleDelta, ZSTD(1)),
    wallclock_slot_start_date_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    pid UInt32 CODEC(ZSTD(1)),
    client_type LowCardinality(String),
    sum Int64 CODEC(ZSTD(1)),
    count UInt32 CODEC(ZSTD(1)),
    meta_client_name LowCardinality(String),
    meta_network_name LowCardinality(String)
) ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/{installation}/{cluster}/tables/{shard}/{database}/{table}',
    '{replica}',
    updated_date_time
)
PARTITION BY toStartOfMonth(window_start)
ORDER BY (meta_network_name, window_start, meta_client_name, pid, client_type);

CREATE TABLE oom_kill ON CLUSTER '{cluster}' AS oom_kill_local
ENGINE = Distributed('{cluster}', currentDatabase(), oom_kill_local, cityHash64(window_start, meta_network_name, meta_client_name));


--------------------------------------------------------------------------------
-- COUNTER TABLES - PROCESS (3 tables)
-- File descriptor and process exit counters
--------------------------------------------------------------------------------

CREATE TABLE fd_open_local ON CLUSTER '{cluster}' (
    updated_date_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    window_start DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    interval_ms UInt16 CODEC(ZSTD(1)),
    wallclock_slot UInt32 CODEC(DoubleDelta, ZSTD(1)),
    wallclock_slot_start_date_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    pid UInt32 CODEC(ZSTD(1)),
    client_type LowCardinality(String),
    sum Int64 CODEC(ZSTD(1)),
    count UInt32 CODEC(ZSTD(1)),
    meta_client_name LowCardinality(String),
    meta_network_name LowCardinality(String)
) ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/{installation}/{cluster}/tables/{shard}/{database}/{table}',
    '{replica}',
    updated_date_time
)
PARTITION BY toStartOfMonth(window_start)
ORDER BY (meta_network_name, window_start, meta_client_name, pid, client_type);

CREATE TABLE fd_open ON CLUSTER '{cluster}' AS fd_open_local
ENGINE = Distributed('{cluster}', currentDatabase(), fd_open_local, cityHash64(window_start, meta_network_name, meta_client_name));

CREATE TABLE fd_close_local ON CLUSTER '{cluster}' (
    updated_date_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    window_start DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    interval_ms UInt16 CODEC(ZSTD(1)),
    wallclock_slot UInt32 CODEC(DoubleDelta, ZSTD(1)),
    wallclock_slot_start_date_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    pid UInt32 CODEC(ZSTD(1)),
    client_type LowCardinality(String),
    sum Int64 CODEC(ZSTD(1)),
    count UInt32 CODEC(ZSTD(1)),
    meta_client_name LowCardinality(String),
    meta_network_name LowCardinality(String)
) ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/{installation}/{cluster}/tables/{shard}/{database}/{table}',
    '{replica}',
    updated_date_time
)
PARTITION BY toStartOfMonth(window_start)
ORDER BY (meta_network_name, window_start, meta_client_name, pid, client_type);

CREATE TABLE fd_close ON CLUSTER '{cluster}' AS fd_close_local
ENGINE = Distributed('{cluster}', currentDatabase(), fd_close_local, cityHash64(window_start, meta_network_name, meta_client_name));

CREATE TABLE process_exit_local ON CLUSTER '{cluster}' (
    updated_date_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    window_start DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    interval_ms UInt16 CODEC(ZSTD(1)),
    wallclock_slot UInt32 CODEC(DoubleDelta, ZSTD(1)),
    wallclock_slot_start_date_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    pid UInt32 CODEC(ZSTD(1)),
    client_type LowCardinality(String),
    sum Int64 CODEC(ZSTD(1)),
    count UInt32 CODEC(ZSTD(1)),
    meta_client_name LowCardinality(String),
    meta_network_name LowCardinality(String)
) ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/{installation}/{cluster}/tables/{shard}/{database}/{table}',
    '{replica}',
    updated_date_time
)
PARTITION BY toStartOfMonth(window_start)
ORDER BY (meta_network_name, window_start, meta_client_name, pid, client_type);

CREATE TABLE process_exit ON CLUSTER '{cluster}' AS process_exit_local
ENGINE = Distributed('{cluster}', currentDatabase(), process_exit_local, cityHash64(window_start, meta_network_name, meta_client_name));


--------------------------------------------------------------------------------
-- COUNTER TABLES - NETWORK (3 tables)
-- TCP state changes, network I/O, and retransmits
--------------------------------------------------------------------------------

CREATE TABLE tcp_state_change_local ON CLUSTER '{cluster}' (
    updated_date_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    window_start DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    interval_ms UInt16 CODEC(ZSTD(1)),
    wallclock_slot UInt32 CODEC(DoubleDelta, ZSTD(1)),
    wallclock_slot_start_date_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    pid UInt32 CODEC(ZSTD(1)),
    client_type LowCardinality(String),
    sum Int64 CODEC(ZSTD(1)),
    count UInt32 CODEC(ZSTD(1)),
    meta_client_name LowCardinality(String),
    meta_network_name LowCardinality(String)
) ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/{installation}/{cluster}/tables/{shard}/{database}/{table}',
    '{replica}',
    updated_date_time
)
PARTITION BY toStartOfMonth(window_start)
ORDER BY (meta_network_name, window_start, meta_client_name, pid, client_type);

CREATE TABLE tcp_state_change ON CLUSTER '{cluster}' AS tcp_state_change_local
ENGINE = Distributed('{cluster}', currentDatabase(), tcp_state_change_local, cityHash64(window_start, meta_network_name, meta_client_name));

CREATE TABLE net_io_local ON CLUSTER '{cluster}' (
    updated_date_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    window_start DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    interval_ms UInt16 CODEC(ZSTD(1)),
    wallclock_slot UInt32 CODEC(DoubleDelta, ZSTD(1)),
    wallclock_slot_start_date_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    pid UInt32 CODEC(ZSTD(1)),
    client_type LowCardinality(String),
    local_port UInt16 CODEC(ZSTD(1)),
    direction LowCardinality(String),
    sum Int64 CODEC(ZSTD(1)),
    count UInt32 CODEC(ZSTD(1)),
    meta_client_name LowCardinality(String),
    meta_network_name LowCardinality(String)
) ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/{installation}/{cluster}/tables/{shard}/{database}/{table}',
    '{replica}',
    updated_date_time
)
PARTITION BY toStartOfMonth(window_start)
ORDER BY (meta_network_name, window_start, meta_client_name, pid, client_type, local_port, direction);

CREATE TABLE net_io ON CLUSTER '{cluster}' AS net_io_local
ENGINE = Distributed('{cluster}', currentDatabase(), net_io_local, cityHash64(window_start, meta_network_name, meta_client_name));

CREATE TABLE tcp_retransmit_local ON CLUSTER '{cluster}' (
    updated_date_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    window_start DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    interval_ms UInt16 CODEC(ZSTD(1)),
    wallclock_slot UInt32 CODEC(DoubleDelta, ZSTD(1)),
    wallclock_slot_start_date_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    pid UInt32 CODEC(ZSTD(1)),
    client_type LowCardinality(String),
    local_port UInt16 CODEC(ZSTD(1)),
    direction LowCardinality(String),
    sum Int64 CODEC(ZSTD(1)),
    count UInt32 CODEC(ZSTD(1)),
    meta_client_name LowCardinality(String),
    meta_network_name LowCardinality(String)
) ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/{installation}/{cluster}/tables/{shard}/{database}/{table}',
    '{replica}',
    updated_date_time
)
PARTITION BY toStartOfMonth(window_start)
ORDER BY (meta_network_name, window_start, meta_client_name, pid, client_type, local_port, direction);

CREATE TABLE tcp_retransmit ON CLUSTER '{cluster}' AS tcp_retransmit_local
ENGINE = Distributed('{cluster}', currentDatabase(), tcp_retransmit_local, cityHash64(window_start, meta_network_name, meta_client_name));


--------------------------------------------------------------------------------
-- COUNTER TABLES - DISK (2 tables)
-- Disk bytes throughput and block merge counters
--------------------------------------------------------------------------------

CREATE TABLE disk_bytes_local ON CLUSTER '{cluster}' (
    updated_date_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    window_start DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    interval_ms UInt16 CODEC(ZSTD(1)),
    wallclock_slot UInt32 CODEC(DoubleDelta, ZSTD(1)),
    wallclock_slot_start_date_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    pid UInt32 CODEC(ZSTD(1)),
    client_type LowCardinality(String),
    device_id UInt32 CODEC(ZSTD(1)),
    rw LowCardinality(String),
    sum Int64 CODEC(ZSTD(1)),
    count UInt32 CODEC(ZSTD(1)),
    meta_client_name LowCardinality(String),
    meta_network_name LowCardinality(String)
) ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/{installation}/{cluster}/tables/{shard}/{database}/{table}',
    '{replica}',
    updated_date_time
)
PARTITION BY toStartOfMonth(window_start)
ORDER BY (meta_network_name, window_start, meta_client_name, pid, client_type, device_id, rw);

CREATE TABLE disk_bytes ON CLUSTER '{cluster}' AS disk_bytes_local
ENGINE = Distributed('{cluster}', currentDatabase(), disk_bytes_local, cityHash64(window_start, meta_network_name, meta_client_name));

CREATE TABLE block_merge_local ON CLUSTER '{cluster}' (
    updated_date_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    window_start DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    interval_ms UInt16 CODEC(ZSTD(1)),
    wallclock_slot UInt32 CODEC(DoubleDelta, ZSTD(1)),
    wallclock_slot_start_date_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    pid UInt32 CODEC(ZSTD(1)),
    client_type LowCardinality(String),
    device_id UInt32 CODEC(ZSTD(1)),
    rw LowCardinality(String),
    sum Int64 CODEC(ZSTD(1)),
    count UInt32 CODEC(ZSTD(1)),
    meta_client_name LowCardinality(String),
    meta_network_name LowCardinality(String)
) ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/{installation}/{cluster}/tables/{shard}/{database}/{table}',
    '{replica}',
    updated_date_time
)
PARTITION BY toStartOfMonth(window_start)
ORDER BY (meta_network_name, window_start, meta_client_name, pid, client_type, device_id, rw);

CREATE TABLE block_merge ON CLUSTER '{cluster}' AS block_merge_local
ENGINE = Distributed('{cluster}', currentDatabase(), block_merge_local, cityHash64(window_start, meta_network_name, meta_client_name));


--------------------------------------------------------------------------------
-- GAUGE TABLES (3 tables)
-- Sampled values with min/max/sum/count (no histogram)
--------------------------------------------------------------------------------

CREATE TABLE tcp_rtt_local ON CLUSTER '{cluster}' (
    updated_date_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    window_start DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    interval_ms UInt16 CODEC(ZSTD(1)),
    wallclock_slot UInt32 CODEC(DoubleDelta, ZSTD(1)),
    wallclock_slot_start_date_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    pid UInt32 CODEC(ZSTD(1)),
    client_type LowCardinality(String),
    local_port UInt16 CODEC(ZSTD(1)),
    sum Int64 CODEC(ZSTD(1)),
    count UInt32 CODEC(ZSTD(1)),
    min Int64 CODEC(ZSTD(1)),
    max Int64 CODEC(ZSTD(1)),
    meta_client_name LowCardinality(String),
    meta_network_name LowCardinality(String)
) ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/{installation}/{cluster}/tables/{shard}/{database}/{table}',
    '{replica}',
    updated_date_time
)
PARTITION BY toStartOfMonth(window_start)
ORDER BY (meta_network_name, window_start, meta_client_name, pid, client_type, local_port);

CREATE TABLE tcp_rtt ON CLUSTER '{cluster}' AS tcp_rtt_local
ENGINE = Distributed('{cluster}', currentDatabase(), tcp_rtt_local, cityHash64(window_start, meta_network_name, meta_client_name));

CREATE TABLE tcp_cwnd_local ON CLUSTER '{cluster}' (
    updated_date_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    window_start DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    interval_ms UInt16 CODEC(ZSTD(1)),
    wallclock_slot UInt32 CODEC(DoubleDelta, ZSTD(1)),
    wallclock_slot_start_date_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    pid UInt32 CODEC(ZSTD(1)),
    client_type LowCardinality(String),
    local_port UInt16 CODEC(ZSTD(1)),
    sum Int64 CODEC(ZSTD(1)),
    count UInt32 CODEC(ZSTD(1)),
    min Int64 CODEC(ZSTD(1)),
    max Int64 CODEC(ZSTD(1)),
    meta_client_name LowCardinality(String),
    meta_network_name LowCardinality(String)
) ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/{installation}/{cluster}/tables/{shard}/{database}/{table}',
    '{replica}',
    updated_date_time
)
PARTITION BY toStartOfMonth(window_start)
ORDER BY (meta_network_name, window_start, meta_client_name, pid, client_type, local_port);

CREATE TABLE tcp_cwnd ON CLUSTER '{cluster}' AS tcp_cwnd_local
ENGINE = Distributed('{cluster}', currentDatabase(), tcp_cwnd_local, cityHash64(window_start, meta_network_name, meta_client_name));

CREATE TABLE disk_queue_depth_local ON CLUSTER '{cluster}' (
    updated_date_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    window_start DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    interval_ms UInt16 CODEC(ZSTD(1)),
    wallclock_slot UInt32 CODEC(DoubleDelta, ZSTD(1)),
    wallclock_slot_start_date_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    pid UInt32 CODEC(ZSTD(1)),
    client_type LowCardinality(String),
    device_id UInt32 CODEC(ZSTD(1)),
    rw LowCardinality(String),
    sum Int64 CODEC(ZSTD(1)),
    count UInt32 CODEC(ZSTD(1)),
    min Int64 CODEC(ZSTD(1)),
    max Int64 CODEC(ZSTD(1)),
    meta_client_name LowCardinality(String),
    meta_network_name LowCardinality(String)
) ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/{installation}/{cluster}/tables/{shard}/{database}/{table}',
    '{replica}',
    updated_date_time
)
PARTITION BY toStartOfMonth(window_start)
ORDER BY (meta_network_name, window_start, meta_client_name, pid, client_type, device_id, rw);

CREATE TABLE disk_queue_depth ON CLUSTER '{cluster}' AS disk_queue_depth_local
ENGINE = Distributed('{cluster}', currentDatabase(), disk_queue_depth_local, cityHash64(window_start, meta_network_name, meta_client_name));
