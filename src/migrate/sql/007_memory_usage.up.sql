-- Migration 007: add process snapshot tables for memory, I/O, FD, and scheduler state.

CREATE TABLE memory_usage_local ON CLUSTER '{cluster}' (
    updated_date_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    window_start DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    interval_ms UInt16 CODEC(ZSTD(1)),
    wallclock_slot UInt32 CODEC(DoubleDelta, ZSTD(1)),
    wallclock_slot_start_date_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    pid UInt32 CODEC(ZSTD(1)),
    client_type LowCardinality(String),
    sampling_mode LowCardinality(String),
    sampling_rate Float32 CODEC(ZSTD(1)),
    vm_size_bytes UInt64 CODEC(ZSTD(1)),
    vm_rss_bytes UInt64 CODEC(ZSTD(1)),
    rss_anon_bytes UInt64 CODEC(ZSTD(1)),
    rss_file_bytes UInt64 CODEC(ZSTD(1)),
    rss_shmem_bytes UInt64 CODEC(ZSTD(1)),
    vm_swap_bytes UInt64 CODEC(ZSTD(1)),
    meta_client_name LowCardinality(String),
    meta_network_name LowCardinality(String)
) ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/{installation}/{cluster}/tables/{shard}/{database}/{table}',
    '{replica}',
    updated_date_time
)
PARTITION BY toStartOfMonth(window_start)
ORDER BY (meta_network_name, window_start, meta_client_name, pid, client_type);

CREATE TABLE memory_usage ON CLUSTER '{cluster}' AS memory_usage_local
ENGINE = Distributed(
    '{cluster}',
    currentDatabase(),
    memory_usage_local,
    cityHash64(window_start, meta_network_name, meta_client_name)
);

CREATE TABLE process_io_usage_local ON CLUSTER '{cluster}' (
    updated_date_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    window_start DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    interval_ms UInt16 CODEC(ZSTD(1)),
    wallclock_slot UInt32 CODEC(DoubleDelta, ZSTD(1)),
    wallclock_slot_start_date_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    pid UInt32 CODEC(ZSTD(1)),
    client_type LowCardinality(String),
    sampling_mode LowCardinality(String),
    sampling_rate Float32 CODEC(ZSTD(1)),
    rchar_bytes UInt64 CODEC(ZSTD(1)),
    wchar_bytes UInt64 CODEC(ZSTD(1)),
    syscr UInt64 CODEC(ZSTD(1)),
    syscw UInt64 CODEC(ZSTD(1)),
    read_bytes UInt64 CODEC(ZSTD(1)),
    write_bytes UInt64 CODEC(ZSTD(1)),
    cancelled_write_bytes Int64 CODEC(ZSTD(1)),
    meta_client_name LowCardinality(String),
    meta_network_name LowCardinality(String)
) ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/{installation}/{cluster}/tables/{shard}/{database}/{table}',
    '{replica}',
    updated_date_time
)
PARTITION BY toStartOfMonth(window_start)
ORDER BY (meta_network_name, window_start, meta_client_name, pid, client_type);

CREATE TABLE process_io_usage ON CLUSTER '{cluster}' AS process_io_usage_local
ENGINE = Distributed(
    '{cluster}',
    currentDatabase(),
    process_io_usage_local,
    cityHash64(window_start, meta_network_name, meta_client_name)
);

CREATE TABLE process_fd_usage_local ON CLUSTER '{cluster}' (
    updated_date_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    window_start DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    interval_ms UInt16 CODEC(ZSTD(1)),
    wallclock_slot UInt32 CODEC(DoubleDelta, ZSTD(1)),
    wallclock_slot_start_date_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    pid UInt32 CODEC(ZSTD(1)),
    client_type LowCardinality(String),
    sampling_mode LowCardinality(String),
    sampling_rate Float32 CODEC(ZSTD(1)),
    open_fds UInt32 CODEC(ZSTD(1)),
    fd_limit_soft UInt64 CODEC(ZSTD(1)),
    fd_limit_hard UInt64 CODEC(ZSTD(1)),
    meta_client_name LowCardinality(String),
    meta_network_name LowCardinality(String)
) ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/{installation}/{cluster}/tables/{shard}/{database}/{table}',
    '{replica}',
    updated_date_time
)
PARTITION BY toStartOfMonth(window_start)
ORDER BY (meta_network_name, window_start, meta_client_name, pid, client_type);

CREATE TABLE process_fd_usage ON CLUSTER '{cluster}' AS process_fd_usage_local
ENGINE = Distributed(
    '{cluster}',
    currentDatabase(),
    process_fd_usage_local,
    cityHash64(window_start, meta_network_name, meta_client_name)
);

CREATE TABLE process_sched_usage_local ON CLUSTER '{cluster}' (
    updated_date_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    window_start DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    interval_ms UInt16 CODEC(ZSTD(1)),
    wallclock_slot UInt32 CODEC(DoubleDelta, ZSTD(1)),
    wallclock_slot_start_date_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    pid UInt32 CODEC(ZSTD(1)),
    client_type LowCardinality(String),
    sampling_mode LowCardinality(String),
    sampling_rate Float32 CODEC(ZSTD(1)),
    threads UInt32 CODEC(ZSTD(1)),
    voluntary_ctxt_switches UInt64 CODEC(ZSTD(1)),
    nonvoluntary_ctxt_switches UInt64 CODEC(ZSTD(1)),
    meta_client_name LowCardinality(String),
    meta_network_name LowCardinality(String)
) ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/{installation}/{cluster}/tables/{shard}/{database}/{table}',
    '{replica}',
    updated_date_time
)
PARTITION BY toStartOfMonth(window_start)
ORDER BY (meta_network_name, window_start, meta_client_name, pid, client_type);

CREATE TABLE process_sched_usage ON CLUSTER '{cluster}' AS process_sched_usage_local
ENGINE = Distributed(
    '{cluster}',
    currentDatabase(),
    process_sched_usage_local,
    cityHash64(window_start, meta_network_name, meta_client_name)
);

CREATE TABLE host_specs_local ON CLUSTER '{cluster}' (
    updated_date_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    event_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    wallclock_slot UInt32 CODEC(DoubleDelta, ZSTD(1)),
    wallclock_slot_start_date_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    host_id String,
    hostname LowCardinality(String),
    machine_id String,
    kernel_release LowCardinality(String),
    os_name LowCardinality(String),
    architecture LowCardinality(String),
    cpu_model String,
    cpu_vendor LowCardinality(String),
    cpu_online_cores UInt16 CODEC(ZSTD(1)),
    cpu_logical_cores UInt16 CODEC(ZSTD(1)),
    memory_total_bytes UInt64 CODEC(ZSTD(1)),
    memory_type LowCardinality(String),
    memory_speed_mts UInt32 CODEC(ZSTD(1)),
    disk_count UInt16 CODEC(ZSTD(1)),
    disk_total_bytes UInt64 CODEC(ZSTD(1)),
    disk_names Array(String),
    disk_models Array(String),
    disk_vendors Array(String),
    disk_serials Array(String),
    disk_sizes_bytes Array(UInt64),
    disk_rotational Array(UInt8),
    meta_client_name LowCardinality(String),
    meta_network_name LowCardinality(String)
) ENGINE = ReplicatedReplacingMergeTree(
    '/clickhouse/{installation}/{cluster}/tables/{shard}/{database}/{table}',
    '{replica}',
    updated_date_time
)
PARTITION BY toStartOfMonth(event_time)
ORDER BY (meta_network_name, event_time, host_id, meta_client_name);

CREATE TABLE host_specs ON CLUSTER '{cluster}' AS host_specs_local
ENGINE = Distributed(
    '{cluster}',
    currentDatabase(),
    host_specs_local,
    cityHash64(event_time, meta_network_name, host_id, meta_client_name)
);
