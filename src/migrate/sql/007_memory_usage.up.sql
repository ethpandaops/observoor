-- Migration 007: add process memory usage snapshot table.

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
