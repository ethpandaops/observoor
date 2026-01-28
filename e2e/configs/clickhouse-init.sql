CREATE DATABASE IF NOT EXISTS observoor;

CREATE TABLE IF NOT EXISTS observoor.raw_events (
    timestamp_ns     UInt64,
    slot             UInt64,
    pid              UInt32,
    tid              UInt32,
    event_type       String,
    client_type      String,
    latency_ns       UInt64,
    bytes            Int64,
    src_port         UInt16,
    dst_port         UInt16,
    fd               Int32,
    filename         String,
    voluntary        Bool,
    major            Bool,
    address          UInt64,
    on_cpu_ns        UInt64
) ENGINE = MergeTree()
ORDER BY (slot, timestamp_ns, event_type)
TTL toDateTime(fromUnixTimestamp64Nano(timestamp_ns)) + INTERVAL 30 DAY
SETTINGS index_granularity = 8192;
