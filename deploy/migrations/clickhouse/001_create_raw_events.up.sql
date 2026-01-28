CREATE TABLE raw_events_local on cluster '{cluster}' (
    timestamp_ns UInt64 Codec(DoubleDelta, ZSTD(1)),
    slot UInt64 Codec(DoubleDelta, ZSTD(1)),
    slot_start_date_time DateTime Codec(DoubleDelta, ZSTD(1)),
    pid UInt32 Codec(ZSTD(1)),
    tid UInt32 Codec(ZSTD(1)),
    event_type LowCardinality(String),
    client_type LowCardinality(String),
    latency_ns UInt64 Codec(ZSTD(1)),
    bytes Int64 Codec(ZSTD(1)),
    src_port UInt16 Codec(ZSTD(1)),
    dst_port UInt16 Codec(ZSTD(1)),
    fd Int32 Codec(ZSTD(1)),
    filename String Codec(ZSTD(1)),
    voluntary Bool Codec(ZSTD(1)),
    major Bool Codec(ZSTD(1)),
    address UInt64 Codec(ZSTD(1)),
    on_cpu_ns UInt64 Codec(ZSTD(1)),
    meta_node_name LowCardinality(String),
    meta_network_name LowCardinality(String),
    meta_labels Map(String, String) Codec(ZSTD(1))
) Engine = ReplicatedMergeTree('/clickhouse/{installation}/{cluster}/tables/{shard}/{database}/{table}', '{replica}')
PARTITION BY toStartOfMonth(slot_start_date_time)
ORDER BY (slot_start_date_time, meta_network_name, client_type, event_type, pid);

ALTER TABLE default.raw_events_local ON CLUSTER '{cluster}'
MODIFY COMMENT 'Raw eBPF events captured from Ethereum client processes, one row per kernel event.',
COMMENT COLUMN timestamp_ns 'Wall clock time of the event in nanoseconds since Unix epoch',
COMMENT COLUMN slot 'Ethereum slot number at the time of the event',
COMMENT COLUMN slot_start_date_time 'Wall clock time when the slot started',
COMMENT COLUMN pid 'Process ID of the traced Ethereum client',
COMMENT COLUMN tid 'Thread ID within the traced process',
COMMENT COLUMN event_type 'Type of eBPF event (syscall_read, disk_io, net_tx, etc.)',
COMMENT COLUMN client_type 'Ethereum client implementation (geth, reth, prysm, lighthouse, etc.)',
COMMENT COLUMN latency_ns 'Latency in nanoseconds for syscall and disk I/O events',
COMMENT COLUMN bytes 'Byte count for I/O events (syscall return value, disk bytes, network bytes)',
COMMENT COLUMN src_port 'Source port for network events',
COMMENT COLUMN dst_port 'Destination port for network events',
COMMENT COLUMN fd 'File descriptor number for syscall and fd_open/fd_close events',
COMMENT COLUMN filename 'Filename for fd_open events',
COMMENT COLUMN voluntary 'Whether a context switch was voluntary',
COMMENT COLUMN major 'Whether a page fault was a major fault',
COMMENT COLUMN address 'Faulting address for page fault events',
COMMENT COLUMN on_cpu_ns 'Time spent on CPU in nanoseconds before a context switch',
COMMENT COLUMN meta_node_name 'Name of the node running the observoor agent',
COMMENT COLUMN meta_network_name 'Ethereum network name (mainnet, holesky, etc.)',
COMMENT COLUMN meta_labels 'Additional labels attached to the event';

CREATE TABLE raw_events on cluster '{cluster}' AS raw_events_local
ENGINE = Distributed('{cluster}', default, raw_events_local, rand());
