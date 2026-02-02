-- Observoor ClickHouse Schema
-- Single consolidated migration for all tables

--------------------------------------------------------------------------------
-- RAW EVENTS
-- One row per kernel event. Use for debugging and detailed analysis.
-- Expected volume: ~20 GB/day at 36k events/sec
--------------------------------------------------------------------------------

CREATE TABLE raw_events_local ON CLUSTER '{cluster}' (
    -- Timing
    timestamp_ns UInt64 CODEC(DoubleDelta, ZSTD(1)),
    wallclock_slot UInt64 CODEC(DoubleDelta, ZSTD(1)),
    wallclock_slot_start_date_time DateTime CODEC(DoubleDelta, ZSTD(1)),

    -- Sync state
    cl_syncing Bool CODEC(ZSTD(1)),
    el_optimistic Bool CODEC(ZSTD(1)),
    el_offline Bool CODEC(ZSTD(1)),

    -- Process identification
    pid UInt32 CODEC(ZSTD(1)),
    tid UInt32 CODEC(ZSTD(1)),
    event_type LowCardinality(String),
    client_type LowCardinality(String),

    -- Common fields
    latency_ns UInt64 CODEC(ZSTD(1)),
    bytes Int64 CODEC(ZSTD(1)),

    -- Network fields
    src_port UInt16 CODEC(ZSTD(1)),
    dst_port UInt16 CODEC(ZSTD(1)),

    -- File descriptor fields
    fd Int32 CODEC(ZSTD(1)),
    filename String CODEC(ZSTD(1)),

    -- Scheduler fields
    voluntary Bool CODEC(ZSTD(1)),
    on_cpu_ns UInt64 CODEC(ZSTD(1)),
    runqueue_ns UInt64 CODEC(ZSTD(1)),
    off_cpu_ns UInt64 CODEC(ZSTD(1)),

    -- Memory fields
    major Bool CODEC(ZSTD(1)),
    address UInt64 CODEC(ZSTD(1)),
    pages UInt64 CODEC(ZSTD(1)),

    -- Disk I/O fields
    rw UInt8 CODEC(ZSTD(1)),
    queue_depth UInt32 CODEC(ZSTD(1)),
    device_id UInt32 CODEC(ZSTD(1)),

    -- TCP fields
    tcp_state UInt8 CODEC(ZSTD(1)),
    tcp_old_state UInt8 CODEC(ZSTD(1)),
    tcp_srtt_us UInt32 CODEC(ZSTD(1)),
    tcp_cwnd UInt32 CODEC(ZSTD(1)),

    -- Process lifecycle fields
    exit_code UInt32 CODEC(ZSTD(1)),
    target_pid UInt32 CODEC(ZSTD(1)),

    -- Metadata
    meta_node_name LowCardinality(String),
    meta_network_name LowCardinality(String)
) ENGINE = ReplicatedMergeTree(
    '/clickhouse/{installation}/{cluster}/tables/{shard}/{database}/{table}',
    '{replica}'
)
PARTITION BY toStartOfMonth(wallclock_slot_start_date_time)
ORDER BY (wallclock_slot_start_date_time, meta_network_name, client_type, event_type, pid);

ALTER TABLE raw_events_local ON CLUSTER '{cluster}'
MODIFY COMMENT 'Raw eBPF events captured from Ethereum client processes, one row per kernel event.',
COMMENT COLUMN timestamp_ns 'Wall clock time of the event in nanoseconds since Unix epoch',
COMMENT COLUMN wallclock_slot 'Ethereum slot number at the time of the event (from wall clock)',
COMMENT COLUMN wallclock_slot_start_date_time 'Wall clock time when the slot started',
COMMENT COLUMN cl_syncing 'Whether the consensus layer was syncing when this event was captured',
COMMENT COLUMN el_optimistic 'Whether the execution layer was in optimistic sync mode when this event was captured',
COMMENT COLUMN el_offline 'Whether the execution layer was unreachable when this event was captured',
COMMENT COLUMN pid 'Process ID of the traced Ethereum client',
COMMENT COLUMN tid 'Thread ID within the traced process',
COMMENT COLUMN event_type 'Type of eBPF event (syscall_read, disk_io, net_tx, etc.)',
COMMENT COLUMN client_type 'Ethereum client implementation (geth, reth, prysm, lighthouse, etc.)',
COMMENT COLUMN latency_ns 'Latency in nanoseconds for syscall and disk I/O events',
COMMENT COLUMN bytes 'Byte count for I/O events',
COMMENT COLUMN src_port 'Source port for network events',
COMMENT COLUMN dst_port 'Destination port for network events',
COMMENT COLUMN fd 'File descriptor number',
COMMENT COLUMN filename 'Filename for fd_open events',
COMMENT COLUMN voluntary 'Whether a context switch was voluntary',
COMMENT COLUMN on_cpu_ns 'Time spent on CPU in nanoseconds before a context switch',
COMMENT COLUMN runqueue_ns 'Time spent waiting in the run queue',
COMMENT COLUMN off_cpu_ns 'Time spent off CPU',
COMMENT COLUMN major 'Whether a page fault was a major fault',
COMMENT COLUMN address 'Faulting address for page fault events',
COMMENT COLUMN pages 'Number of pages for swap events',
COMMENT COLUMN rw 'Read (0) or write (1) for disk I/O',
COMMENT COLUMN queue_depth 'Block device queue depth at time of I/O',
COMMENT COLUMN device_id 'Block device ID (major:minor encoded)',
COMMENT COLUMN tcp_state 'New TCP state after state change',
COMMENT COLUMN tcp_old_state 'Previous TCP state before state change',
COMMENT COLUMN tcp_srtt_us 'Smoothed RTT in microseconds',
COMMENT COLUMN tcp_cwnd 'Congestion window size',
COMMENT COLUMN exit_code 'Process exit code',
COMMENT COLUMN target_pid 'Target PID for OOM kill events',
COMMENT COLUMN meta_node_name 'Name of the node running the observoor agent',
COMMENT COLUMN meta_network_name 'Ethereum network name (mainnet, holesky, etc.)';

CREATE TABLE raw_events ON CLUSTER '{cluster}' AS raw_events_local
ENGINE = Distributed('{cluster}', default, raw_events_local, rand());


--------------------------------------------------------------------------------
-- AGGREGATED METRICS
-- Time-windowed aggregations with histograms. Primary storage for analysis.
-- Expected volume: ~500 MB/day at 1s intervals
--------------------------------------------------------------------------------

CREATE TABLE aggregated_metrics_local ON CLUSTER '{cluster}' (
    -- Time window
    window_start DateTime CODEC(DoubleDelta, ZSTD(1)),
    interval_ms UInt16 CODEC(ZSTD(1)),
    wallclock_slot UInt32 CODEC(DoubleDelta, ZSTD(1)),

    -- Sync state
    cl_syncing Bool CODEC(ZSTD(1)),
    el_optimistic Bool CODEC(ZSTD(1)),
    el_offline Bool CODEC(ZSTD(1)),

    -- Dimensions
    metric_name LowCardinality(String),
    pid UInt32 CODEC(ZSTD(1)),
    client_type LowCardinality(String),
    local_port UInt16 CODEC(ZSTD(1)),
    direction LowCardinality(String),
    device_id UInt32 CODEC(ZSTD(1)),
    rw LowCardinality(String),

    -- Statistics
    sum Int64 CODEC(ZSTD(1)),
    count UInt32 CODEC(ZSTD(1)),
    min Int64 CODEC(ZSTD(1)),
    max Int64 CODEC(ZSTD(1)),

    -- Histogram buckets (exponential: 1us, 10us, 100us, 1ms, 10ms, 100ms, 1s, 10s, 100s, inf)
    hist_1us UInt16 CODEC(ZSTD(1)),
    hist_10us UInt16 CODEC(ZSTD(1)),
    hist_100us UInt16 CODEC(ZSTD(1)),
    hist_1ms UInt16 CODEC(ZSTD(1)),
    hist_10ms UInt16 CODEC(ZSTD(1)),
    hist_100ms UInt16 CODEC(ZSTD(1)),
    hist_1s UInt16 CODEC(ZSTD(1)),
    hist_10s UInt16 CODEC(ZSTD(1)),
    hist_100s UInt16 CODEC(ZSTD(1)),
    hist_inf UInt16 CODEC(ZSTD(1)),

    -- Metadata
    meta_node_name LowCardinality(String),
    meta_network_name LowCardinality(String)
) ENGINE = ReplicatedMergeTree(
    '/clickhouse/{installation}/{cluster}/tables/{shard}/{database}/{table}',
    '{replica}'
)
PARTITION BY toStartOfMonth(window_start)
ORDER BY (window_start, meta_network_name, client_type, metric_name, pid);

ALTER TABLE aggregated_metrics_local ON CLUSTER '{cluster}'
MODIFY COMMENT 'Aggregated eBPF metrics with configurable time resolution and dimensional breakdown.',
COMMENT COLUMN window_start 'Start time of the aggregation window',
COMMENT COLUMN interval_ms 'Aggregation interval in milliseconds (window_end = window_start + interval_ms)',
COMMENT COLUMN wallclock_slot 'Ethereum slot number at window start (from wall clock)',
COMMENT COLUMN cl_syncing 'Whether the consensus layer was syncing during this window',
COMMENT COLUMN el_optimistic 'Whether the execution layer was in optimistic sync mode during this window',
COMMENT COLUMN el_offline 'Whether the execution layer was unreachable during this window',
COMMENT COLUMN metric_name 'Name of the aggregated metric (syscall_read, disk_latency, net_io, etc.)',
COMMENT COLUMN pid 'Process ID of the traced Ethereum client',
COMMENT COLUMN client_type 'Ethereum client implementation (geth, reth, prysm, lighthouse, etc.)',
COMMENT COLUMN local_port 'Local port for network metrics (0 if not applicable)',
COMMENT COLUMN direction 'Network direction: tx, rx, or empty',
COMMENT COLUMN device_id 'Block device ID for disk metrics (major:minor encoded, 0 if not applicable)',
COMMENT COLUMN rw 'Read/write indicator for disk metrics: read, write, or empty',
COMMENT COLUMN sum 'Sum of all values in the window (latency in ns, bytes, etc.)',
COMMENT COLUMN count 'Number of events in the window',
COMMENT COLUMN min 'Minimum value observed in the window',
COMMENT COLUMN max 'Maximum value observed in the window',
COMMENT COLUMN hist_1us 'Count of values < 1 microsecond',
COMMENT COLUMN hist_10us 'Count of values 1us - 10us',
COMMENT COLUMN hist_100us 'Count of values 10us - 100us',
COMMENT COLUMN hist_1ms 'Count of values 100us - 1ms',
COMMENT COLUMN hist_10ms 'Count of values 1ms - 10ms',
COMMENT COLUMN hist_100ms 'Count of values 10ms - 100ms',
COMMENT COLUMN hist_1s 'Count of values 100ms - 1s',
COMMENT COLUMN hist_10s 'Count of values 1s - 10s',
COMMENT COLUMN hist_100s 'Count of values 10s - 100s',
COMMENT COLUMN hist_inf 'Count of values >= 100s',
COMMENT COLUMN meta_node_name 'Name of the node running the observoor agent',
COMMENT COLUMN meta_network_name 'Ethereum network name (mainnet, holesky, etc.)';

CREATE TABLE aggregated_metrics ON CLUSTER '{cluster}' AS aggregated_metrics_local
ENGINE = Distributed('{cluster}', default, aggregated_metrics_local, rand());
