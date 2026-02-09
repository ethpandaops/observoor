-- Migration 003: Int64 → Float32 for sum/min/max columns
-- Reduces compressed storage ~48% with negligible precision loss for monitoring data.
-- ALTER MODIFY COLUMN runs as a background mutation; no downtime required.

--------------------------------------------------------------------------------
-- LATENCY TABLES (14) — modify sum, min, max
--------------------------------------------------------------------------------

-- syscall_read
ALTER TABLE syscall_read_local ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Float32 CODEC(ZSTD(1)),
    MODIFY COLUMN `min` Float32 CODEC(ZSTD(1)),
    MODIFY COLUMN `max` Float32 CODEC(ZSTD(1));

ALTER TABLE syscall_read ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Float32,
    MODIFY COLUMN `min` Float32,
    MODIFY COLUMN `max` Float32;

-- syscall_write
ALTER TABLE syscall_write_local ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Float32 CODEC(ZSTD(1)),
    MODIFY COLUMN `min` Float32 CODEC(ZSTD(1)),
    MODIFY COLUMN `max` Float32 CODEC(ZSTD(1));

ALTER TABLE syscall_write ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Float32,
    MODIFY COLUMN `min` Float32,
    MODIFY COLUMN `max` Float32;

-- syscall_futex
ALTER TABLE syscall_futex_local ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Float32 CODEC(ZSTD(1)),
    MODIFY COLUMN `min` Float32 CODEC(ZSTD(1)),
    MODIFY COLUMN `max` Float32 CODEC(ZSTD(1));

ALTER TABLE syscall_futex ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Float32,
    MODIFY COLUMN `min` Float32,
    MODIFY COLUMN `max` Float32;

-- syscall_mmap
ALTER TABLE syscall_mmap_local ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Float32 CODEC(ZSTD(1)),
    MODIFY COLUMN `min` Float32 CODEC(ZSTD(1)),
    MODIFY COLUMN `max` Float32 CODEC(ZSTD(1));

ALTER TABLE syscall_mmap ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Float32,
    MODIFY COLUMN `min` Float32,
    MODIFY COLUMN `max` Float32;

-- syscall_epoll_wait
ALTER TABLE syscall_epoll_wait_local ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Float32 CODEC(ZSTD(1)),
    MODIFY COLUMN `min` Float32 CODEC(ZSTD(1)),
    MODIFY COLUMN `max` Float32 CODEC(ZSTD(1));

ALTER TABLE syscall_epoll_wait ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Float32,
    MODIFY COLUMN `min` Float32,
    MODIFY COLUMN `max` Float32;

-- syscall_fsync
ALTER TABLE syscall_fsync_local ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Float32 CODEC(ZSTD(1)),
    MODIFY COLUMN `min` Float32 CODEC(ZSTD(1)),
    MODIFY COLUMN `max` Float32 CODEC(ZSTD(1));

ALTER TABLE syscall_fsync ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Float32,
    MODIFY COLUMN `min` Float32,
    MODIFY COLUMN `max` Float32;

-- syscall_fdatasync
ALTER TABLE syscall_fdatasync_local ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Float32 CODEC(ZSTD(1)),
    MODIFY COLUMN `min` Float32 CODEC(ZSTD(1)),
    MODIFY COLUMN `max` Float32 CODEC(ZSTD(1));

ALTER TABLE syscall_fdatasync ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Float32,
    MODIFY COLUMN `min` Float32,
    MODIFY COLUMN `max` Float32;

-- syscall_pwrite
ALTER TABLE syscall_pwrite_local ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Float32 CODEC(ZSTD(1)),
    MODIFY COLUMN `min` Float32 CODEC(ZSTD(1)),
    MODIFY COLUMN `max` Float32 CODEC(ZSTD(1));

ALTER TABLE syscall_pwrite ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Float32,
    MODIFY COLUMN `min` Float32,
    MODIFY COLUMN `max` Float32;

-- sched_on_cpu
ALTER TABLE sched_on_cpu_local ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Float32 CODEC(ZSTD(1)),
    MODIFY COLUMN `min` Float32 CODEC(ZSTD(1)),
    MODIFY COLUMN `max` Float32 CODEC(ZSTD(1));

ALTER TABLE sched_on_cpu ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Float32,
    MODIFY COLUMN `min` Float32,
    MODIFY COLUMN `max` Float32;

-- sched_off_cpu
ALTER TABLE sched_off_cpu_local ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Float32 CODEC(ZSTD(1)),
    MODIFY COLUMN `min` Float32 CODEC(ZSTD(1)),
    MODIFY COLUMN `max` Float32 CODEC(ZSTD(1));

ALTER TABLE sched_off_cpu ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Float32,
    MODIFY COLUMN `min` Float32,
    MODIFY COLUMN `max` Float32;

-- sched_runqueue
ALTER TABLE sched_runqueue_local ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Float32 CODEC(ZSTD(1)),
    MODIFY COLUMN `min` Float32 CODEC(ZSTD(1)),
    MODIFY COLUMN `max` Float32 CODEC(ZSTD(1));

ALTER TABLE sched_runqueue ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Float32,
    MODIFY COLUMN `min` Float32,
    MODIFY COLUMN `max` Float32;

-- mem_reclaim
ALTER TABLE mem_reclaim_local ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Float32 CODEC(ZSTD(1)),
    MODIFY COLUMN `min` Float32 CODEC(ZSTD(1)),
    MODIFY COLUMN `max` Float32 CODEC(ZSTD(1));

ALTER TABLE mem_reclaim ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Float32,
    MODIFY COLUMN `min` Float32,
    MODIFY COLUMN `max` Float32;

-- mem_compaction
ALTER TABLE mem_compaction_local ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Float32 CODEC(ZSTD(1)),
    MODIFY COLUMN `min` Float32 CODEC(ZSTD(1)),
    MODIFY COLUMN `max` Float32 CODEC(ZSTD(1));

ALTER TABLE mem_compaction ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Float32,
    MODIFY COLUMN `min` Float32,
    MODIFY COLUMN `max` Float32;

-- disk_latency
ALTER TABLE disk_latency_local ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Float32 CODEC(ZSTD(1)),
    MODIFY COLUMN `min` Float32 CODEC(ZSTD(1)),
    MODIFY COLUMN `max` Float32 CODEC(ZSTD(1));

ALTER TABLE disk_latency ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Float32,
    MODIFY COLUMN `min` Float32,
    MODIFY COLUMN `max` Float32;


--------------------------------------------------------------------------------
-- COUNTER TABLES (13) — modify sum only
--------------------------------------------------------------------------------

-- page_fault_major
ALTER TABLE page_fault_major_local ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Float32 CODEC(ZSTD(1));

ALTER TABLE page_fault_major ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Float32;

-- page_fault_minor
ALTER TABLE page_fault_minor_local ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Float32 CODEC(ZSTD(1));

ALTER TABLE page_fault_minor ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Float32;

-- swap_in
ALTER TABLE swap_in_local ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Float32 CODEC(ZSTD(1));

ALTER TABLE swap_in ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Float32;

-- swap_out
ALTER TABLE swap_out_local ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Float32 CODEC(ZSTD(1));

ALTER TABLE swap_out ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Float32;

-- oom_kill
ALTER TABLE oom_kill_local ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Float32 CODEC(ZSTD(1));

ALTER TABLE oom_kill ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Float32;

-- fd_open
ALTER TABLE fd_open_local ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Float32 CODEC(ZSTD(1));

ALTER TABLE fd_open ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Float32;

-- fd_close
ALTER TABLE fd_close_local ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Float32 CODEC(ZSTD(1));

ALTER TABLE fd_close ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Float32;

-- process_exit
ALTER TABLE process_exit_local ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Float32 CODEC(ZSTD(1));

ALTER TABLE process_exit ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Float32;

-- tcp_state_change
ALTER TABLE tcp_state_change_local ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Float32 CODEC(ZSTD(1));

ALTER TABLE tcp_state_change ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Float32;

-- net_io
ALTER TABLE net_io_local ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Float32 CODEC(ZSTD(1));

ALTER TABLE net_io ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Float32;

-- tcp_retransmit
ALTER TABLE tcp_retransmit_local ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Float32 CODEC(ZSTD(1));

ALTER TABLE tcp_retransmit ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Float32;

-- disk_bytes
ALTER TABLE disk_bytes_local ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Float32 CODEC(ZSTD(1));

ALTER TABLE disk_bytes ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Float32;

-- block_merge
ALTER TABLE block_merge_local ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Float32 CODEC(ZSTD(1));

ALTER TABLE block_merge ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Float32;


--------------------------------------------------------------------------------
-- GAUGE TABLES (3) — modify sum, min, max
--------------------------------------------------------------------------------

-- tcp_rtt
ALTER TABLE tcp_rtt_local ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Float32 CODEC(ZSTD(1)),
    MODIFY COLUMN `min` Float32 CODEC(ZSTD(1)),
    MODIFY COLUMN `max` Float32 CODEC(ZSTD(1));

ALTER TABLE tcp_rtt ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Float32,
    MODIFY COLUMN `min` Float32,
    MODIFY COLUMN `max` Float32;

-- tcp_cwnd
ALTER TABLE tcp_cwnd_local ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Float32 CODEC(ZSTD(1)),
    MODIFY COLUMN `min` Float32 CODEC(ZSTD(1)),
    MODIFY COLUMN `max` Float32 CODEC(ZSTD(1));

ALTER TABLE tcp_cwnd ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Float32,
    MODIFY COLUMN `min` Float32,
    MODIFY COLUMN `max` Float32;

-- disk_queue_depth
ALTER TABLE disk_queue_depth_local ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Float32 CODEC(ZSTD(1)),
    MODIFY COLUMN `min` Float32 CODEC(ZSTD(1)),
    MODIFY COLUMN `max` Float32 CODEC(ZSTD(1));

ALTER TABLE disk_queue_depth ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Float32,
    MODIFY COLUMN `min` Float32,
    MODIFY COLUMN `max` Float32;
