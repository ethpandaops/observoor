-- Migration 003 rollback: Float32 → Int64 for sum/min/max columns

--------------------------------------------------------------------------------
-- LATENCY TABLES (14) — restore sum, min, max to Int64
--------------------------------------------------------------------------------

-- syscall_read
ALTER TABLE syscall_read_local ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Int64 CODEC(ZSTD(1)),
    MODIFY COLUMN `min` Int64 CODEC(ZSTD(1)),
    MODIFY COLUMN `max` Int64 CODEC(ZSTD(1));

ALTER TABLE syscall_read ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Int64,
    MODIFY COLUMN `min` Int64,
    MODIFY COLUMN `max` Int64;

-- syscall_write
ALTER TABLE syscall_write_local ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Int64 CODEC(ZSTD(1)),
    MODIFY COLUMN `min` Int64 CODEC(ZSTD(1)),
    MODIFY COLUMN `max` Int64 CODEC(ZSTD(1));

ALTER TABLE syscall_write ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Int64,
    MODIFY COLUMN `min` Int64,
    MODIFY COLUMN `max` Int64;

-- syscall_futex
ALTER TABLE syscall_futex_local ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Int64 CODEC(ZSTD(1)),
    MODIFY COLUMN `min` Int64 CODEC(ZSTD(1)),
    MODIFY COLUMN `max` Int64 CODEC(ZSTD(1));

ALTER TABLE syscall_futex ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Int64,
    MODIFY COLUMN `min` Int64,
    MODIFY COLUMN `max` Int64;

-- syscall_mmap
ALTER TABLE syscall_mmap_local ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Int64 CODEC(ZSTD(1)),
    MODIFY COLUMN `min` Int64 CODEC(ZSTD(1)),
    MODIFY COLUMN `max` Int64 CODEC(ZSTD(1));

ALTER TABLE syscall_mmap ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Int64,
    MODIFY COLUMN `min` Int64,
    MODIFY COLUMN `max` Int64;

-- syscall_epoll_wait
ALTER TABLE syscall_epoll_wait_local ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Int64 CODEC(ZSTD(1)),
    MODIFY COLUMN `min` Int64 CODEC(ZSTD(1)),
    MODIFY COLUMN `max` Int64 CODEC(ZSTD(1));

ALTER TABLE syscall_epoll_wait ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Int64,
    MODIFY COLUMN `min` Int64,
    MODIFY COLUMN `max` Int64;

-- syscall_fsync
ALTER TABLE syscall_fsync_local ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Int64 CODEC(ZSTD(1)),
    MODIFY COLUMN `min` Int64 CODEC(ZSTD(1)),
    MODIFY COLUMN `max` Int64 CODEC(ZSTD(1));

ALTER TABLE syscall_fsync ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Int64,
    MODIFY COLUMN `min` Int64,
    MODIFY COLUMN `max` Int64;

-- syscall_fdatasync
ALTER TABLE syscall_fdatasync_local ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Int64 CODEC(ZSTD(1)),
    MODIFY COLUMN `min` Int64 CODEC(ZSTD(1)),
    MODIFY COLUMN `max` Int64 CODEC(ZSTD(1));

ALTER TABLE syscall_fdatasync ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Int64,
    MODIFY COLUMN `min` Int64,
    MODIFY COLUMN `max` Int64;

-- syscall_pwrite
ALTER TABLE syscall_pwrite_local ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Int64 CODEC(ZSTD(1)),
    MODIFY COLUMN `min` Int64 CODEC(ZSTD(1)),
    MODIFY COLUMN `max` Int64 CODEC(ZSTD(1));

ALTER TABLE syscall_pwrite ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Int64,
    MODIFY COLUMN `min` Int64,
    MODIFY COLUMN `max` Int64;

-- sched_on_cpu
ALTER TABLE sched_on_cpu_local ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Int64 CODEC(ZSTD(1)),
    MODIFY COLUMN `min` Int64 CODEC(ZSTD(1)),
    MODIFY COLUMN `max` Int64 CODEC(ZSTD(1));

ALTER TABLE sched_on_cpu ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Int64,
    MODIFY COLUMN `min` Int64,
    MODIFY COLUMN `max` Int64;

-- sched_off_cpu
ALTER TABLE sched_off_cpu_local ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Int64 CODEC(ZSTD(1)),
    MODIFY COLUMN `min` Int64 CODEC(ZSTD(1)),
    MODIFY COLUMN `max` Int64 CODEC(ZSTD(1));

ALTER TABLE sched_off_cpu ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Int64,
    MODIFY COLUMN `min` Int64,
    MODIFY COLUMN `max` Int64;

-- sched_runqueue
ALTER TABLE sched_runqueue_local ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Int64 CODEC(ZSTD(1)),
    MODIFY COLUMN `min` Int64 CODEC(ZSTD(1)),
    MODIFY COLUMN `max` Int64 CODEC(ZSTD(1));

ALTER TABLE sched_runqueue ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Int64,
    MODIFY COLUMN `min` Int64,
    MODIFY COLUMN `max` Int64;

-- mem_reclaim
ALTER TABLE mem_reclaim_local ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Int64 CODEC(ZSTD(1)),
    MODIFY COLUMN `min` Int64 CODEC(ZSTD(1)),
    MODIFY COLUMN `max` Int64 CODEC(ZSTD(1));

ALTER TABLE mem_reclaim ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Int64,
    MODIFY COLUMN `min` Int64,
    MODIFY COLUMN `max` Int64;

-- mem_compaction
ALTER TABLE mem_compaction_local ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Int64 CODEC(ZSTD(1)),
    MODIFY COLUMN `min` Int64 CODEC(ZSTD(1)),
    MODIFY COLUMN `max` Int64 CODEC(ZSTD(1));

ALTER TABLE mem_compaction ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Int64,
    MODIFY COLUMN `min` Int64,
    MODIFY COLUMN `max` Int64;

-- disk_latency
ALTER TABLE disk_latency_local ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Int64 CODEC(ZSTD(1)),
    MODIFY COLUMN `min` Int64 CODEC(ZSTD(1)),
    MODIFY COLUMN `max` Int64 CODEC(ZSTD(1));

ALTER TABLE disk_latency ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Int64,
    MODIFY COLUMN `min` Int64,
    MODIFY COLUMN `max` Int64;


--------------------------------------------------------------------------------
-- COUNTER TABLES (13) — restore sum to Int64
--------------------------------------------------------------------------------

-- page_fault_major
ALTER TABLE page_fault_major_local ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Int64 CODEC(ZSTD(1));

ALTER TABLE page_fault_major ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Int64;

-- page_fault_minor
ALTER TABLE page_fault_minor_local ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Int64 CODEC(ZSTD(1));

ALTER TABLE page_fault_minor ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Int64;

-- swap_in
ALTER TABLE swap_in_local ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Int64 CODEC(ZSTD(1));

ALTER TABLE swap_in ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Int64;

-- swap_out
ALTER TABLE swap_out_local ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Int64 CODEC(ZSTD(1));

ALTER TABLE swap_out ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Int64;

-- oom_kill
ALTER TABLE oom_kill_local ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Int64 CODEC(ZSTD(1));

ALTER TABLE oom_kill ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Int64;

-- fd_open
ALTER TABLE fd_open_local ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Int64 CODEC(ZSTD(1));

ALTER TABLE fd_open ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Int64;

-- fd_close
ALTER TABLE fd_close_local ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Int64 CODEC(ZSTD(1));

ALTER TABLE fd_close ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Int64;

-- process_exit
ALTER TABLE process_exit_local ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Int64 CODEC(ZSTD(1));

ALTER TABLE process_exit ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Int64;

-- tcp_state_change
ALTER TABLE tcp_state_change_local ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Int64 CODEC(ZSTD(1));

ALTER TABLE tcp_state_change ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Int64;

-- net_io
ALTER TABLE net_io_local ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Int64 CODEC(ZSTD(1));

ALTER TABLE net_io ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Int64;

-- tcp_retransmit
ALTER TABLE tcp_retransmit_local ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Int64 CODEC(ZSTD(1));

ALTER TABLE tcp_retransmit ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Int64;

-- disk_bytes
ALTER TABLE disk_bytes_local ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Int64 CODEC(ZSTD(1));

ALTER TABLE disk_bytes ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Int64;

-- block_merge
ALTER TABLE block_merge_local ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Int64 CODEC(ZSTD(1));

ALTER TABLE block_merge ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Int64;


--------------------------------------------------------------------------------
-- GAUGE TABLES (3) — restore sum, min, max to Int64
--------------------------------------------------------------------------------

-- tcp_rtt
ALTER TABLE tcp_rtt_local ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Int64 CODEC(ZSTD(1)),
    MODIFY COLUMN `min` Int64 CODEC(ZSTD(1)),
    MODIFY COLUMN `max` Int64 CODEC(ZSTD(1));

ALTER TABLE tcp_rtt ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Int64,
    MODIFY COLUMN `min` Int64,
    MODIFY COLUMN `max` Int64;

-- tcp_cwnd
ALTER TABLE tcp_cwnd_local ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Int64 CODEC(ZSTD(1)),
    MODIFY COLUMN `min` Int64 CODEC(ZSTD(1)),
    MODIFY COLUMN `max` Int64 CODEC(ZSTD(1));

ALTER TABLE tcp_cwnd ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Int64,
    MODIFY COLUMN `min` Int64,
    MODIFY COLUMN `max` Int64;

-- disk_queue_depth
ALTER TABLE disk_queue_depth_local ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Int64 CODEC(ZSTD(1)),
    MODIFY COLUMN `min` Int64 CODEC(ZSTD(1)),
    MODIFY COLUMN `max` Int64 CODEC(ZSTD(1));

ALTER TABLE disk_queue_depth ON CLUSTER '{cluster}'
    MODIFY COLUMN `sum` Int64,
    MODIFY COLUMN `min` Int64,
    MODIFY COLUMN `max` Int64;
