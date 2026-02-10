-- Migration 006 rollback: remove sampling metadata columns from aggregated metric tables.

-- syscall_read
ALTER TABLE syscall_read_local ON CLUSTER '{cluster}'
    DROP COLUMN IF EXISTS sampling_rate,
    DROP COLUMN IF EXISTS sampling_mode;

ALTER TABLE syscall_read ON CLUSTER '{cluster}'
    DROP COLUMN IF EXISTS sampling_rate,
    DROP COLUMN IF EXISTS sampling_mode;

-- syscall_write
ALTER TABLE syscall_write_local ON CLUSTER '{cluster}'
    DROP COLUMN IF EXISTS sampling_rate,
    DROP COLUMN IF EXISTS sampling_mode;

ALTER TABLE syscall_write ON CLUSTER '{cluster}'
    DROP COLUMN IF EXISTS sampling_rate,
    DROP COLUMN IF EXISTS sampling_mode;

-- syscall_futex
ALTER TABLE syscall_futex_local ON CLUSTER '{cluster}'
    DROP COLUMN IF EXISTS sampling_rate,
    DROP COLUMN IF EXISTS sampling_mode;

ALTER TABLE syscall_futex ON CLUSTER '{cluster}'
    DROP COLUMN IF EXISTS sampling_rate,
    DROP COLUMN IF EXISTS sampling_mode;

-- syscall_mmap
ALTER TABLE syscall_mmap_local ON CLUSTER '{cluster}'
    DROP COLUMN IF EXISTS sampling_rate,
    DROP COLUMN IF EXISTS sampling_mode;

ALTER TABLE syscall_mmap ON CLUSTER '{cluster}'
    DROP COLUMN IF EXISTS sampling_rate,
    DROP COLUMN IF EXISTS sampling_mode;

-- syscall_epoll_wait
ALTER TABLE syscall_epoll_wait_local ON CLUSTER '{cluster}'
    DROP COLUMN IF EXISTS sampling_rate,
    DROP COLUMN IF EXISTS sampling_mode;

ALTER TABLE syscall_epoll_wait ON CLUSTER '{cluster}'
    DROP COLUMN IF EXISTS sampling_rate,
    DROP COLUMN IF EXISTS sampling_mode;

-- syscall_fsync
ALTER TABLE syscall_fsync_local ON CLUSTER '{cluster}'
    DROP COLUMN IF EXISTS sampling_rate,
    DROP COLUMN IF EXISTS sampling_mode;

ALTER TABLE syscall_fsync ON CLUSTER '{cluster}'
    DROP COLUMN IF EXISTS sampling_rate,
    DROP COLUMN IF EXISTS sampling_mode;

-- syscall_fdatasync
ALTER TABLE syscall_fdatasync_local ON CLUSTER '{cluster}'
    DROP COLUMN IF EXISTS sampling_rate,
    DROP COLUMN IF EXISTS sampling_mode;

ALTER TABLE syscall_fdatasync ON CLUSTER '{cluster}'
    DROP COLUMN IF EXISTS sampling_rate,
    DROP COLUMN IF EXISTS sampling_mode;

-- syscall_pwrite
ALTER TABLE syscall_pwrite_local ON CLUSTER '{cluster}'
    DROP COLUMN IF EXISTS sampling_rate,
    DROP COLUMN IF EXISTS sampling_mode;

ALTER TABLE syscall_pwrite ON CLUSTER '{cluster}'
    DROP COLUMN IF EXISTS sampling_rate,
    DROP COLUMN IF EXISTS sampling_mode;

-- sched_on_cpu
ALTER TABLE sched_on_cpu_local ON CLUSTER '{cluster}'
    DROP COLUMN IF EXISTS sampling_rate,
    DROP COLUMN IF EXISTS sampling_mode;

ALTER TABLE sched_on_cpu ON CLUSTER '{cluster}'
    DROP COLUMN IF EXISTS sampling_rate,
    DROP COLUMN IF EXISTS sampling_mode;

-- sched_off_cpu
ALTER TABLE sched_off_cpu_local ON CLUSTER '{cluster}'
    DROP COLUMN IF EXISTS sampling_rate,
    DROP COLUMN IF EXISTS sampling_mode;

ALTER TABLE sched_off_cpu ON CLUSTER '{cluster}'
    DROP COLUMN IF EXISTS sampling_rate,
    DROP COLUMN IF EXISTS sampling_mode;

-- sched_runqueue
ALTER TABLE sched_runqueue_local ON CLUSTER '{cluster}'
    DROP COLUMN IF EXISTS sampling_rate,
    DROP COLUMN IF EXISTS sampling_mode;

ALTER TABLE sched_runqueue ON CLUSTER '{cluster}'
    DROP COLUMN IF EXISTS sampling_rate,
    DROP COLUMN IF EXISTS sampling_mode;

-- mem_reclaim
ALTER TABLE mem_reclaim_local ON CLUSTER '{cluster}'
    DROP COLUMN IF EXISTS sampling_rate,
    DROP COLUMN IF EXISTS sampling_mode;

ALTER TABLE mem_reclaim ON CLUSTER '{cluster}'
    DROP COLUMN IF EXISTS sampling_rate,
    DROP COLUMN IF EXISTS sampling_mode;

-- mem_compaction
ALTER TABLE mem_compaction_local ON CLUSTER '{cluster}'
    DROP COLUMN IF EXISTS sampling_rate,
    DROP COLUMN IF EXISTS sampling_mode;

ALTER TABLE mem_compaction ON CLUSTER '{cluster}'
    DROP COLUMN IF EXISTS sampling_rate,
    DROP COLUMN IF EXISTS sampling_mode;

-- disk_latency
ALTER TABLE disk_latency_local ON CLUSTER '{cluster}'
    DROP COLUMN IF EXISTS sampling_rate,
    DROP COLUMN IF EXISTS sampling_mode;

ALTER TABLE disk_latency ON CLUSTER '{cluster}'
    DROP COLUMN IF EXISTS sampling_rate,
    DROP COLUMN IF EXISTS sampling_mode;

-- page_fault_major
ALTER TABLE page_fault_major_local ON CLUSTER '{cluster}'
    DROP COLUMN IF EXISTS sampling_rate,
    DROP COLUMN IF EXISTS sampling_mode;

ALTER TABLE page_fault_major ON CLUSTER '{cluster}'
    DROP COLUMN IF EXISTS sampling_rate,
    DROP COLUMN IF EXISTS sampling_mode;

-- page_fault_minor
ALTER TABLE page_fault_minor_local ON CLUSTER '{cluster}'
    DROP COLUMN IF EXISTS sampling_rate,
    DROP COLUMN IF EXISTS sampling_mode;

ALTER TABLE page_fault_minor ON CLUSTER '{cluster}'
    DROP COLUMN IF EXISTS sampling_rate,
    DROP COLUMN IF EXISTS sampling_mode;

-- swap_in
ALTER TABLE swap_in_local ON CLUSTER '{cluster}'
    DROP COLUMN IF EXISTS sampling_rate,
    DROP COLUMN IF EXISTS sampling_mode;

ALTER TABLE swap_in ON CLUSTER '{cluster}'
    DROP COLUMN IF EXISTS sampling_rate,
    DROP COLUMN IF EXISTS sampling_mode;

-- swap_out
ALTER TABLE swap_out_local ON CLUSTER '{cluster}'
    DROP COLUMN IF EXISTS sampling_rate,
    DROP COLUMN IF EXISTS sampling_mode;

ALTER TABLE swap_out ON CLUSTER '{cluster}'
    DROP COLUMN IF EXISTS sampling_rate,
    DROP COLUMN IF EXISTS sampling_mode;

-- oom_kill
ALTER TABLE oom_kill_local ON CLUSTER '{cluster}'
    DROP COLUMN IF EXISTS sampling_rate,
    DROP COLUMN IF EXISTS sampling_mode;

ALTER TABLE oom_kill ON CLUSTER '{cluster}'
    DROP COLUMN IF EXISTS sampling_rate,
    DROP COLUMN IF EXISTS sampling_mode;

-- fd_open
ALTER TABLE fd_open_local ON CLUSTER '{cluster}'
    DROP COLUMN IF EXISTS sampling_rate,
    DROP COLUMN IF EXISTS sampling_mode;

ALTER TABLE fd_open ON CLUSTER '{cluster}'
    DROP COLUMN IF EXISTS sampling_rate,
    DROP COLUMN IF EXISTS sampling_mode;

-- fd_close
ALTER TABLE fd_close_local ON CLUSTER '{cluster}'
    DROP COLUMN IF EXISTS sampling_rate,
    DROP COLUMN IF EXISTS sampling_mode;

ALTER TABLE fd_close ON CLUSTER '{cluster}'
    DROP COLUMN IF EXISTS sampling_rate,
    DROP COLUMN IF EXISTS sampling_mode;

-- process_exit
ALTER TABLE process_exit_local ON CLUSTER '{cluster}'
    DROP COLUMN IF EXISTS sampling_rate,
    DROP COLUMN IF EXISTS sampling_mode;

ALTER TABLE process_exit ON CLUSTER '{cluster}'
    DROP COLUMN IF EXISTS sampling_rate,
    DROP COLUMN IF EXISTS sampling_mode;

-- tcp_state_change
ALTER TABLE tcp_state_change_local ON CLUSTER '{cluster}'
    DROP COLUMN IF EXISTS sampling_rate,
    DROP COLUMN IF EXISTS sampling_mode;

ALTER TABLE tcp_state_change ON CLUSTER '{cluster}'
    DROP COLUMN IF EXISTS sampling_rate,
    DROP COLUMN IF EXISTS sampling_mode;

-- net_io
ALTER TABLE net_io_local ON CLUSTER '{cluster}'
    DROP COLUMN IF EXISTS sampling_rate,
    DROP COLUMN IF EXISTS sampling_mode;

ALTER TABLE net_io ON CLUSTER '{cluster}'
    DROP COLUMN IF EXISTS sampling_rate,
    DROP COLUMN IF EXISTS sampling_mode;

-- tcp_retransmit
ALTER TABLE tcp_retransmit_local ON CLUSTER '{cluster}'
    DROP COLUMN IF EXISTS sampling_rate,
    DROP COLUMN IF EXISTS sampling_mode;

ALTER TABLE tcp_retransmit ON CLUSTER '{cluster}'
    DROP COLUMN IF EXISTS sampling_rate,
    DROP COLUMN IF EXISTS sampling_mode;

-- disk_bytes
ALTER TABLE disk_bytes_local ON CLUSTER '{cluster}'
    DROP COLUMN IF EXISTS sampling_rate,
    DROP COLUMN IF EXISTS sampling_mode;

ALTER TABLE disk_bytes ON CLUSTER '{cluster}'
    DROP COLUMN IF EXISTS sampling_rate,
    DROP COLUMN IF EXISTS sampling_mode;

-- block_merge
ALTER TABLE block_merge_local ON CLUSTER '{cluster}'
    DROP COLUMN IF EXISTS sampling_rate,
    DROP COLUMN IF EXISTS sampling_mode;

ALTER TABLE block_merge ON CLUSTER '{cluster}'
    DROP COLUMN IF EXISTS sampling_rate,
    DROP COLUMN IF EXISTS sampling_mode;

-- tcp_rtt
ALTER TABLE tcp_rtt_local ON CLUSTER '{cluster}'
    DROP COLUMN IF EXISTS sampling_rate,
    DROP COLUMN IF EXISTS sampling_mode;

ALTER TABLE tcp_rtt ON CLUSTER '{cluster}'
    DROP COLUMN IF EXISTS sampling_rate,
    DROP COLUMN IF EXISTS sampling_mode;

-- tcp_cwnd
ALTER TABLE tcp_cwnd_local ON CLUSTER '{cluster}'
    DROP COLUMN IF EXISTS sampling_rate,
    DROP COLUMN IF EXISTS sampling_mode;

ALTER TABLE tcp_cwnd ON CLUSTER '{cluster}'
    DROP COLUMN IF EXISTS sampling_rate,
    DROP COLUMN IF EXISTS sampling_mode;

-- disk_queue_depth
ALTER TABLE disk_queue_depth_local ON CLUSTER '{cluster}'
    DROP COLUMN IF EXISTS sampling_rate,
    DROP COLUMN IF EXISTS sampling_mode;

ALTER TABLE disk_queue_depth ON CLUSTER '{cluster}'
    DROP COLUMN IF EXISTS sampling_rate,
    DROP COLUMN IF EXISTS sampling_mode;

-- cpu_utilization
ALTER TABLE cpu_utilization_local ON CLUSTER '{cluster}'
    DROP COLUMN IF EXISTS sampling_rate,
    DROP COLUMN IF EXISTS sampling_mode;

ALTER TABLE cpu_utilization ON CLUSTER '{cluster}'
    DROP COLUMN IF EXISTS sampling_rate,
    DROP COLUMN IF EXISTS sampling_mode;

