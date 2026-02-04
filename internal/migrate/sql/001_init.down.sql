-- Observoor ClickHouse Schema Teardown

-- Raw events
DROP TABLE IF EXISTS raw_events ON CLUSTER '{cluster}';
DROP TABLE IF EXISTS raw_events_local ON CLUSTER '{cluster}';

-- Sync state
DROP TABLE IF EXISTS sync_state ON CLUSTER '{cluster}';
DROP TABLE IF EXISTS sync_state_local ON CLUSTER '{cluster}';

-- Syscall latency tables
DROP TABLE IF EXISTS syscall_read ON CLUSTER '{cluster}';
DROP TABLE IF EXISTS syscall_read_local ON CLUSTER '{cluster}';
DROP TABLE IF EXISTS syscall_write ON CLUSTER '{cluster}';
DROP TABLE IF EXISTS syscall_write_local ON CLUSTER '{cluster}';
DROP TABLE IF EXISTS syscall_futex ON CLUSTER '{cluster}';
DROP TABLE IF EXISTS syscall_futex_local ON CLUSTER '{cluster}';
DROP TABLE IF EXISTS syscall_mmap ON CLUSTER '{cluster}';
DROP TABLE IF EXISTS syscall_mmap_local ON CLUSTER '{cluster}';
DROP TABLE IF EXISTS syscall_epoll_wait ON CLUSTER '{cluster}';
DROP TABLE IF EXISTS syscall_epoll_wait_local ON CLUSTER '{cluster}';
DROP TABLE IF EXISTS syscall_fsync ON CLUSTER '{cluster}';
DROP TABLE IF EXISTS syscall_fsync_local ON CLUSTER '{cluster}';
DROP TABLE IF EXISTS syscall_fdatasync ON CLUSTER '{cluster}';
DROP TABLE IF EXISTS syscall_fdatasync_local ON CLUSTER '{cluster}';
DROP TABLE IF EXISTS syscall_pwrite ON CLUSTER '{cluster}';
DROP TABLE IF EXISTS syscall_pwrite_local ON CLUSTER '{cluster}';

-- Scheduler latency tables
DROP TABLE IF EXISTS sched_on_cpu ON CLUSTER '{cluster}';
DROP TABLE IF EXISTS sched_on_cpu_local ON CLUSTER '{cluster}';
DROP TABLE IF EXISTS sched_off_cpu ON CLUSTER '{cluster}';
DROP TABLE IF EXISTS sched_off_cpu_local ON CLUSTER '{cluster}';
DROP TABLE IF EXISTS sched_runqueue ON CLUSTER '{cluster}';
DROP TABLE IF EXISTS sched_runqueue_local ON CLUSTER '{cluster}';

-- Memory latency tables
DROP TABLE IF EXISTS mem_reclaim ON CLUSTER '{cluster}';
DROP TABLE IF EXISTS mem_reclaim_local ON CLUSTER '{cluster}';
DROP TABLE IF EXISTS mem_compaction ON CLUSTER '{cluster}';
DROP TABLE IF EXISTS mem_compaction_local ON CLUSTER '{cluster}';

-- Disk latency table
DROP TABLE IF EXISTS disk_latency ON CLUSTER '{cluster}';
DROP TABLE IF EXISTS disk_latency_local ON CLUSTER '{cluster}';

-- Memory counter tables
DROP TABLE IF EXISTS page_fault_major ON CLUSTER '{cluster}';
DROP TABLE IF EXISTS page_fault_major_local ON CLUSTER '{cluster}';
DROP TABLE IF EXISTS page_fault_minor ON CLUSTER '{cluster}';
DROP TABLE IF EXISTS page_fault_minor_local ON CLUSTER '{cluster}';
DROP TABLE IF EXISTS swap_in ON CLUSTER '{cluster}';
DROP TABLE IF EXISTS swap_in_local ON CLUSTER '{cluster}';
DROP TABLE IF EXISTS swap_out ON CLUSTER '{cluster}';
DROP TABLE IF EXISTS swap_out_local ON CLUSTER '{cluster}';
DROP TABLE IF EXISTS oom_kill ON CLUSTER '{cluster}';
DROP TABLE IF EXISTS oom_kill_local ON CLUSTER '{cluster}';

-- Process counter tables
DROP TABLE IF EXISTS fd_open ON CLUSTER '{cluster}';
DROP TABLE IF EXISTS fd_open_local ON CLUSTER '{cluster}';
DROP TABLE IF EXISTS fd_close ON CLUSTER '{cluster}';
DROP TABLE IF EXISTS fd_close_local ON CLUSTER '{cluster}';
DROP TABLE IF EXISTS process_exit ON CLUSTER '{cluster}';
DROP TABLE IF EXISTS process_exit_local ON CLUSTER '{cluster}';

-- Network counter tables
DROP TABLE IF EXISTS tcp_state_change ON CLUSTER '{cluster}';
DROP TABLE IF EXISTS tcp_state_change_local ON CLUSTER '{cluster}';
DROP TABLE IF EXISTS net_io ON CLUSTER '{cluster}';
DROP TABLE IF EXISTS net_io_local ON CLUSTER '{cluster}';
DROP TABLE IF EXISTS tcp_retransmit ON CLUSTER '{cluster}';
DROP TABLE IF EXISTS tcp_retransmit_local ON CLUSTER '{cluster}';

-- Disk counter tables
DROP TABLE IF EXISTS disk_bytes ON CLUSTER '{cluster}';
DROP TABLE IF EXISTS disk_bytes_local ON CLUSTER '{cluster}';
DROP TABLE IF EXISTS block_merge ON CLUSTER '{cluster}';
DROP TABLE IF EXISTS block_merge_local ON CLUSTER '{cluster}';

-- Gauge tables
DROP TABLE IF EXISTS tcp_rtt ON CLUSTER '{cluster}';
DROP TABLE IF EXISTS tcp_rtt_local ON CLUSTER '{cluster}';
DROP TABLE IF EXISTS tcp_cwnd ON CLUSTER '{cluster}';
DROP TABLE IF EXISTS tcp_cwnd_local ON CLUSTER '{cluster}';
DROP TABLE IF EXISTS disk_queue_depth ON CLUSTER '{cluster}';
DROP TABLE IF EXISTS disk_queue_depth_local ON CLUSTER '{cluster}';
