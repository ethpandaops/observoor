-- Migration 008 rollback: remove process snapshot tables for I/O, FD, and scheduler state.

DROP TABLE IF EXISTS process_sched_usage ON CLUSTER '{cluster}';
DROP TABLE IF EXISTS process_sched_usage_local ON CLUSTER '{cluster}';

DROP TABLE IF EXISTS process_fd_usage ON CLUSTER '{cluster}';
DROP TABLE IF EXISTS process_fd_usage_local ON CLUSTER '{cluster}';

DROP TABLE IF EXISTS process_io_usage ON CLUSTER '{cluster}';
DROP TABLE IF EXISTS process_io_usage_local ON CLUSTER '{cluster}';
