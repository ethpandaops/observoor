-- Migration 007 rollback: remove process snapshot and host_specs tables.

DROP TABLE IF EXISTS host_specs ON CLUSTER '{cluster}';
DROP TABLE IF EXISTS host_specs_local ON CLUSTER '{cluster}';

DROP TABLE IF EXISTS process_sched_usage ON CLUSTER '{cluster}';
DROP TABLE IF EXISTS process_sched_usage_local ON CLUSTER '{cluster}';

DROP TABLE IF EXISTS process_fd_usage ON CLUSTER '{cluster}';
DROP TABLE IF EXISTS process_fd_usage_local ON CLUSTER '{cluster}';

DROP TABLE IF EXISTS process_io_usage ON CLUSTER '{cluster}';
DROP TABLE IF EXISTS process_io_usage_local ON CLUSTER '{cluster}';

DROP TABLE IF EXISTS memory_usage ON CLUSTER '{cluster}';
DROP TABLE IF EXISTS memory_usage_local ON CLUSTER '{cluster}';
