-- Migration 004 rollback: remove CPU utilization summary table.

DROP TABLE IF EXISTS cpu_utilization ON CLUSTER '{cluster}';
DROP TABLE IF EXISTS cpu_utilization_local ON CLUSTER '{cluster}';
