-- Migration 007 rollback: remove process memory usage snapshot table.

DROP TABLE IF EXISTS memory_usage ON CLUSTER '{cluster}';
DROP TABLE IF EXISTS memory_usage_local ON CLUSTER '{cluster}';
