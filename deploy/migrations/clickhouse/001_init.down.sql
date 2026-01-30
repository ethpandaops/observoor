-- Observoor ClickHouse Schema Teardown

DROP TABLE IF EXISTS aggregated_metrics ON CLUSTER '{cluster}';
DROP TABLE IF EXISTS aggregated_metrics_local ON CLUSTER '{cluster}';

DROP TABLE IF EXISTS raw_events ON CLUSTER '{cluster}';
DROP TABLE IF EXISTS raw_events_local ON CLUSTER '{cluster}';
