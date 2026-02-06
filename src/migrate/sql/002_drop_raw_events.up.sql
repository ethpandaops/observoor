-- Remove deprecated raw events tables.
DROP TABLE IF EXISTS raw_events ON CLUSTER '{cluster}';
DROP TABLE IF EXISTS raw_events_local ON CLUSTER '{cluster}';
