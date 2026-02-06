// Re-export the aggregated sink config types from the central config module.
// This module exists for discoverability; the actual types live in crate::config
// to keep YAML deserialization in one place.
pub use crate::config::{
    AggregatedSinkConfig, DimensionsConfig, DiskDimensionsConfig, NetworkDimensionsConfig,
    ResolutionConfig,
};
