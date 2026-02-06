use std::sync::atomic::{AtomicU64, Ordering};

/// Number of histogram buckets.
pub const NUM_BUCKETS: usize = 10;

/// Histogram bucket boundaries in nanoseconds.
/// 10 buckets: <1us, 1us-10us, 10us-100us, 100us-1ms, 1ms-10ms,
/// 10ms-100ms, 100ms-1s, 1s-10s, 10s-100s, 100s+.
const BOUNDARIES: [u64; 9] = [
    1_000,           // 1 microsecond
    10_000,          // 10 microseconds
    100_000,         // 100 microseconds
    1_000_000,       // 1 millisecond
    10_000_000,      // 10 milliseconds
    100_000_000,     // 100 milliseconds
    1_000_000_000,   // 1 second
    10_000_000_000,  // 10 seconds
    100_000_000_000, // 100 seconds
];

/// Exponential histogram with 10 buckets for latency values.
/// All operations are atomic and safe for concurrent use.
pub struct Histogram {
    buckets: [AtomicU64; NUM_BUCKETS],
}

impl Histogram {
    /// Creates a new histogram with all buckets at zero.
    pub fn new() -> Self {
        Self {
            buckets: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }

    /// Records a value (in nanoseconds) to the appropriate bucket.
    pub fn record(&self, value_ns: u64) {
        let idx = bucket_index(value_ns);
        if let Some(bucket) = self.buckets.get(idx) {
            bucket.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Returns the current bucket counts as a snapshot.
    /// Returns [<1us, 1us-10us, 10us-100us, ..., 100s+].
    pub fn snapshot(&self) -> [u32; NUM_BUCKETS] {
        let mut result = [0u32; NUM_BUCKETS];
        for (slot, bucket) in result.iter_mut().zip(self.buckets.iter()) {
            *slot = bucket.load(Ordering::Relaxed) as u32;
        }
        result
    }
}

impl Default for Histogram {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for Histogram {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Histogram")
            .field("buckets", &self.snapshot())
            .finish()
    }
}

/// Returns the bucket index for a given value in nanoseconds.
fn bucket_index(value_ns: u64) -> usize {
    // Linear scan is fine for 9 boundaries - branch predictor handles this well.
    for (i, &boundary) in BOUNDARIES.iter().enumerate() {
        if value_ns < boundary {
            return i;
        }
    }
    9 // +inf bucket
}

/// Returns the upper bounds for each bucket in nanoseconds.
/// The last bucket (index 9) is unbounded (+inf, represented as 0).
pub fn bucket_boundaries() -> [u64; NUM_BUCKETS] {
    [
        BOUNDARIES[0],
        BOUNDARIES[1],
        BOUNDARIES[2],
        BOUNDARIES[3],
        BOUNDARIES[4],
        BOUNDARIES[5],
        BOUNDARIES[6],
        BOUNDARIES[7],
        BOUNDARIES[8],
        0, // +inf
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bucket_index_below_first_boundary() {
        assert_eq!(bucket_index(0), 0);
        assert_eq!(bucket_index(500), 0);
        assert_eq!(bucket_index(999), 0);
    }

    #[test]
    fn test_bucket_index_at_boundaries() {
        assert_eq!(bucket_index(1_000), 1);
        assert_eq!(bucket_index(10_000), 2);
        assert_eq!(bucket_index(100_000), 3);
        assert_eq!(bucket_index(1_000_000), 4);
        assert_eq!(bucket_index(10_000_000), 5);
        assert_eq!(bucket_index(100_000_000), 6);
        assert_eq!(bucket_index(1_000_000_000), 7);
        assert_eq!(bucket_index(10_000_000_000), 8);
        assert_eq!(bucket_index(100_000_000_000), 9);
    }

    #[test]
    fn test_bucket_index_just_below_boundaries() {
        assert_eq!(bucket_index(999), 0);
        assert_eq!(bucket_index(9_999), 1);
        assert_eq!(bucket_index(99_999), 2);
        assert_eq!(bucket_index(999_999), 3);
        assert_eq!(bucket_index(9_999_999), 4);
        assert_eq!(bucket_index(99_999_999), 5);
        assert_eq!(bucket_index(999_999_999), 6);
        assert_eq!(bucket_index(9_999_999_999), 7);
        assert_eq!(bucket_index(99_999_999_999), 8);
    }

    #[test]
    fn test_bucket_index_large_value() {
        assert_eq!(bucket_index(u64::MAX), 9);
        assert_eq!(bucket_index(1_000_000_000_000), 9);
    }

    #[test]
    fn test_histogram_record_and_snapshot() {
        let h = Histogram::new();

        // Record values in different buckets.
        h.record(500); // bucket 0 (<1us)
        h.record(5_000); // bucket 1 (1us-10us)
        h.record(5_000); // bucket 1 again
        h.record(50_000_000); // bucket 5 (10ms-100ms)

        let snap = h.snapshot();
        assert_eq!(snap[0], 1);
        assert_eq!(snap[1], 2);
        assert_eq!(snap[2], 0);
        assert_eq!(snap[5], 1);
    }

    #[test]
    fn test_histogram_empty_snapshot() {
        let h = Histogram::new();
        let snap = h.snapshot();
        assert_eq!(snap, [0u32; NUM_BUCKETS]);
    }

    #[test]
    fn test_bucket_boundaries_length() {
        let b = bucket_boundaries();
        assert_eq!(b.len(), NUM_BUCKETS);
        assert_eq!(b[0], 1_000);
        assert_eq!(b[9], 0); // +inf
    }
}
