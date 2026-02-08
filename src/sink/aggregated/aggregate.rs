use std::sync::atomic::{AtomicI64, AtomicU32, Ordering};

use super::histogram::{Histogram, NUM_BUCKETS};

/// Tracks latency statistics with histogram.
/// Used for syscalls, disk I/O latency, scheduler events, memory latency.
/// All operations are atomic and safe for concurrent use.
pub struct LatencyAggregate {
    sum: AtomicI64,
    count: AtomicU32,
    min: AtomicI64,
    max: AtomicI64,
    histogram: Histogram,
}

impl LatencyAggregate {
    /// Creates a new aggregate with min initialized to MAX and max to MIN.
    pub fn new() -> Self {
        Self {
            sum: AtomicI64::new(0),
            count: AtomicU32::new(0),
            min: AtomicI64::new(i64::MAX),
            max: AtomicI64::new(i64::MIN),
            histogram: Histogram::new(),
        }
    }

    /// Records a latency value in nanoseconds.
    pub fn record(&self, value_ns: u64) {
        let val = value_ns as i64;
        self.sum.fetch_add(val, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
        self.histogram.record(value_ns);

        // CAS loop for min.
        loop {
            let old_min = self.min.load(Ordering::Relaxed);
            if val >= old_min {
                break;
            }
            if self
                .min
                .compare_exchange_weak(old_min, val, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                break;
            }
        }

        // CAS loop for max.
        loop {
            let old_max = self.max.load(Ordering::Relaxed);
            if val <= old_max {
                break;
            }
            if self
                .max
                .compare_exchange_weak(old_max, val, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                break;
            }
        }
    }

    /// Returns a point-in-time snapshot of all statistics.
    pub fn snapshot(&self) -> LatencySnapshot {
        let count = self.count.load(Ordering::Relaxed);
        let mut min_val = self.min.load(Ordering::Relaxed);
        let mut max_val = self.max.load(Ordering::Relaxed);

        // Handle case where no values were recorded.
        if count == 0 {
            min_val = 0;
            max_val = 0;
        }

        LatencySnapshot {
            sum: self.sum.load(Ordering::Relaxed),
            count,
            min: min_val,
            max: max_val,
            histogram: self.histogram.snapshot(),
        }
    }
}

impl Default for LatencyAggregate {
    fn default() -> Self {
        Self::new()
    }
}

/// Point-in-time view of latency statistics.
#[derive(Debug, Clone)]
pub struct LatencySnapshot {
    pub sum: i64,
    pub count: u32,
    pub min: i64,
    pub max: i64,
    pub histogram: [u32; NUM_BUCKETS],
}

/// Tracks count and sum for counter-type metrics.
/// Used for network bytes, FD operations, page faults, etc.
/// All operations are atomic and safe for concurrent use.
pub struct CounterAggregate {
    count: AtomicU32,
    sum: AtomicI64,
}

impl CounterAggregate {
    /// Creates a new counter aggregate.
    pub fn new() -> Self {
        Self {
            count: AtomicU32::new(0),
            sum: AtomicI64::new(0),
        }
    }

    /// Records a value (typically bytes), incrementing count by 1.
    pub fn add(&self, value: i64) {
        self.count.fetch_add(1, Ordering::Relaxed);
        self.sum.fetch_add(value, Ordering::Relaxed);
    }

    /// Increments only the count by n.
    pub fn add_count(&self, n: u32) {
        self.count.fetch_add(n, Ordering::Relaxed);
    }

    /// Returns a point-in-time snapshot.
    pub fn snapshot(&self) -> CounterSnapshot {
        CounterSnapshot {
            count: self.count.load(Ordering::Relaxed),
            sum: self.sum.load(Ordering::Relaxed),
        }
    }
}

impl Default for CounterAggregate {
    fn default() -> Self {
        Self::new()
    }
}

/// Point-in-time view of counter statistics.
#[derive(Debug, Clone)]
pub struct CounterSnapshot {
    pub count: u32,
    pub sum: i64,
}

/// Tracks statistics for gauge-type metrics.
/// Used for TCP RTT, CWND, queue depth, etc.
/// All operations are atomic and safe for concurrent use.
pub struct GaugeAggregate {
    sum: AtomicI64,
    count: AtomicU32,
    min: AtomicI64,
    max: AtomicI64,
}

impl GaugeAggregate {
    /// Creates a new gauge aggregate with min initialized to MAX and max to MIN.
    pub fn new() -> Self {
        Self {
            sum: AtomicI64::new(0),
            count: AtomicU32::new(0),
            min: AtomicI64::new(i64::MAX),
            max: AtomicI64::new(i64::MIN),
        }
    }

    /// Records a gauge value.
    pub fn record(&self, value: i64) {
        self.sum.fetch_add(value, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);

        // CAS loop for min.
        loop {
            let old_min = self.min.load(Ordering::Relaxed);
            if value >= old_min {
                break;
            }
            if self
                .min
                .compare_exchange_weak(old_min, value, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                break;
            }
        }

        // CAS loop for max.
        loop {
            let old_max = self.max.load(Ordering::Relaxed);
            if value <= old_max {
                break;
            }
            if self
                .max
                .compare_exchange_weak(old_max, value, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                break;
            }
        }
    }

    /// Returns a point-in-time snapshot.
    pub fn snapshot(&self) -> GaugeSnapshot {
        let count = self.count.load(Ordering::Relaxed);
        let mut min_val = self.min.load(Ordering::Relaxed);
        let mut max_val = self.max.load(Ordering::Relaxed);

        if count == 0 {
            min_val = 0;
            max_val = 0;
        }

        GaugeSnapshot {
            sum: self.sum.load(Ordering::Relaxed),
            count,
            min: min_val,
            max: max_val,
        }
    }
}

impl Default for GaugeAggregate {
    fn default() -> Self {
        Self::new()
    }
}

/// Point-in-time view of gauge statistics.
#[derive(Debug, Clone)]
pub struct GaugeSnapshot {
    pub sum: i64,
    pub count: u32,
    pub min: i64,
    pub max: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_latency_aggregate_single_value() {
        let agg = LatencyAggregate::new();
        agg.record(5_000); // 5us

        let snap = agg.snapshot();
        assert_eq!(snap.sum, 5_000);
        assert_eq!(snap.count, 1);
        assert_eq!(snap.min, 5_000);
        assert_eq!(snap.max, 5_000);
        // 5_000ns is in bucket 1 (1us-10us).
        assert_eq!(snap.histogram[1], 1);
    }

    #[test]
    fn test_latency_aggregate_multiple_values() {
        let agg = LatencyAggregate::new();
        agg.record(1_000);
        agg.record(5_000);
        agg.record(10_000);

        let snap = agg.snapshot();
        assert_eq!(snap.sum, 16_000);
        assert_eq!(snap.count, 3);
        assert_eq!(snap.min, 1_000);
        assert_eq!(snap.max, 10_000);
    }

    #[test]
    fn test_latency_aggregate_empty_snapshot() {
        let agg = LatencyAggregate::new();
        let snap = agg.snapshot();
        assert_eq!(snap.count, 0);
        assert_eq!(snap.min, 0);
        assert_eq!(snap.max, 0);
    }

    #[test]
    fn test_counter_aggregate_add() {
        let agg = CounterAggregate::new();
        agg.add(100);
        agg.add(200);

        let snap = agg.snapshot();
        assert_eq!(snap.count, 2);
        assert_eq!(snap.sum, 300);
    }

    #[test]
    fn test_counter_aggregate_add_count() {
        let agg = CounterAggregate::new();
        agg.add_count(5);
        agg.add_count(3);

        let snap = agg.snapshot();
        assert_eq!(snap.count, 8);
        assert_eq!(snap.sum, 0);
    }

    #[test]
    fn test_counter_aggregate_empty_snapshot() {
        let agg = CounterAggregate::new();
        let snap = agg.snapshot();
        assert_eq!(snap.count, 0);
        assert_eq!(snap.sum, 0);
    }

    #[test]
    fn test_gauge_aggregate_single_value() {
        let agg = GaugeAggregate::new();
        agg.record(42);

        let snap = agg.snapshot();
        assert_eq!(snap.sum, 42);
        assert_eq!(snap.count, 1);
        assert_eq!(snap.min, 42);
        assert_eq!(snap.max, 42);
    }

    #[test]
    fn test_gauge_aggregate_multiple_values() {
        let agg = GaugeAggregate::new();
        agg.record(10);
        agg.record(50);
        agg.record(30);

        let snap = agg.snapshot();
        assert_eq!(snap.sum, 90);
        assert_eq!(snap.count, 3);
        assert_eq!(snap.min, 10);
        assert_eq!(snap.max, 50);
    }

    #[test]
    fn test_gauge_aggregate_empty_snapshot() {
        let agg = GaugeAggregate::new();
        let snap = agg.snapshot();
        assert_eq!(snap.count, 0);
        assert_eq!(snap.min, 0);
        assert_eq!(snap.max, 0);
    }

    #[test]
    fn test_gauge_aggregate_negative_values() {
        let agg = GaugeAggregate::new();
        agg.record(-10);
        agg.record(20);
        agg.record(-30);

        let snap = agg.snapshot();
        assert_eq!(snap.sum, -20);
        assert_eq!(snap.count, 3);
        assert_eq!(snap.min, -30);
        assert_eq!(snap.max, 20);
    }

    #[test]
    fn test_latency_aggregate_concurrent() {
        use std::sync::Arc;
        use std::thread;

        let agg = Arc::new(LatencyAggregate::new());
        let mut handles = Vec::new();

        for t in 0..4 {
            let agg = Arc::clone(&agg);
            handles.push(thread::spawn(move || {
                for i in 0..1000 {
                    agg.record((t * 1000 + i) as u64);
                }
            }));
        }

        for h in handles {
            h.join().expect("thread panicked");
        }

        let snap = agg.snapshot();
        assert_eq!(snap.count, 4000);
    }
}
