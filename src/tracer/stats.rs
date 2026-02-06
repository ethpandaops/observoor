use std::sync::atomic::{AtomicU64, Ordering};

use super::event::{EventType, MAX_EVENT_TYPE};

/// Lock-free per-EventType counters.
///
/// `snapshot()` atomically reads and resets all counters, making it
/// suitable for periodic reporting without contention.
pub struct EventStats {
    counts: [AtomicU64; MAX_EVENT_TYPE + 1],
}

impl EventStats {
    /// Create a new zeroed EventStats.
    pub fn new() -> Self {
        Self {
            counts: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }

    /// Increment the counter for the given event type by one.
    pub fn record(&self, t: EventType) {
        if let Some(counter) = self.counts.get(t as usize) {
            counter.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Increment the counter for the given event type by n.
    #[allow(dead_code)]
    pub fn record_n(&self, t: EventType, n: u64) {
        if let Some(counter) = self.counts.get(t as usize) {
            counter.fetch_add(n, Ordering::Relaxed);
        }
    }

    /// Atomically read and reset all counters, returning only non-zero entries.
    pub fn snapshot(&self) -> Vec<(EventType, u64)> {
        let mut result = Vec::new();

        for (i, counter) in self.counts.iter().enumerate() {
            let v = counter.swap(0, Ordering::Relaxed);
            if v > 0 {
                if let Some(et) = EventType::from_u8(i as u8) {
                    result.push((et, v));
                }
            }
        }

        result
    }
}

impl Default for EventStats {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_and_snapshot() {
        let stats = EventStats::new();
        stats.record(EventType::SyscallRead);
        stats.record(EventType::SyscallRead);
        stats.record(EventType::NetTX);

        let snap = stats.snapshot();
        assert_eq!(snap.len(), 2);

        let read_count = snap
            .iter()
            .find(|(et, _)| *et == EventType::SyscallRead)
            .map(|(_, v)| *v);
        assert_eq!(read_count, Some(2));

        let tx_count = snap
            .iter()
            .find(|(et, _)| *et == EventType::NetTX)
            .map(|(_, v)| *v);
        assert_eq!(tx_count, Some(1));
    }

    #[test]
    fn test_snapshot_resets_counters() {
        let stats = EventStats::new();
        stats.record(EventType::DiskIO);

        let snap1 = stats.snapshot();
        assert_eq!(snap1.len(), 1);

        let snap2 = stats.snapshot();
        assert!(snap2.is_empty());
    }

    #[test]
    fn test_record_n() {
        let stats = EventStats::new();
        stats.record_n(EventType::PageFault, 42);

        let snap = stats.snapshot();
        let count = snap
            .iter()
            .find(|(et, _)| *et == EventType::PageFault)
            .map(|(_, v)| *v);
        assert_eq!(count, Some(42));
    }
}
