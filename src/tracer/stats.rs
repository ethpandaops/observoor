use std::sync::atomic::{AtomicU64, Ordering};

use super::event::{ClientType, EventType, CLIENT_TYPE_CARDINALITY, MAX_EVENT_TYPE};

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

    /// Increment the counter for a raw event-type index by n.
    pub fn record_raw_n(&self, raw: usize, n: u64) {
        if n == 0 {
            return;
        }

        if let Some(counter) = self.counts.get(raw) {
            counter.fetch_add(n, Ordering::Relaxed);
        }
    }

    /// Flush a batch of per-event-type counts into the shared counters.
    pub fn record_batch(&self, counts: &[u64; MAX_EVENT_TYPE + 1]) {
        for (raw, count) in counts.iter().copied().enumerate().skip(1) {
            self.record_raw_n(raw, count);
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

/// Lock-free per-ClientType counters.
///
/// `snapshot()` atomically reads and resets all counters, making it suitable
/// for periodic reporting without contention.
pub struct ClientStats {
    counts: [AtomicU64; CLIENT_TYPE_CARDINALITY],
}

impl ClientStats {
    /// Create a new zeroed ClientStats.
    pub fn new() -> Self {
        Self {
            counts: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }

    /// Increment the counter for the given client type by one.
    pub fn record(&self, t: ClientType) {
        if let Some(counter) = self.counts.get(t as usize) {
            counter.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Increment the counter for a raw client-type index by n.
    pub fn record_raw_n(&self, raw: usize, n: u64) {
        if n == 0 {
            return;
        }

        if let Some(counter) = self.counts.get(raw) {
            counter.fetch_add(n, Ordering::Relaxed);
        }
    }

    /// Flush a batch of per-client counts into the shared counters.
    pub fn record_batch(&self, counts: &[u64; CLIENT_TYPE_CARDINALITY]) {
        for (raw, count) in counts.iter().copied().enumerate() {
            self.record_raw_n(raw, count);
        }
    }

    /// Atomically read and reset all counters, returning only non-zero entries.
    pub fn snapshot(&self) -> Vec<(ClientType, u64)> {
        let mut result = Vec::new();

        for (i, counter) in self.counts.iter().enumerate() {
            let v = counter.swap(0, Ordering::Relaxed);
            if v > 0 {
                if let Some(client_type) = ClientType::from_u8(i as u8) {
                    result.push((client_type, v));
                }
            }
        }

        result
    }
}

impl Default for ClientStats {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tracer::event::MAX_CLIENT_TYPE;

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

    #[test]
    fn test_event_stats_record_batch() {
        let stats = EventStats::new();
        let mut batch = [0u64; MAX_EVENT_TYPE + 1];
        batch[EventType::SyscallRead as usize] = 3;
        batch[EventType::NetTX as usize] = 5;

        stats.record_batch(&batch);

        let snap = stats.snapshot();
        assert!(snap.contains(&(EventType::SyscallRead, 3)));
        assert!(snap.contains(&(EventType::NetTX, 5)));
    }

    #[test]
    fn test_client_stats_record_and_snapshot() {
        let stats = ClientStats::new();
        stats.record(ClientType::Geth);
        stats.record(ClientType::Geth);
        stats.record(ClientType::Prysm);

        let snap = stats.snapshot();
        assert_eq!(snap.len(), 2);

        let geth_count = snap
            .iter()
            .find(|(client, _)| *client == ClientType::Geth)
            .map(|(_, v)| *v);
        assert_eq!(geth_count, Some(2));

        let prysm_count = snap
            .iter()
            .find(|(client, _)| *client == ClientType::Prysm)
            .map(|(_, v)| *v);
        assert_eq!(prysm_count, Some(1));
    }

    #[test]
    fn test_client_stats_snapshot_resets_counters() {
        let stats = ClientStats::new();
        stats.record(ClientType::Lighthouse);

        let snap1 = stats.snapshot();
        assert_eq!(snap1.len(), 1);

        let snap2 = stats.snapshot();
        assert!(snap2.is_empty());
    }

    #[test]
    fn test_client_stats_record_batch() {
        let stats = ClientStats::new();
        let mut batch = [0u64; CLIENT_TYPE_CARDINALITY];
        batch[ClientType::Geth as usize] = 7;
        batch[ClientType::Prysm as usize] = 2;

        stats.record_batch(&batch);

        let snap = stats.snapshot();
        assert!(snap.contains(&(ClientType::Geth, 7)));
        assert!(snap.contains(&(ClientType::Prysm, 2)));
    }

    #[test]
    fn test_client_stats_capacity_matches_client_types() {
        let stats = ClientStats::new();
        assert_eq!(stats.counts.len(), MAX_CLIENT_TYPE + 1);
    }
}
