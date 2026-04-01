pub mod event;
pub mod parse;
pub mod stats;

#[cfg(feature = "bpf")]
pub mod bpf;

use std::collections::HashMap;

use anyhow::Result;
use tokio_util::sync::CancellationToken;

use self::event::{ClientType, ParsedEvent, CLIENT_TYPE_CARDINALITY, MAX_EVENT_TYPE};

/// Ring buffer usage statistics.
#[derive(Debug, Clone, Copy, Default)]
#[allow(dead_code)]
pub struct RingbufStats {
    pub used_bytes: usize,
    pub size_bytes: usize,
}

/// Information about a tracked thread.
#[derive(Debug, Clone, Copy)]
pub struct TrackedTidInfo {
    pub pid: u32,
    pub client: ClientType,
}

/// Shared parsed-event batch size for tracer -> sink handoff.
///
/// Under sustained load the tracer and aggregated sink pay this cost on every
/// batch boundary, so a larger batch materially reduces channel sends, receiver
/// wakeups, and fresh Vec allocations while keeping buffering bounded.
pub const PARSED_EVENT_BATCH_SIZE: usize = 4096;

/// Parsed events plus per-batch counters computed in the tracer read loop.
///
/// This lets downstream consumers reuse already-known event/client totals
/// instead of rescanning every batch on the hot path.
#[derive(Debug, Clone)]
pub struct ParsedEventBatch {
    pub events: Vec<ParsedEvent>,
    pub event_type_totals: [u32; MAX_EVENT_TYPE + 1],
    pub client_totals: [u32; CLIENT_TYPE_CARDINALITY],
}

impl ParsedEventBatch {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            events: Vec::with_capacity(capacity),
            event_type_totals: [0; MAX_EVENT_TYPE + 1],
            client_totals: [0; CLIENT_TYPE_CARDINALITY],
        }
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        self.events.len()
    }

    #[inline(always)]
    pub fn push(&mut self, event: ParsedEvent) {
        let event_type_idx = event.raw.event_type as usize;
        let client_idx = usize::from(event.raw.client_type);

        debug_assert!(event_type_idx <= MAX_EVENT_TYPE);
        debug_assert!(client_idx < CLIENT_TYPE_CARDINALITY);

        // Safety: the parser rejects out-of-range client types, and EventType is
        // always constructed from a validated discriminant before reaching this hot path.
        unsafe {
            *self.event_type_totals.get_unchecked_mut(event_type_idx) += 1;
            *self.client_totals.get_unchecked_mut(client_idx) += 1;
        }
        self.events.push(event);
    }

    #[inline(always)]
    pub fn clear(&mut self) {
        self.events.clear();
        self.event_type_totals.fill(0);
        self.client_totals.fill(0);
    }
}

/// Callback for parsed events.
///
/// Event handlers are invoked serially by the ring-buffer read loop, so they
/// can keep mutable local state without per-event synchronization.
pub type EventHandler = Box<dyn FnMut(ParsedEvent) + Send>;

/// Callback for batches of parsed events drained from the ring buffer.
///
/// Batch handlers are invoked serially by the ring-buffer read loop and receive
/// ownership of each parsed batch so they can forward it without cloning.
pub type EventBatchHandler = Box<dyn FnMut(ParsedEventBatch) + Send>;

/// Callback for tracer errors.
pub type ErrorHandler = Box<dyn Fn(anyhow::Error) + Send + Sync>;

/// Callback for ring buffer statistics.
pub type RingbufStatsHandler = Box<dyn Fn(RingbufStats) + Send + Sync>;

/// Tracer manages BPF program loading, attachment, and event reading.
pub trait Tracer: Send {
    /// Load BPF programs, attach to tracepoints/kprobes, start ring buffer reader.
    fn start(
        &mut self,
        ctx: CancellationToken,
    ) -> impl std::future::Future<Output = Result<()>> + Send;

    /// Detach BPF programs and stop the ring buffer reader.
    fn stop(&mut self) -> impl std::future::Future<Output = Result<()>> + Send;

    /// Update the set of tracked PIDs and their client types in the BPF map.
    fn update_pids(&mut self, pids: &[u32], client_types: &HashMap<u32, ClientType>) -> Result<()>;

    /// Update the set of tracked TIDs in the BPF map.
    fn update_tids(&mut self, tids: &[u32], tid_info: &HashMap<u32, TrackedTidInfo>) -> Result<()>;

    /// Register a handler for parsed events.
    fn on_event(&mut self, handler: EventHandler);

    /// Register a handler for parsed event batches.
    fn on_event_batch(&mut self, handler: EventBatchHandler);

    /// Register a handler for tracer errors.
    fn on_error(&mut self, handler: ErrorHandler);

    /// Register a handler for ring buffer statistics.
    fn on_ringbuf_stats(&mut self, handler: RingbufStatsHandler);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tracer::event::{Event, EventType, TypedEvent};

    #[test]
    fn parsed_event_batch_tracks_precomputed_counts() {
        let mut batch = ParsedEventBatch::with_capacity(2);

        batch.push(ParsedEvent {
            raw: Event {
                timestamp_ns: 1,
                pid: 100,
                tid: 100,
                event_type: EventType::FDOpen,
                client_type: 1,
            },
            typed: TypedEvent::FDOpen,
        });
        batch.push(ParsedEvent {
            raw: Event {
                timestamp_ns: 2,
                pid: 200,
                tid: 200,
                event_type: EventType::FDClose,
                client_type: 1,
            },
            typed: TypedEvent::FDClose,
        });

        assert_eq!(batch.len(), 2);
        assert_eq!(batch.event_type_totals[EventType::FDOpen as usize], 1);
        assert_eq!(batch.event_type_totals[EventType::FDClose as usize], 1);
        assert_eq!(batch.client_totals[1], 2);

        batch.clear();
        assert!(batch.is_empty());
        assert_eq!(batch.event_type_totals[EventType::FDOpen as usize], 0);
        assert_eq!(batch.client_totals[1], 0);
    }
}
