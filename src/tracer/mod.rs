pub mod event;
pub mod parse;
pub mod stats;

#[cfg(feature = "bpf")]
pub mod bpf;

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use parking_lot::Mutex;
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
/// batch boundary, so using 16k-event batches further cuts channel/pool
/// boundary overhead while the sink keeps the same total queued-event budget by
/// using fewer batch slots.
pub const PARSED_EVENT_BATCH_SIZE: usize = 16384;
#[derive(Clone)]
pub struct ParsedEventBatch {
    pub events: Vec<ParsedEvent>,
    event_totals: [u32; MAX_EVENT_TYPE + 1],
    client_totals: [u32; CLIENT_TYPE_CARDINALITY],
    recycler: Option<Arc<ParsedEventBatchPool>>,
}

impl ParsedEventBatch {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            events: Vec::with_capacity(capacity),
            event_totals: [0; MAX_EVENT_TYPE + 1],
            client_totals: [0; CLIENT_TYPE_CARDINALITY],
            recycler: None,
        }
    }

    #[cfg_attr(not(feature = "bpf"), allow(dead_code))]
    pub(crate) fn checkout(pool: &Arc<ParsedEventBatchPool>) -> Self {
        let mut batch = pool
            .inner
            .lock()
            .pop()
            .unwrap_or_else(|| Self::with_capacity(PARSED_EVENT_BATCH_SIZE));
        batch.recycler = Some(Arc::clone(pool));
        batch
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
        self.record_event(&event);
        self.events.push(event);
    }

    #[inline(always)]
    pub fn clear(&mut self) {
        self.events.clear();
        self.event_totals.fill(0);
        self.client_totals.fill(0);
    }

    #[inline(always)]
    pub fn event_totals(&self) -> &[u32; MAX_EVENT_TYPE + 1] {
        &self.event_totals
    }

    #[inline(always)]
    pub fn client_totals(&self) -> &[u32; CLIENT_TYPE_CARDINALITY] {
        &self.client_totals
    }

    #[inline(always)]
    fn record_event(&mut self, event: &ParsedEvent) {
        let event_type = event.raw.event_type as usize;
        if let Some(total) = self.event_totals.get_mut(event_type) {
            *total += 1;
        }

        let client_type = event.raw.client_type() as usize;
        if let Some(total) = self.client_totals.get_mut(client_type) {
            *total += 1;
        }

        let secondary_event_type = event.raw.secondary_event_type_raw() as usize;
        if secondary_event_type == 0 {
            return;
        }

        if let Some(total) = self.event_totals.get_mut(secondary_event_type) {
            *total += 1;
        }

        let secondary_client_type = event.raw.secondary_client_type_raw() as usize;
        if let Some(total) = self.client_totals.get_mut(secondary_client_type) {
            *total += 1;
        }
    }

    pub fn recycle(mut self) {
        let Some(pool) = self.recycler.take() else {
            return;
        };

        self.clear();
        pool.inner.lock().push(self);
    }
}

#[derive(Default)]
pub(crate) struct ParsedEventBatchPool {
    inner: Mutex<Vec<ParsedEventBatch>>,
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
    fn parsed_event_batch_pushes_and_clears_events() {
        let mut batch = ParsedEventBatch::with_capacity(2);

        batch.push(ParsedEvent {
            raw: Event::new(1, 100, 100, EventType::FDOpen, 1),
            typed: TypedEvent::FDOpen,
        });
        batch.push(ParsedEvent {
            raw: Event::new(2, 200, 200, EventType::FDClose, 1),
            typed: TypedEvent::FDClose,
        });

        assert_eq!(batch.len(), 2);
        assert_eq!(batch.event_totals()[EventType::FDOpen as usize], 1);
        assert_eq!(batch.event_totals()[EventType::FDClose as usize], 1);
        assert_eq!(batch.client_totals()[1], 2);

        batch.clear();
        assert!(batch.is_empty());
        assert!(batch.event_totals().iter().all(|count| *count == 0));
        assert!(batch.client_totals().iter().all(|count| *count == 0));
    }

    #[test]
    fn parsed_event_batch_recycle_reuses_storage() {
        let pool = Arc::new(ParsedEventBatchPool::default());
        let mut batch = ParsedEventBatch::checkout(&pool);

        batch.push(ParsedEvent {
            raw: Event::new(1, 100, 100, EventType::FDOpen, 1),
            typed: TypedEvent::FDOpen,
        });

        let initial_capacity = batch.events.capacity();
        batch.recycle();

        let recycled = ParsedEventBatch::checkout(&pool);
        assert!(recycled.is_empty());
        assert_eq!(recycled.events.capacity(), initial_capacity);
        assert!(recycled.event_totals().iter().all(|count| *count == 0));
        assert!(recycled.client_totals().iter().all(|count| *count == 0));
    }

    #[test]
    fn parsed_event_batch_counts_secondary_logical_events() {
        let mut batch = ParsedEventBatch::with_capacity(1);

        batch.push(ParsedEvent {
            raw: Event::new(1, 100, 100, EventType::SchedSwitch, 1)
                .with_secondary_logical_event(EventType::SchedRunqueue, 2),
            typed: TypedEvent::SchedCombined(crate::tracer::event::SchedCombinedEvent {
                on_cpu_ns: 10,
                cpu_id: 3,
                next_pid: 200,
                next_tid: 200,
                next_client_type: 2,
                runqueue_ns: 20,
                off_cpu_ns: 30,
            }),
        });

        assert_eq!(batch.event_totals()[EventType::SchedSwitch as usize], 1);
        assert_eq!(batch.event_totals()[EventType::SchedRunqueue as usize], 1);
        assert_eq!(batch.client_totals()[1], 1);
        assert_eq!(batch.client_totals()[2], 1);
    }
}
