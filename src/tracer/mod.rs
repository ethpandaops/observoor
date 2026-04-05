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

use self::event::{ClientType, ParsedEvent};

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
    recycler: Option<Arc<ParsedEventBatchPool>>,
}

impl ParsedEventBatch {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            events: Vec::with_capacity(capacity),
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
        self.events.push(event);
    }

    #[inline(always)]
    pub fn clear(&mut self) {
        self.events.clear();
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

        batch.clear();
        assert!(batch.is_empty());
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
    }
}
