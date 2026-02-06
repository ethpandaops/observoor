pub mod event;
pub mod parse;
pub mod stats;

#[cfg(feature = "bpf")]
pub mod bpf;

use std::collections::HashMap;

use anyhow::Result;
use tokio_util::sync::CancellationToken;

use self::event::{ClientType, ParsedEvent};

/// Ring buffer usage statistics.
#[derive(Debug, Clone, Copy, Default)]
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

/// Callback for parsed events.
pub type EventHandler = Box<dyn Fn(ParsedEvent) + Send + Sync>;

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

    /// Register a handler for tracer errors.
    fn on_error(&mut self, handler: ErrorHandler);

    /// Register a handler for ring buffer statistics.
    fn on_ringbuf_stats(&mut self, handler: RingbufStatsHandler);
}
