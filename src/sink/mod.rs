pub mod aggregated;

use std::time::SystemTime;

use anyhow::Result;

use crate::beacon::SyncStatus;
use crate::tracer::event::ParsedEvent;

/// Sink consumes parsed events and exports them.
pub trait Sink: Send {
    /// Returns the sink's name for logging.
    fn name(&self) -> &str;

    /// Initialize the sink.
    fn start(
        &mut self,
        ctx: tokio_util::sync::CancellationToken,
    ) -> impl std::future::Future<Output = Result<()>> + Send;

    /// Shut down the sink.
    fn stop(&mut self) -> impl std::future::Future<Output = Result<()>> + Send;

    /// Process a single parsed event.
    fn handle_event(&self, event: ParsedEvent);

    /// Called at slot boundaries.
    fn on_slot_changed(&self, new_slot: u64, slot_start: SystemTime);

    /// Update the current sync state from the beacon node.
    fn set_sync_state(&self, status: SyncStatus);
}
