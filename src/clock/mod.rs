use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{bail, Result};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

/// Callback invoked when the Ethereum slot changes.
pub type SlotChangedFn = Box<dyn Fn(u64) + Send + Sync>;

/// Ethereum wall clock providing slot timing based on genesis parameters.
pub struct Clock {
    genesis_time: SystemTime,
    seconds_per_slot: u64,
    slots_per_epoch: u64,
    current_slot: Arc<AtomicU64>,
    callbacks: Arc<parking_lot::Mutex<Vec<SlotChangedFn>>>,
    running: Arc<AtomicBool>,
    cancel: CancellationToken,
}

impl std::fmt::Debug for Clock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Clock")
            .field("seconds_per_slot", &self.seconds_per_slot)
            .field("slots_per_epoch", &self.slots_per_epoch)
            .finish()
    }
}

impl Clock {
    /// Create a new clock from genesis parameters.
    pub fn new(
        genesis_time: SystemTime,
        seconds_per_slot: u64,
        slots_per_epoch: u64,
    ) -> Result<Self> {
        if seconds_per_slot == 0 {
            bail!("seconds_per_slot must be > 0");
        }

        if slots_per_epoch == 0 {
            bail!("slots_per_epoch must be > 0");
        }

        let slot = compute_current_slot(genesis_time, seconds_per_slot);

        Ok(Self {
            genesis_time,
            seconds_per_slot,
            slots_per_epoch,
            current_slot: Arc::new(AtomicU64::new(slot)),
            callbacks: Arc::new(parking_lot::Mutex::new(Vec::with_capacity(4))),
            running: Arc::new(AtomicBool::new(false)),
            cancel: CancellationToken::new(),
        })
    }

    /// Return the current Ethereum slot number.
    pub fn current_slot(&self) -> u64 {
        self.current_slot.load(Ordering::Relaxed)
    }

    /// Return the wall-clock start time of the given slot.
    pub fn slot_start_time(&self, slot: u64) -> SystemTime {
        let offset = Duration::from_secs(slot * self.seconds_per_slot);
        self.genesis_time + offset
    }

    /// Return how many milliseconds have elapsed in the current slot.
    #[allow(dead_code)]
    pub fn millis_into_slot(&self) -> u64 {
        let slot = self.current_slot();
        let slot_start = self.slot_start_time(slot);

        SystemTime::now()
            .duration_since(slot_start)
            .unwrap_or(Duration::ZERO)
            .as_millis() as u64
    }

    /// Register a callback that fires when the slot changes.
    pub fn on_slot_changed(&self, f: SlotChangedFn) {
        self.callbacks.lock().push(f);
    }

    /// Start the background slot polling task.
    pub fn start(&self) {
        if self.running.swap(true, Ordering::SeqCst) {
            return; // Already running.
        }

        let genesis_time = self.genesis_time;
        let seconds_per_slot = self.seconds_per_slot;
        let current_slot = Arc::clone(&self.current_slot);
        let callbacks = Arc::clone(&self.callbacks);
        let cancel = self.cancel.clone();

        info!(
            ?genesis_time,
            seconds_per_slot,
            slots_per_epoch = self.slots_per_epoch,
            "clock started",
        );

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(100));

            loop {
                tokio::select! {
                    _ = cancel.cancelled() => {
                        debug!("clock stopped");
                        break;
                    }
                    _ = interval.tick() => {
                        let new_slot = compute_current_slot(
                            genesis_time,
                            seconds_per_slot,
                        );
                        let old_slot = current_slot.load(Ordering::Relaxed);

                        if new_slot != old_slot {
                            current_slot.store(new_slot, Ordering::Relaxed);
                            debug!(slot = new_slot, "slot changed");

                            let cbs = callbacks.lock();
                            for cb in cbs.iter() {
                                cb(new_slot);
                            }
                        }
                    }
                }
            }
        });
    }

    /// Stop the background task.
    pub fn stop(&self) {
        self.cancel.cancel();
        self.running.store(false, Ordering::SeqCst);
    }
}

/// Compute the current slot from genesis time and slot duration.
fn compute_current_slot(genesis_time: SystemTime, seconds_per_slot: u64) -> u64 {
    let elapsed = SystemTime::now()
        .duration_since(genesis_time)
        .unwrap_or(Duration::ZERO);

    elapsed.as_secs() / seconds_per_slot
}

#[cfg(test)]
mod tests {
    use std::time::UNIX_EPOCH;

    use super::*;

    #[test]
    fn test_current_slot_computation() {
        // Genesis 120 seconds ago, 12 seconds per slot => slot 10.
        let genesis = SystemTime::now() - Duration::from_secs(120);
        let slot = compute_current_slot(genesis, 12);
        assert_eq!(slot, 10);
    }

    #[test]
    fn test_current_slot_before_genesis() {
        // Genesis in the future => slot 0.
        let genesis = SystemTime::now() + Duration::from_secs(3600);
        let slot = compute_current_slot(genesis, 12);
        assert_eq!(slot, 0);
    }

    #[test]
    fn test_slot_start_time() {
        let genesis = UNIX_EPOCH + Duration::from_secs(1_606_824_023);
        let clock = Clock::new(genesis, 12, 32).expect("valid params");

        let slot_0_start = clock.slot_start_time(0);
        assert_eq!(slot_0_start, genesis);

        let slot_1_start = clock.slot_start_time(1);
        assert_eq!(slot_1_start, genesis + Duration::from_secs(12));

        let slot_100_start = clock.slot_start_time(100);
        assert_eq!(slot_100_start, genesis + Duration::from_secs(1200));
    }

    #[test]
    fn test_millis_into_slot() {
        // Set genesis so we're partway through a slot.
        let seconds_per_slot = 12u64;
        let genesis = SystemTime::now()
            - Duration::from_millis(
                // 5 full slots + 500ms into current slot.
                5 * seconds_per_slot * 1000 + 500,
            );
        let clock = Clock::new(genesis, seconds_per_slot, 32).expect("valid params");

        let millis = clock.millis_into_slot();
        // Should be approximately 500ms (allow some tolerance for test execution).
        assert!(millis >= 400, "millis={millis}, expected ~500");
        assert!(millis <= 700, "millis={millis}, expected ~500");
    }

    #[test]
    fn test_clock_new_rejects_zero_seconds_per_slot() {
        let result = Clock::new(SystemTime::now(), 0, 32);
        assert!(result.is_err());
        assert!(result
            .expect_err("should fail")
            .to_string()
            .contains("seconds_per_slot"));
    }

    #[test]
    fn test_clock_new_rejects_zero_slots_per_epoch() {
        let result = Clock::new(SystemTime::now(), 12, 0);
        assert!(result.is_err());
        assert!(result
            .expect_err("should fail")
            .to_string()
            .contains("slots_per_epoch"));
    }

    #[tokio::test]
    async fn test_clock_slot_change_callback() {
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::sync::Arc;

        // Set genesis so next slot is imminent (in ~50ms).
        let seconds_per_slot = 1u64;
        let genesis = SystemTime::now() - Duration::from_millis(950);

        let clock = Clock::new(genesis, seconds_per_slot, 32).expect("valid params");

        let observed_slot = Arc::new(AtomicU64::new(0));
        let observed_clone = Arc::clone(&observed_slot);

        clock.on_slot_changed(Box::new(move |slot| {
            observed_clone.store(slot, Ordering::Relaxed);
        }));

        clock.start();

        // Wait for the slot to change.
        tokio::time::sleep(Duration::from_millis(200)).await;

        let slot = observed_slot.load(Ordering::Relaxed);
        assert!(slot >= 1, "expected callback to fire, got slot={slot}");

        clock.stop();
    }
}
