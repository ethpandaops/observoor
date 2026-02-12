use std::collections::HashMap;
use std::time::Duration;

use crate::config::IntervalOverride;

use super::collector::ALL_METRIC_NAMES;
use super::metric::{CounterMetric, GaugeMetric, LatencyMetric, MetricBatch, SamplingMode};

/// Identity key for latency accumulation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct LatencyKey {
    metric_type: &'static str,
    pid: u32,
    client_type: u8,
    device_id: Option<u32>,
    rw: Option<&'static str>,
    sampling_mode: SamplingMode,
    sampling_rate_bits: u32,
}

/// Identity key for counter accumulation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct CounterKey {
    metric_type: &'static str,
    pid: u32,
    client_type: u8,
    device_id: Option<u32>,
    rw: Option<&'static str>,
    port_label: Option<&'static str>,
    direction: Option<&'static str>,
    sampling_mode: SamplingMode,
    sampling_rate_bits: u32,
}

/// Identity key for gauge accumulation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct GaugeKey {
    metric_type: &'static str,
    pid: u32,
    client_type: u8,
    device_id: Option<u32>,
    rw: Option<&'static str>,
    port_label: Option<&'static str>,
    sampling_mode: SamplingMode,
    sampling_rate_bits: u32,
}

#[derive(Debug)]
struct TierAccumulator {
    interval_ms: u16,
    tick_target: u32,
    ticks_elapsed: u32,
    latency: HashMap<LatencyKey, LatencyMetric>,
    counter: HashMap<CounterKey, CounterMetric>,
    gauge: HashMap<GaugeKey, GaugeMetric>,
}

impl TierAccumulator {
    fn new(interval_ms: u16, tick_target: u32) -> Self {
        Self {
            interval_ms,
            tick_target,
            ticks_elapsed: 0,
            latency: HashMap::new(),
            counter: HashMap::new(),
            gauge: HashMap::new(),
        }
    }

    fn is_empty(&self) -> bool {
        self.latency.is_empty() && self.counter.is_empty() && self.gauge.is_empty()
    }
}

/// Accumulates configured slow-tier metrics and releases them at tier boundaries.
pub struct TieredFlushController {
    base_interval_ms: u16,
    /// Maps metric_type -> tier index. Absent = fast tier (pass-through).
    metric_to_tier: HashMap<&'static str, usize>,
    tiers: Vec<TierAccumulator>,
    latency_scratch: Vec<LatencyMetric>,
    counter_scratch: Vec<CounterMetric>,
    gauge_scratch: Vec<GaugeMetric>,
}

impl TieredFlushController {
    /// Creates a tiered flush controller from base interval and overrides.
    pub fn new(base_interval: Duration, overrides: &[IntervalOverride]) -> Self {
        let base_interval_ms_u128 = base_interval.as_millis().max(1);
        let base_interval_ms = to_u16_ms(base_interval_ms_u128);

        let mut metric_to_tier = HashMap::new();
        let mut tiers = Vec::with_capacity(overrides.len());

        for interval_override in overrides {
            let override_ms_u128 = interval_override.interval.as_millis();
            let override_interval_ms = to_u16_ms(override_ms_u128);
            let tick_target = u32::try_from((override_ms_u128 / base_interval_ms_u128).max(1))
                .unwrap_or(u32::MAX);

            let tier_idx = tiers.len();
            tiers.push(TierAccumulator::new(override_interval_ms, tick_target));

            for metric_name in &interval_override.metrics {
                if let Some(canonical_name) = canonical_metric_name(metric_name) {
                    metric_to_tier.insert(canonical_name, tier_idx);
                }
            }
        }

        Self {
            base_interval_ms,
            metric_to_tier,
            tiers,
            latency_scratch: Vec::new(),
            counter_scratch: Vec::new(),
            gauge_scratch: Vec::new(),
        }
    }

    /// Processes one base-interval tick.
    ///
    /// Slow-tier metrics are absorbed into per-tier accumulators.
    /// Fast-tier metrics remain in `batch` and are exported immediately.
    pub fn process_tick(&mut self, batch: &mut MetricBatch) {
        if self.tiers.is_empty() {
            return;
        }

        self.absorb_slow_metrics(batch);

        for tier in &mut self.tiers {
            tier.ticks_elapsed = tier.ticks_elapsed.saturating_add(1);
            if tier.ticks_elapsed >= tier.tick_target {
                Self::drain_tier_into_batch(tier, batch, tier.interval_ms);
                tier.ticks_elapsed = 0;
            }
        }
    }

    /// Forces emission of all accumulated slow-tier metrics.
    ///
    /// Used on slot rotation and shutdown so no tiered data is left behind.
    pub fn force_flush_all(&mut self, batch: &mut MetricBatch) {
        if self.tiers.is_empty() {
            return;
        }

        self.absorb_slow_metrics(batch);

        for tier in &mut self.tiers {
            if tier.is_empty() {
                tier.ticks_elapsed = 0;
                continue;
            }

            // If a force flush happens before the first full tick boundary,
            // still emit a non-zero partial interval.
            let elapsed_ticks = tier.ticks_elapsed.max(1);
            let partial_interval_ms = to_u16_ms(
                u128::from(self.base_interval_ms).saturating_mul(u128::from(elapsed_ticks)),
            );

            Self::drain_tier_into_batch(tier, batch, partial_interval_ms);
            tier.ticks_elapsed = 0;
        }
    }

    fn absorb_slow_metrics(&mut self, batch: &mut MetricBatch) {
        std::mem::swap(&mut self.latency_scratch, &mut batch.latency);
        for metric in self.latency_scratch.drain(..) {
            if let Some(&tier_idx) = self.metric_to_tier.get(metric.metric_type) {
                if let Some(tier) = self.tiers.get_mut(tier_idx) {
                    Self::merge_latency(tier, metric);
                    continue;
                }
            }
            batch.latency.push(metric);
        }

        std::mem::swap(&mut self.counter_scratch, &mut batch.counter);
        for metric in self.counter_scratch.drain(..) {
            if let Some(&tier_idx) = self.metric_to_tier.get(metric.metric_type) {
                if let Some(tier) = self.tiers.get_mut(tier_idx) {
                    Self::merge_counter(tier, metric);
                    continue;
                }
            }
            batch.counter.push(metric);
        }

        std::mem::swap(&mut self.gauge_scratch, &mut batch.gauge);
        for metric in self.gauge_scratch.drain(..) {
            if let Some(&tier_idx) = self.metric_to_tier.get(metric.metric_type) {
                if let Some(tier) = self.tiers.get_mut(tier_idx) {
                    Self::merge_gauge(tier, metric);
                    continue;
                }
            }
            batch.gauge.push(metric);
        }
    }

    fn merge_latency(tier: &mut TierAccumulator, metric: LatencyMetric) {
        let key = LatencyKey {
            metric_type: metric.metric_type,
            pid: metric.pid,
            client_type: metric.client_type as u8,
            device_id: metric.device_id,
            rw: metric.rw,
            sampling_mode: metric.sampling_mode,
            sampling_rate_bits: metric.sampling_rate.to_bits(),
        };

        if let Some(existing) = tier.latency.get_mut(&key) {
            existing.sum = existing.sum.saturating_add(metric.sum);
            existing.count = existing.count.saturating_add(metric.count);
            existing.min = existing.min.min(metric.min);
            existing.max = existing.max.max(metric.max);
            for (dst, src) in existing.histogram.iter_mut().zip(metric.histogram.iter()) {
                *dst = dst.saturating_add(*src);
            }
            return;
        }

        tier.latency.insert(key, metric);
    }

    fn merge_counter(tier: &mut TierAccumulator, metric: CounterMetric) {
        let key = CounterKey {
            metric_type: metric.metric_type,
            pid: metric.pid,
            client_type: metric.client_type as u8,
            device_id: metric.device_id,
            rw: metric.rw,
            port_label: metric.port_label,
            direction: metric.direction,
            sampling_mode: metric.sampling_mode,
            sampling_rate_bits: metric.sampling_rate.to_bits(),
        };

        if let Some(existing) = tier.counter.get_mut(&key) {
            existing.sum = existing.sum.saturating_add(metric.sum);
            existing.count = existing.count.saturating_add(metric.count);
            return;
        }

        tier.counter.insert(key, metric);
    }

    fn merge_gauge(tier: &mut TierAccumulator, metric: GaugeMetric) {
        let key = GaugeKey {
            metric_type: metric.metric_type,
            pid: metric.pid,
            client_type: metric.client_type as u8,
            device_id: metric.device_id,
            rw: metric.rw,
            port_label: metric.port_label,
            sampling_mode: metric.sampling_mode,
            sampling_rate_bits: metric.sampling_rate.to_bits(),
        };

        if let Some(existing) = tier.gauge.get_mut(&key) {
            existing.sum = existing.sum.saturating_add(metric.sum);
            existing.count = existing.count.saturating_add(metric.count);
            existing.min = existing.min.min(metric.min);
            existing.max = existing.max.max(metric.max);
            return;
        }

        tier.gauge.insert(key, metric);
    }

    fn drain_tier_into_batch(
        tier: &mut TierAccumulator,
        batch: &mut MetricBatch,
        interval_ms: u16,
    ) {
        for (_, mut metric) in tier.latency.drain() {
            metric.window.interval_ms = interval_ms;
            batch.latency.push(metric);
        }

        for (_, mut metric) in tier.counter.drain() {
            metric.window.interval_ms = interval_ms;
            batch.counter.push(metric);
        }

        for (_, mut metric) in tier.gauge.drain() {
            metric.window.interval_ms = interval_ms;
            batch.gauge.push(metric);
        }
    }
}

fn canonical_metric_name(name: &str) -> Option<&'static str> {
    ALL_METRIC_NAMES
        .iter()
        .find(|metric| **metric == name)
        .copied()
}

fn to_u16_ms(ms: u128) -> u16 {
    u16::try_from(ms).unwrap_or(u16::MAX)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::{Duration, SystemTime};

    use crate::tracer::event::ClientType;

    use super::*;
    use crate::sink::aggregated::metric::{
        BatchMetadata, CounterMetric, GaugeMetric, LatencyMetric, MetricBatch, SamplingMode,
        SlotInfo, WindowInfo,
    };

    fn test_batch() -> MetricBatch {
        MetricBatch {
            metadata: BatchMetadata {
                client_name: Arc::from("node-a"),
                network_name: Arc::from("mainnet"),
                updated_time: SystemTime::UNIX_EPOCH,
            },
            latency: Vec::new(),
            counter: Vec::new(),
            gauge: Vec::new(),
            cpu_util: Vec::new(),
            #[cfg(feature = "bpf")]
            memory_usage: Vec::new(),
            #[cfg(feature = "bpf")]
            process_io_usage: Vec::new(),
            #[cfg(feature = "bpf")]
            process_fd_usage: Vec::new(),
            #[cfg(feature = "bpf")]
            process_sched_usage: Vec::new(),
        }
    }

    fn latency_metric(
        metric_type: &'static str,
        start: SystemTime,
        sum: i64,
        count: u32,
        min: i64,
        max: i64,
    ) -> LatencyMetric {
        LatencyMetric {
            metric_type,
            window: WindowInfo {
                start,
                interval_ms: 100,
            },
            slot: SlotInfo {
                number: 100,
                start_time: SystemTime::UNIX_EPOCH,
            },
            pid: 42,
            client_type: ClientType::Geth,
            device_id: None,
            rw: None,
            sampling_mode: SamplingMode::None,
            sampling_rate: 1.0,
            sum,
            count,
            min,
            max,
            histogram: [1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        }
    }

    fn counter_metric(
        metric_type: &'static str,
        start: SystemTime,
        sum: i64,
        count: u32,
    ) -> CounterMetric {
        CounterMetric {
            metric_type,
            window: WindowInfo {
                start,
                interval_ms: 100,
            },
            slot: SlotInfo {
                number: 100,
                start_time: SystemTime::UNIX_EPOCH,
            },
            pid: 42,
            client_type: ClientType::Geth,
            device_id: None,
            rw: None,
            port_label: None,
            direction: None,
            sampling_mode: SamplingMode::None,
            sampling_rate: 1.0,
            sum,
            count,
        }
    }

    fn gauge_metric(
        metric_type: &'static str,
        start: SystemTime,
        sum: i64,
        count: u32,
        min: i64,
        max: i64,
    ) -> GaugeMetric {
        GaugeMetric {
            metric_type,
            window: WindowInfo {
                start,
                interval_ms: 100,
            },
            slot: SlotInfo {
                number: 100,
                start_time: SystemTime::UNIX_EPOCH,
            },
            pid: 42,
            client_type: ClientType::Geth,
            device_id: None,
            rw: None,
            port_label: Some("el_p2p_tcp"),
            sampling_mode: SamplingMode::None,
            sampling_rate: 1.0,
            sum,
            count,
            min,
            max,
        }
    }

    #[test]
    fn test_process_tick_pass_through_without_overrides() {
        let mut controller = TieredFlushController::new(Duration::from_millis(100), &[]);

        let mut batch = test_batch();
        batch.latency.push(latency_metric(
            "syscall_read",
            SystemTime::UNIX_EPOCH,
            10,
            1,
            10,
            10,
        ));

        controller.process_tick(&mut batch);

        assert_eq!(batch.latency.len(), 1);
        assert_eq!(batch.latency[0].metric_type, "syscall_read");
    }

    #[test]
    fn test_process_tick_merges_and_flushes_on_tier_boundary() {
        let overrides = vec![IntervalOverride {
            metrics: vec!["syscall_futex".to_string()],
            interval: Duration::from_millis(500),
        }];

        let mut controller = TieredFlushController::new(Duration::from_millis(100), &overrides);

        let base = SystemTime::UNIX_EPOCH;

        for tick in 0..4 {
            let mut batch = test_batch();
            batch.latency.push(latency_metric(
                "syscall_futex",
                base + Duration::from_millis(tick * 100),
                10,
                1,
                9,
                11,
            ));
            if tick == 0 {
                batch
                    .latency
                    .push(latency_metric("syscall_read", base, 3, 1, 3, 3));
            }

            controller.process_tick(&mut batch);

            if tick == 0 {
                assert_eq!(batch.latency.len(), 1);
                assert_eq!(batch.latency[0].metric_type, "syscall_read");
            } else {
                assert!(batch.latency.is_empty());
            }
        }

        let mut tick5 = test_batch();
        tick5.latency.push(latency_metric(
            "syscall_futex",
            base + Duration::from_millis(400),
            20,
            2,
            8,
            12,
        ));

        controller.process_tick(&mut tick5);

        assert_eq!(tick5.latency.len(), 1);
        let flushed = &tick5.latency[0];
        assert_eq!(flushed.metric_type, "syscall_futex");
        assert_eq!(flushed.window.interval_ms, 500);
        assert_eq!(flushed.window.start, base);
        assert_eq!(flushed.sum, 60);
        assert_eq!(flushed.count, 6);
        assert_eq!(flushed.min, 8);
        assert_eq!(flushed.max, 12);
        assert_eq!(flushed.histogram[0], 5);
    }

    #[test]
    fn test_force_flush_all_emits_partial_window() {
        let overrides = vec![IntervalOverride {
            metrics: vec!["page_fault_major".to_string(), "tcp_rtt".to_string()],
            interval: Duration::from_secs(1),
        }];

        let mut controller = TieredFlushController::new(Duration::from_millis(100), &overrides);

        for _ in 0..2 {
            let mut batch = test_batch();
            batch.counter.push(counter_metric(
                "page_fault_major",
                SystemTime::UNIX_EPOCH,
                1,
                1,
            ));
            batch.gauge.push(gauge_metric(
                "tcp_rtt",
                SystemTime::UNIX_EPOCH,
                100,
                1,
                90,
                110,
            ));
            controller.process_tick(&mut batch);
            assert!(batch.counter.is_empty());
            assert!(batch.gauge.is_empty());
        }

        let mut partial = test_batch();
        partial.counter.push(counter_metric(
            "page_fault_major",
            SystemTime::UNIX_EPOCH,
            3,
            3,
        ));
        partial
            .counter
            .push(counter_metric("net_io", SystemTime::UNIX_EPOCH, 2048, 1));
        partial.gauge.push(gauge_metric(
            "tcp_rtt",
            SystemTime::UNIX_EPOCH,
            300,
            3,
            80,
            120,
        ));

        controller.force_flush_all(&mut partial);

        let slow_counter = partial
            .counter
            .iter()
            .find(|m| m.metric_type == "page_fault_major")
            .expect("slow counter metric should be flushed");
        assert_eq!(slow_counter.window.interval_ms, 200);
        assert_eq!(slow_counter.sum, 5);
        assert_eq!(slow_counter.count, 5);

        let fast_counter = partial
            .counter
            .iter()
            .find(|m| m.metric_type == "net_io")
            .expect("fast counter metric should pass through");
        assert_eq!(fast_counter.sum, 2048);

        let slow_gauge = partial
            .gauge
            .iter()
            .find(|m| m.metric_type == "tcp_rtt")
            .expect("slow gauge metric should be flushed");
        assert_eq!(slow_gauge.window.interval_ms, 200);
        assert_eq!(slow_gauge.sum, 500);
        assert_eq!(slow_gauge.count, 5);
        assert_eq!(slow_gauge.min, 80);
        assert_eq!(slow_gauge.max, 120);
    }
}
