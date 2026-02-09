pub mod ports;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
#[cfg(feature = "bpf")]
use prometheus::Counter;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::beacon::{self, BeaconClient};
use crate::clock::Clock;
use crate::config::Config;
use crate::export::health::HealthMetrics;
use crate::export::ClickHouseWriter;
use crate::pid::{self, CompositeDiscovery, Discovery};
use crate::sink::aggregated::clickhouse::ClickHouseExporter;
use crate::sink::aggregated::exporter::Exporter;
use crate::sink::aggregated::http::HttpExporter;
use crate::sink::aggregated::AggregatedSink;
use crate::sink::Sink;
use crate::tracer::event::{ClientType, CLIENT_TYPE_CARDINALITY};
#[cfg(feature = "bpf")]
use crate::tracer::event::{EventType, MAX_CLIENT_TYPE, MAX_EVENT_TYPE};
use crate::tracer::stats::EventStats;

#[cfg(feature = "bpf")]
use crate::tracer::bpf::BpfTracer;
#[cfg(feature = "bpf")]
use crate::tracer::Tracer;

/// Agent orchestrates all components: tracer, sinks, beacon, clock, PID discovery.
pub struct Agent {
    cfg: Config,
    health: Arc<HealthMetrics>,
    clock: Option<Clock>,
    sink: Option<Arc<AggregatedSink>>,
    ch_writer: Option<ClickHouseWriter>,
    #[cfg(feature = "bpf")]
    tracer: Option<Arc<tokio::sync::Mutex<BpfTracer>>>,
    captured_stats: Arc<EventStats>,
    cancel: CancellationToken,
}

#[cfg(feature = "bpf")]
fn build_event_type_counters(health: &HealthMetrics) -> Vec<Option<Counter>> {
    let mut counters = vec![None; MAX_EVENT_TYPE + 1];
    for raw in 1..=MAX_EVENT_TYPE {
        if let Ok(raw_u8) = u8::try_from(raw) {
            if let Some(event_type) = EventType::from_u8(raw_u8) {
                if let Some(slot) = counters.get_mut(raw) {
                    *slot = Some(
                        health
                            .events_by_type
                            .with_label_values(&[event_type.as_str()]),
                    );
                }
            }
        }
    }
    counters
}

#[cfg(feature = "bpf")]
fn build_client_type_counters(health: &HealthMetrics) -> Vec<Option<Counter>> {
    let mut counters = vec![None; MAX_CLIENT_TYPE + 1];
    for raw in 0..=MAX_CLIENT_TYPE {
        if let Ok(raw_u8) = u8::try_from(raw) {
            if let Some(client_type) = ClientType::from_u8(raw_u8) {
                if let Some(slot) = counters.get_mut(raw) {
                    *slot = Some(
                        health
                            .events_by_client
                            .with_label_values(&[client_type.as_str()]),
                    );
                }
            }
        }
    }
    counters
}

impl Agent {
    /// Creates a new Agent, initializing health metrics.
    pub fn new(cfg: Config) -> Result<Self> {
        let health =
            Arc::new(HealthMetrics::new(&cfg.health.addr).context("creating health metrics")?);

        Ok(Self {
            cfg,
            health,
            clock: None,
            sink: None,
            ch_writer: None,
            #[cfg(feature = "bpf")]
            tracer: None,
            captured_stats: Arc::new(EventStats::new()),
            cancel: CancellationToken::new(),
        })
    }

    /// Start all components and begin observation.
    pub async fn start(&mut self) -> Result<()> {
        // 0. Start health metrics server (before migrations so probes respond).
        self.health
            .start()
            .await
            .context("starting health metrics server")?;
        info!("health metrics server started");

        // 1. Run migrations if enabled.
        if self.cfg.sinks.aggregated.enabled
            && self.cfg.sinks.aggregated.clickhouse.migrations.enabled
        {
            self.run_migrations().await?;
        }

        // 2. Fetch genesis and spec from beacon node.
        let beacon = self.create_beacon_client()?;

        let genesis = beacon
            .fetch_genesis()
            .await
            .context("fetching beacon genesis")?;
        info!(genesis_time = ?genesis.genesis_time, "fetched genesis info");

        let spec = beacon.fetch_spec().await.context("fetching beacon spec")?;
        info!(
            seconds_per_slot = spec.seconds_per_slot,
            slots_per_epoch = spec.slots_per_epoch,
            "fetched chain spec",
        );

        // 3. Fetch initial sync state (continue even if it fails).
        let initial_sync = match beacon.fetch_sync_status().await {
            Ok(status) => {
                info!(
                    is_syncing = status.is_syncing,
                    is_optimistic = status.is_optimistic,
                    el_offline = status.el_offline,
                    head_slot = status.head_slot,
                    sync_distance = status.sync_distance,
                    "fetched initial sync state",
                );
                status
            }
            Err(e) => {
                warn!(error = %e, "failed to fetch initial sync status, using defaults");
                beacon::SyncStatus::default()
            }
        };
        self.update_sync_metrics(&initial_sync);

        // 4. Create wall clock.
        let clock = Clock::new(
            genesis.genesis_time,
            spec.seconds_per_slot,
            spec.slots_per_epoch,
        )
        .context("creating clock")?;

        // 5. Discover PIDs.
        let disc = CompositeDiscovery::new(&self.cfg.pid);
        let pids = disc.discover().context("discovering PIDs")?;

        if pids.is_empty() {
            warn!("no PIDs discovered, tracer will have no targets");
        }

        self.health.pids_tracked.set(pids.len() as f64);
        let client_types = pid::resolve_client_types(&pids);
        self.update_pids_by_client(&client_types);

        // 5b. Discover well-known ports for port whitelist.
        let port_infos = ports::discover_ports(&pids, &client_types);
        let all_ports = ports::all_tracked_ports(&port_infos);
        if !all_ports.is_empty() {
            let port_list: Vec<u16> = all_ports.iter().copied().collect();
            info!(ports = ?port_list, "discovered well-known ports");
        }

        // 6. Create and configure aggregated sink.
        let mut sink = AggregatedSink::new(
            self.cfg.sinks.aggregated.clone(),
            self.cfg.meta_client_name.clone(),
            self.cfg.meta_network_name.clone(),
        );
        sink.set_port_whitelist(all_ports);

        // Add ClickHouse exporter if enabled.
        if self.cfg.sinks.aggregated.clickhouse.enabled {
            let mut writer = ClickHouseWriter::new(self.cfg.sinks.aggregated.clickhouse.clone());
            writer.start().await.context("starting ClickHouse writer")?;

            let pool = writer
                .pool()
                .expect("pool should exist after start")
                .clone();

            let ch_exporter = ClickHouseExporter::new(
                pool,
                self.cfg.sinks.aggregated.clickhouse.database.clone(),
                Some(Arc::clone(&self.health)),
            );
            sink.add_exporter(Exporter::ClickHouse(ch_exporter));
            self.ch_writer = Some(writer);

            info!(
                endpoint = %self.cfg.sinks.aggregated.clickhouse.endpoint,
                "ClickHouse exporter configured",
            );
        }

        // Add HTTP exporter if enabled.
        if self.cfg.sinks.aggregated.http.enabled {
            let http_exporter = HttpExporter::new(self.cfg.sinks.aggregated.http.clone());
            sink.add_exporter(Exporter::Http(http_exporter));

            info!(
                address = %self.cfg.sinks.aggregated.http.address,
                "HTTP exporter configured",
            );
        }

        // Start sink (spawns background processing task).
        sink.start(self.cancel.child_token())
            .await
            .context("starting aggregated sink")?;

        let sink = Arc::new(sink);

        // Set initial sync state.
        sink.set_sync_state(initial_sync);

        // 7. Register slot change callback.
        {
            let health = Arc::clone(&self.health);
            let sink_ref = Arc::clone(&sink);
            let genesis_time = genesis.genesis_time;
            let seconds_per_slot = spec.seconds_per_slot;

            clock.on_slot_changed(Box::new(move |slot| {
                health.current_slot.set(slot as f64);
                health.slots_flushed.inc();

                let slot_start = genesis_time + Duration::from_secs(slot * seconds_per_slot);
                sink_ref.on_slot_changed(slot, slot_start);
            }));
        }

        // 8. Seed sinks with current slot.
        let initial_slot = clock.current_slot();
        self.health.current_slot.set(initial_slot as f64);
        sink.on_slot_changed(initial_slot, clock.slot_start_time(initial_slot));

        // 9. Start the clock.
        clock.start();
        self.clock = Some(clock);

        // 10. Set up BPF tracer (Linux with bpf feature only).
        #[cfg(feature = "bpf")]
        {
            let ring_buf_size = u32::try_from(self.cfg.ring_buffer_size).unwrap_or(u32::MAX);
            let mut tracer = BpfTracer::new(ring_buf_size);

            // Register event handler.
            let health_ev = Arc::clone(&self.health);
            let captured_stats = Arc::clone(&self.captured_stats);
            let sink_ev = Arc::clone(&sink);
            let event_type_counters = build_event_type_counters(&health_ev);
            let client_type_counters = build_client_type_counters(&health_ev);
            tracer.on_event(Box::new(move |event| {
                health_ev.events_received.inc();
                captured_stats.record(event.raw.event_type);

                if let Some(counter) = event_type_counters
                    .get(usize::from(event.raw.event_type as u8))
                    .and_then(Option::as_ref)
                {
                    counter.inc();
                }

                if let Some(counter) = client_type_counters
                    .get(usize::from(event.raw.client_type as u8))
                    .and_then(Option::as_ref)
                {
                    counter.inc();
                }

                sink_ev.handle_event(event);
            }));

            // Register error handler.
            let health_err = Arc::clone(&self.health);
            tracer.on_error(Box::new(move |_err| {
                health_err.events_dropped.inc();
            }));

            // Register ringbuf stats handler.
            let health_rb = Arc::clone(&self.health);
            self.health
                .ringbuf_capacity_bytes
                .set(f64::from(ring_buf_size));
            tracer.on_ringbuf_stats(Box::new(move |stats| {
                health_rb.ringbuf_used.set(stats.used_bytes as f64);
            }));

            // Start tracer (load BPF programs, attach, start ring buffer reader).
            tracer
                .start(self.cancel.child_token())
                .await
                .context("starting BPF tracer")?;

            // Populate PID and TID maps.
            tracer
                .update_pids(&pids, &client_types)
                .context("updating PIDs in BPF map")?;

            let (tids, tid_info) = pid::discover_tids(&pids, &client_types);
            tracer
                .update_tids(&tids, &tid_info)
                .context("updating TIDs in BPF map")?;

            self.health.tid_discovery_count.set(tids.len() as f64);
            info!(count = tids.len(), "updated tracked TIDs");

            let tracer = Arc::new(tokio::sync::Mutex::new(tracer));
            self.tracer = Some(tracer);
        }

        self.sink = Some(sink);

        // 11. Start background monitors.
        self.spawn_sync_monitor(beacon);
        self.spawn_pid_monitor();
        self.spawn_event_stats_reporter();

        info!("agent fully started");

        Ok(())
    }

    /// Gracefully stop all components.
    pub async fn stop(&mut self) -> Result<()> {
        // Signal all background tasks to stop.
        self.cancel.cancel();

        // Stop clock so slot callbacks cannot rotate buffers during shutdown.
        if let Some(clock) = &self.clock {
            clock.stop();
        }

        // Wait for sink task to finish final flush/export shutdown.
        if let Some(sink) = &self.sink {
            sink.wait_for_shutdown().await;
        }

        // Stop tracer.
        #[cfg(feature = "bpf")]
        if let Some(tracer) = &self.tracer {
            let mut t = tracer.lock().await;
            if let Err(e) = t.stop().await {
                error!(error = %e, "error stopping tracer");
            }
        }

        // Sink stop is handled by cancellation token in the spawned task.

        // Stop ClickHouse writer.
        if let Some(writer) = &mut self.ch_writer {
            if let Err(e) = writer.stop().await {
                error!(error = %e, "error stopping ClickHouse writer");
            }
        }

        // Stop health metrics server.
        self.health.stop().await?;

        Ok(())
    }

    /// Create a beacon client with metrics callback.
    fn create_beacon_client(&self) -> Result<beacon::Client> {
        let client = beacon::Client::new(&self.cfg.beacon).context("creating beacon client")?;

        let health = Arc::clone(&self.health);
        let client = client.with_metrics(Box::new(move |endpoint, status, duration| {
            health
                .beacon_requests_total
                .with_label_values(&[endpoint, status])
                .inc();
            health
                .beacon_request_duration
                .with_label_values(&[endpoint])
                .observe(duration.as_secs_f64());
        }));

        Ok(client)
    }

    /// Run ClickHouse migrations.
    async fn run_migrations(&self) -> Result<()> {
        info!("running ClickHouse migrations...");

        let ch_cfg = &self.cfg.sinks.aggregated.clickhouse;

        // Build TCP DSN for clickhouse-rs.
        let mut dsn = "tcp://".to_string();
        if !ch_cfg.username.is_empty() {
            dsn.push_str(&ch_cfg.username);
            if !ch_cfg.password.is_empty() {
                dsn.push(':');
                dsn.push_str(&ch_cfg.password);
            }
            dsn.push('@');
        }
        dsn.push_str(&ch_cfg.endpoint);
        dsn.push('/');
        dsn.push_str(&ch_cfg.database);

        let pool = clickhouse_rs::Pool::new(dsn);
        let migrator = crate::migrate::ClickHouseMigrator::new(pool);

        use crate::migrate::Migrator;
        migrator
            .up()
            .await
            .context("applying ClickHouse migrations")?;

        info!("ClickHouse migrations applied");

        Ok(())
    }

    /// Update sync-related Prometheus metrics.
    fn update_sync_metrics(&self, status: &beacon::SyncStatus) {
        self.health
            .is_syncing
            .set(if status.is_syncing { 1.0 } else { 0.0 });
        self.health
            .is_optimistic
            .set(if status.is_optimistic { 1.0 } else { 0.0 });
        self.health
            .el_offline
            .set(if status.el_offline { 1.0 } else { 0.0 });
        self.health
            .beacon_sync_distance
            .set(status.sync_distance as f64);
    }

    /// Update PIDs-by-client metrics.
    fn update_pids_by_client(&self, client_types: &HashMap<u32, ClientType>) {
        Self::set_pids_by_client_metrics(&self.health, client_types);
    }

    /// Set PIDs-by-client metrics from resolved client types.
    fn set_pids_by_client_metrics(health: &HealthMetrics, client_types: &HashMap<u32, ClientType>) {
        let mut counts = [0usize; CLIENT_TYPE_CARDINALITY];
        for ct in client_types.values() {
            counts[*ct as usize] += 1;
        }

        for ct in ClientType::all_with_unknown() {
            let name = ct.as_str();
            let count = counts.get(*ct as usize).copied().unwrap_or(0);
            health
                .pids_by_client
                .with_label_values(&[name])
                .set(count as f64);
        }
    }

    /// Spawn background sync state monitor.
    fn spawn_sync_monitor(&self, beacon: beacon::Client) {
        let cancel = self.cancel.clone();
        let health = Arc::clone(&self.health);
        let sink = self.sink.as_ref().map(Arc::clone);
        let poll_interval = self.cfg.sync_poll_interval;

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(poll_interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                tokio::select! {
                    _ = cancel.cancelled() => return,
                    _ = ticker.tick() => {
                        match beacon.fetch_sync_status().await {
                            Ok(status) => {
                                health.is_syncing.set(
                                    if status.is_syncing { 1.0 } else { 0.0 },
                                );
                                health.is_optimistic.set(
                                    if status.is_optimistic { 1.0 } else { 0.0 },
                                );
                                health.el_offline.set(
                                    if status.el_offline { 1.0 } else { 0.0 },
                                );
                                health.beacon_sync_distance.set(
                                    status.sync_distance as f64,
                                );

                                if let Some(sink) = &sink {
                                    sink.set_sync_state(status);
                                }
                            }
                            Err(e) => {
                                warn!(error = %e, "sync status poll failed");
                            }
                        }
                    }
                }
            }
        });
    }

    /// Spawn background PID refresh monitor.
    fn spawn_pid_monitor(&self) {
        let cancel = self.cancel.clone();
        let health = Arc::clone(&self.health);
        let poll_interval = self.cfg.sync_poll_interval;
        let disc = CompositeDiscovery::new(&self.cfg.pid);

        #[cfg(feature = "bpf")]
        let tracer = self.tracer.as_ref().map(Arc::clone);

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(poll_interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                tokio::select! {
                    _ = cancel.cancelled() => return,
                    _ = ticker.tick() => {
                        let start = Instant::now();

                        let pids = match disc.discover() {
                            Ok(pids) => pids,
                            Err(e) => {
                                warn!(error = %e, "PID refresh failed");
                                continue;
                            }
                        };

                        health.pids_tracked.set(pids.len() as f64);
                        let client_types = pid::resolve_client_types(&pids);
                        Agent::set_pids_by_client_metrics(&health, &client_types);

                        #[cfg(feature = "bpf")]
                        if let Some(tracer) = &tracer {
                            let mut t = tracer.lock().await;
                            if let Err(e) = t.update_pids(&pids, &client_types) {
                                warn!(error = %e, "PID map update failed");
                            }

                            let (tids, tid_info) =
                                pid::discover_tids(&pids, &client_types);
                            if let Err(e) = t.update_tids(&tids, &tid_info) {
                                warn!(error = %e, "TID map update failed");
                            }

                            health.tid_discovery_count.set(tids.len() as f64);
                            debug!(count = tids.len(), "updated tracked TIDs");
                        }

                        health
                            .pid_refresh_duration
                            .observe(start.elapsed().as_secs_f64());
                    }
                }
            }
        });
    }

    /// Spawn background event stats reporter.
    fn spawn_event_stats_reporter(&self) {
        let cancel = self.cancel.clone();
        let captured_stats = Arc::clone(&self.captured_stats);

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(60));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                tokio::select! {
                    _ = cancel.cancelled() => return,
                    _ = ticker.tick() => {
                        let snapshot = captured_stats.snapshot();
                        let total: u64 = snapshot.iter().map(|(_, n)| n).sum();

                        if total == 0 {
                            continue;
                        }

                        info!(captured = total, "event stats (60s)");

                        for (event_type, count) in &snapshot {
                            debug!(
                                event_type = %event_type,
                                count,
                                "  by type (60s)",
                            );
                        }
                    }
                }
            }
        });
    }
}
