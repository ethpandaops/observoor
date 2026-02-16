//! BPF program loading, attachment, and ring buffer reading.
//!
//! Implements the [`Tracer`] trait using aya to manage eBPF programs.
//! All code is gated behind `#[cfg(feature = "bpf")]`.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::io::unix::AsyncFd;

use aya::maps::hash_map::HashMap as BpfHashMap;
use aya::maps::Array;
use aya::maps::RingBuf;
use aya::programs::{KProbe, TracePoint};
use aya::{Ebpf, EbpfLoader};

use crate::config::{EventSamplingMode, ProbeGroup, SamplingConfig};

use super::event::ClientType;
use super::event::EventType;
use super::parse::{parse_event, ParseError};
use super::{
    ErrorHandler, EventHandler, RingbufStats, RingbufStatsHandler, Tracer, TrackedTidInfo,
};

/// Compiled BPF object, embedded at build time.
///
/// Uses `include_bytes_aligned!` to guarantee 32-byte alignment. Without this,
/// `include_bytes!` provides only 1-byte alignment and `aya-obj`'s ELF parser
/// (via the `object` crate without the `unaligned` feature) will reject the
/// data when the pointer happens to land at a non-8-byte-aligned address.
#[cfg(target_os = "linux")]
const BPF_OBJ: &[u8] = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/observoor.bpf.o"));

/// BPF map value for tracked_tids (matches `struct tracked_tid_val` in maps.h).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
#[allow(dead_code)]
struct BpfTrackedTidVal {
    pid: u32,
    client_type: u8,
    _pad: [u8; 3],
}

// SAFETY: BpfTrackedTidVal is a plain C struct with no padding concerns.
unsafe impl aya::Pod for BpfTrackedTidVal {}

/// BPF map value for event_sampling (matches `struct event_sampling_cfg` in maps.h).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct BpfEventSamplingVal {
    mode: u8,
    _pad: [u8; 3],
    value: u32,
}

// SAFETY: BpfEventSamplingVal is a plain C struct with no padding concerns.
unsafe impl aya::Pod for BpfEventSamplingVal {}

const BPF_SAMPLING_MODE_NONE: u8 = 0;
const BPF_SAMPLING_MODE_PROBABILITY: u8 = 1;
const BPF_SAMPLING_MODE_NTH: u8 = 2;
const BPF_SAMPLING_PROBABILITY_SCALE: u32 = 1_000_000;

/// BPF program attachment statistics for Prometheus metrics.
#[derive(Debug, Clone, Copy, Default)]
pub struct AttachmentStats {
    pub tracepoints_attached: u32,
    pub tracepoints_failed: u32,
    pub tracepoints_skipped: u32,
    pub kprobes_attached: u32,
    pub kprobes_failed: u32,
    pub kprobes_skipped: u32,
    pub kretprobes_attached: u32,
    pub kretprobes_failed: u32,
    pub kretprobes_skipped: u32,
}

/// BPF-backed tracer implementation.
pub struct BpfTracer {
    ring_buf_size: u32,
    disabled_probes: HashSet<ProbeGroup>,
    event_handlers: Vec<EventHandler>,
    error_handlers: Vec<ErrorHandler>,
    stats_handlers: Vec<RingbufStatsHandler>,
    ebpf: Option<Ebpf>,
    read_task: Option<tokio::task::JoinHandle<()>>,
    attach_stats: AttachmentStats,
}

impl BpfTracer {
    /// Create a new BPF tracer with the given ring buffer size and disabled probe groups.
    pub fn new(ring_buf_size: u32, disabled_probes: HashSet<ProbeGroup>) -> Self {
        Self {
            ring_buf_size,
            disabled_probes,
            event_handlers: Vec::with_capacity(4),
            error_handlers: Vec::with_capacity(2),
            stats_handlers: Vec::with_capacity(2),
            ebpf: None,
            read_task: None,
            attach_stats: AttachmentStats::default(),
        }
    }

    /// Return a copy of the attachment statistics.
    #[allow(dead_code)]
    pub fn attachment_stats(&self) -> AttachmentStats {
        self.attach_stats
    }

    /// Update per-event sampling policy in the BPF map.
    pub fn update_sampling(&mut self, sampling: &SamplingConfig) -> Result<()> {
        let ebpf = self
            .ebpf
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("BPF objects not loaded"))?;

        let mut map: Array<_, BpfEventSamplingVal> = Array::try_from(
            ebpf.map_mut("event_sampling")
                .ok_or_else(|| anyhow::anyhow!("event_sampling map not found"))?,
        )?;

        // index 0 is unused (EventType starts at 1).
        map.set(
            0,
            BpfEventSamplingVal {
                mode: BPF_SAMPLING_MODE_NONE,
                _pad: [0; 3],
                value: 1,
            },
            0,
        )?;

        for event_type in EventType::all() {
            let resolved = sampling
                .resolved_rule_for_event(*event_type)
                .with_context(|| format!("resolving sampling for {}", event_type.as_str()))?;

            let (mode, value) = match resolved.mode {
                EventSamplingMode::None => (BPF_SAMPLING_MODE_NONE, 1),
                EventSamplingMode::Probability => (
                    BPF_SAMPLING_MODE_PROBABILITY,
                    ((resolved.rate * BPF_SAMPLING_PROBABILITY_SCALE as f32).round() as u32)
                        .min(BPF_SAMPLING_PROBABILITY_SCALE),
                ),
                EventSamplingMode::Nth => (BPF_SAMPLING_MODE_NTH, resolved.nth),
            };

            map.set(
                u32::from(*event_type as u8),
                BpfEventSamplingVal {
                    mode,
                    _pad: [0; 3],
                    value,
                },
                0,
            )
            .with_context(|| format!("updating event_sampling for {}", event_type.as_str()))?;
        }

        Ok(())
    }
}

impl Tracer for BpfTracer {
    async fn start(&mut self, ctx: tokio_util::sync::CancellationToken) -> Result<()> {
        // Load BPF programs with configured ring buffer size.
        let mut ebpf = EbpfLoader::new()
            .set_max_entries("events", self.ring_buf_size)
            .load(BPF_OBJ)
            .context("loading BPF objects")?;

        // Attach all BPF programs (skipping disabled probe groups).
        self.attach_stats = attach_programs(&mut ebpf, &self.disabled_probes)?;
        log_attachment_stats(&self.attach_stats);

        // Take the ring buffer map for the read task.
        let events_map = ebpf
            .take_map("events")
            .ok_or_else(|| anyhow::anyhow!("events map not found"))?;
        let ring_buf =
            RingBuf::try_from(events_map).context("creating ring buffer from events map")?;

        // Move handlers into the read task.
        let event_handlers = Arc::new(std::mem::take(&mut self.event_handlers));
        let error_handlers = Arc::new(std::mem::take(&mut self.error_handlers));
        let stats_handlers = Arc::new(std::mem::take(&mut self.stats_handlers));
        let ring_buf_size = self.ring_buf_size;

        let handle = tokio::spawn(async move {
            read_loop(
                ring_buf,
                ring_buf_size,
                event_handlers,
                error_handlers,
                stats_handlers,
                ctx,
            )
            .await;
        });

        self.read_task = Some(handle);
        self.ebpf = Some(ebpf);

        tracing::info!("BPF tracer started");
        Ok(())
    }

    async fn stop(&mut self) -> Result<()> {
        // The read task exits when the CancellationToken is cancelled.
        if let Some(handle) = self.read_task.take() {
            handle.await.context("waiting for read task")?;
        }

        // Drop the Ebpf object which detaches all programs and closes maps.
        self.ebpf = None;

        tracing::info!("BPF tracer stopped");
        Ok(())
    }

    fn update_pids(&mut self, pids: &[u32], client_types: &HashMap<u32, ClientType>) -> Result<()> {
        let ebpf = self
            .ebpf
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("BPF objects not loaded"))?;

        // Collect existing keys.
        let existing_keys: Vec<u32> = {
            let map: BpfHashMap<_, u32, u8> = BpfHashMap::try_from(
                ebpf.map_mut("tracked_pids")
                    .ok_or_else(|| anyhow::anyhow!("tracked_pids map not found"))?,
            )?;
            map.keys().filter_map(|k| k.ok()).collect()
        };

        // Delete existing entries.
        {
            let mut map: BpfHashMap<_, u32, u8> = BpfHashMap::try_from(
                ebpf.map_mut("tracked_pids")
                    .ok_or_else(|| anyhow::anyhow!("tracked_pids map not found"))?,
            )?;
            for key in &existing_keys {
                if let Err(e) = map.remove(key) {
                    tracing::warn!(pid = key, error = %e, "failed to delete PID from BPF map");
                }
            }
        }

        // Insert new entries.
        {
            let mut map: BpfHashMap<_, u32, u8> = BpfHashMap::try_from(
                ebpf.map_mut("tracked_pids")
                    .ok_or_else(|| anyhow::anyhow!("tracked_pids map not found"))?,
            )?;
            for &pid in pids {
                let ct = client_types
                    .get(&pid)
                    .copied()
                    .unwrap_or(ClientType::Unknown);
                map.insert(pid, ct as u8, 0)
                    .with_context(|| format!("adding PID {pid} to BPF map"))?;

                tracing::debug!(pid, client = %ct, "added PID to BPF map");
            }
        }

        Ok(())
    }

    fn update_tids(&mut self, tids: &[u32], tid_info: &HashMap<u32, TrackedTidInfo>) -> Result<()> {
        let ebpf = self
            .ebpf
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("BPF objects not loaded"))?;

        // Clear tracked_tids and wakeup_ts (explicitly managed HASH maps).
        clear_hash_map::<u32, BpfTrackedTidVal>(ebpf, "tracked_tids")?;
        clear_hash_map::<u32, u64>(ebpf, "wakeup_ts")?;

        // NOTE: sched_on_ts and offcpu_ts are LRU maps that record timestamps
        // unconditionally for all threads. Clearing them on TID refresh would
        // lose timestamps for currently-running threads, creating on_cpu_ns=0
        // holes. LRU eviction handles staleness automatically.

        // Insert new TID entries.
        {
            let mut map: BpfHashMap<_, u32, BpfTrackedTidVal> = BpfHashMap::try_from(
                ebpf.map_mut("tracked_tids")
                    .ok_or_else(|| anyhow::anyhow!("tracked_tids map not found"))?,
            )?;
            for &tid in tids {
                let info = tid_info.get(&tid);
                let val = BpfTrackedTidVal {
                    pid: info.map_or(0, |i| i.pid),
                    client_type: info.map_or(ClientType::Unknown as u8, |i| i.client as u8),
                    _pad: [0; 3],
                };
                map.insert(tid, val, 0)
                    .with_context(|| format!("adding TID {tid} to BPF map"))?;
            }
        }

        const TRACKED_TIDS_CAPACITY: usize = 65536;
        if tids.len() > TRACKED_TIDS_CAPACITY {
            tracing::warn!(
                count = tids.len(),
                capacity = TRACKED_TIDS_CAPACITY,
                "discovered TIDs exceed tracked_tids map capacity; some threads will not emit runqueue events"
            );
        }

        tracing::debug!(count = tids.len(), "updated tracked TIDs");
        Ok(())
    }

    fn on_event(&mut self, handler: EventHandler) {
        self.event_handlers.push(handler);
    }

    fn on_error(&mut self, handler: ErrorHandler) {
        self.error_handlers.push(handler);
    }

    fn on_ringbuf_stats(&mut self, handler: RingbufStatsHandler) {
        self.stats_handlers.push(handler);
    }
}

// ---------------------------------------------------------------------------
// Ring buffer read loop
// ---------------------------------------------------------------------------

/// Report stats every N events to reduce overhead.
const STATS_INTERVAL: u32 = 1000;

async fn read_loop(
    ring_buf: RingBuf<aya::maps::MapData>,
    ring_buf_size: u32,
    event_handlers: Arc<Vec<EventHandler>>,
    error_handlers: Arc<Vec<ErrorHandler>>,
    stats_handlers: Arc<Vec<RingbufStatsHandler>>,
    cancel: tokio_util::sync::CancellationToken,
) {
    let mut async_fd = match AsyncFd::new(ring_buf) {
        Ok(fd) => fd,
        Err(e) => {
            tracing::error!(error = %e, "failed to create async fd for ring buffer");
            return;
        }
    };

    let mut event_count: u32 = 0;

    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            result = async_fd.readable_mut() => {
                let mut guard = match result {
                    Ok(g) => g,
                    Err(e) => {
                        tracing::warn!(error = %e, "ring buffer poll error");
                        report_error(&error_handlers, &e);
                        continue;
                    }
                };

                // Drain all available events.
                let rb = guard.get_inner_mut();
                while let Some(item) = rb.next() {
                    let data: &[u8] = &item;

                    // Empty record indicates ring buffer overflow.
                    if data.is_empty() {
                        tracing::warn!("ring buffer overflow detected");
                        continue;
                    }

                    event_count += 1;
                    if event_count >= STATS_INTERVAL {
                        let stats = RingbufStats {
                            used_bytes: 0, // aya does not expose remaining/capacity
                            size_bytes: ring_buf_size as usize,
                        };
                        for handler in stats_handlers.iter() {
                            handler(stats);
                        }
                        event_count = 0;
                    }

                    match parse_event(data) {
                        Ok(event) => {
                            match event_handlers.len() {
                                0 => {}
                                1 => {
                                    if let Some(handler) = event_handlers.first() {
                                        handler(event);
                                    }
                                }
                                len => {
                                    for handler in event_handlers.iter().take(len - 1) {
                                        handler(event.clone());
                                    }
                                    if let Some(last_handler) = event_handlers.get(len - 1) {
                                        last_handler(event);
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            tracing::debug!(error = %e, "event parse error");
                            report_parse_error(&error_handlers, &e);
                        }
                    }
                }

                guard.clear_ready();
            }
        }
    }
}

fn report_error(handlers: &[ErrorHandler], err: &std::io::Error) {
    let anyhow_err = anyhow::anyhow!("{err}");
    for handler in handlers {
        handler(anyhow::anyhow!("{anyhow_err}"));
    }
}

fn report_parse_error(handlers: &[ErrorHandler], err: &ParseError) {
    for handler in handlers {
        handler(anyhow::anyhow!("{err}"));
    }
}

// ---------------------------------------------------------------------------
// BPF program attachment
// ---------------------------------------------------------------------------

fn attach_programs(ebpf: &mut Ebpf, disabled: &HashSet<ProbeGroup>) -> Result<AttachmentStats> {
    let mut stats = AttachmentStats::default();

    // ---------------------------------------------------------------
    // Syscall tracepoints (enter/exit pairs grouped by ProbeGroup)
    // ---------------------------------------------------------------
    let syscall_probes: &[(
        ProbeGroup,
        (&str, &str, &str), // enter: (prog, group, name)
        (&str, &str, &str), // exit:  (prog, group, name)
    )] = &[
        (
            ProbeGroup::SyscallRead,
            ("trace_sys_enter_read", "syscalls", "sys_enter_read"),
            ("trace_sys_exit_read", "syscalls", "sys_exit_read"),
        ),
        (
            ProbeGroup::SyscallWrite,
            ("trace_sys_enter_write", "syscalls", "sys_enter_write"),
            ("trace_sys_exit_write", "syscalls", "sys_exit_write"),
        ),
        (
            ProbeGroup::SyscallFutex,
            ("trace_sys_enter_futex", "syscalls", "sys_enter_futex"),
            ("trace_sys_exit_futex", "syscalls", "sys_exit_futex"),
        ),
        (
            ProbeGroup::SyscallMmap,
            ("trace_sys_enter_mmap", "syscalls", "sys_enter_mmap"),
            ("trace_sys_exit_mmap", "syscalls", "sys_exit_mmap"),
        ),
        (
            ProbeGroup::SyscallEpollWait,
            (
                "trace_sys_enter_epoll_wait",
                "syscalls",
                "sys_enter_epoll_wait",
            ),
            (
                "trace_sys_exit_epoll_wait",
                "syscalls",
                "sys_exit_epoll_wait",
            ),
        ),
        (
            ProbeGroup::SyscallFsync,
            ("trace_sys_enter_fsync", "syscalls", "sys_enter_fsync"),
            ("trace_sys_exit_fsync", "syscalls", "sys_exit_fsync"),
        ),
        (
            ProbeGroup::SyscallFdatasync,
            (
                "trace_sys_enter_fdatasync",
                "syscalls",
                "sys_enter_fdatasync",
            ),
            ("trace_sys_exit_fdatasync", "syscalls", "sys_exit_fdatasync"),
        ),
        (
            ProbeGroup::SyscallPwrite,
            ("trace_sys_enter_pwrite64", "syscalls", "sys_enter_pwrite64"),
            ("trace_sys_exit_pwrite64", "syscalls", "sys_exit_pwrite64"),
        ),
    ];

    for (group, (ep, eg, en), (xp, xg, xn)) in syscall_probes {
        if disabled.contains(group) {
            tracing::info!(probe = %group, "skipping (disabled)");
            stats.tracepoints_skipped += 2;
            continue;
        }
        attach_tracepoint_required(ebpf, ep, eg, en, &mut stats)?;
        attach_tracepoint_required(ebpf, xp, xg, xn, &mut stats)?;
    }

    // ---------------------------------------------------------------
    // FD tracepoints
    // ---------------------------------------------------------------
    if disabled.contains(&ProbeGroup::FdOpen) {
        tracing::info!(probe = "fd_open", "skipping (disabled)");
        stats.tracepoints_skipped += 2;
    } else {
        attach_tracepoint_required(
            ebpf,
            "trace_sys_enter_openat",
            "syscalls",
            "sys_enter_openat",
            &mut stats,
        )?;
        attach_tracepoint_required(
            ebpf,
            "trace_sys_exit_openat",
            "syscalls",
            "sys_exit_openat",
            &mut stats,
        )?;
    }

    if disabled.contains(&ProbeGroup::FdClose) {
        tracing::info!(probe = "fd_close", "skipping (disabled)");
        stats.tracepoints_skipped += 1;
    } else {
        attach_tracepoint_required(
            ebpf,
            "trace_sys_enter_close",
            "syscalls",
            "sys_enter_close",
            &mut stats,
        )?;
    }

    // ---------------------------------------------------------------
    // Block I/O tracepoints
    // ---------------------------------------------------------------
    if disabled.contains(&ProbeGroup::DiskIo) {
        tracing::info!(probe = "disk_io", "skipping (disabled)");
        stats.tracepoints_skipped += 2;
    } else {
        attach_tracepoint_required(
            ebpf,
            "trace_block_rq_issue",
            "block",
            "block_rq_issue",
            &mut stats,
        )?;
        attach_tracepoint_required(
            ebpf,
            "trace_block_rq_complete",
            "block",
            "block_rq_complete",
            &mut stats,
        )?;
    }

    // ---------------------------------------------------------------
    // Network kprobes (grouped by ProbeGroup)
    // ---------------------------------------------------------------
    let net_kprobes: &[(ProbeGroup, &str, &str, &str, &str)] = &[
        (
            ProbeGroup::TcpSend,
            "kprobe_tcp_sendmsg",
            "kretprobe_tcp_sendmsg",
            "tcp_sendmsg",
            "tcp_sendmsg",
        ),
        (
            ProbeGroup::TcpRecv,
            "kprobe_tcp_recvmsg",
            "kretprobe_tcp_recvmsg",
            "tcp_recvmsg",
            "tcp_recvmsg",
        ),
        (
            ProbeGroup::UdpSend,
            "kprobe_udp_sendmsg",
            "kretprobe_udp_sendmsg",
            "udp_sendmsg",
            "udp_sendmsg",
        ),
        (
            ProbeGroup::UdpRecv,
            "kprobe_udp_recvmsg",
            "kretprobe_udp_recvmsg",
            "udp_recvmsg",
            "udp_recvmsg",
        ),
    ];

    for (group, kp, krp, ksym, krsym) in net_kprobes {
        if disabled.contains(group) {
            tracing::info!(probe = %group, "skipping (disabled)");
            stats.kprobes_skipped += 1;
            stats.kretprobes_skipped += 1;
            continue;
        }
        attach_kprobe_required(ebpf, kp, ksym, &mut stats)?;
        attach_kprobe_required(ebpf, krp, krsym, &mut stats)?;
    }

    // ---------------------------------------------------------------
    // Scheduler tracepoint
    // ---------------------------------------------------------------
    if disabled.contains(&ProbeGroup::Scheduler) {
        tracing::info!(probe = "scheduler", "skipping (disabled)");
        stats.tracepoints_skipped += 1;
    } else {
        attach_tracepoint_required(
            ebpf,
            "trace_sched_switch",
            "sched",
            "sched_switch",
            &mut stats,
        )?;
    }

    // ---------------------------------------------------------------
    // Page fault kprobes
    // ---------------------------------------------------------------
    if disabled.contains(&ProbeGroup::PageFault) {
        tracing::info!(probe = "page_fault", "skipping (disabled)");
        stats.kprobes_skipped += 1;
        stats.kretprobes_skipped += 1;
    } else {
        attach_kprobe_required(
            ebpf,
            "kprobe_handle_mm_fault",
            "handle_mm_fault",
            &mut stats,
        )?;
        attach_kprobe_required(
            ebpf,
            "kretprobe_handle_mm_fault",
            "handle_mm_fault",
            &mut stats,
        )?;
    }

    // ---------------------------------------------------------------
    // Optional tracepoints (with probe group gating)
    // ---------------------------------------------------------------
    let disk_io_enabled = !disabled.contains(&ProbeGroup::DiskIo);
    let optional_tracepoints: &[(ProbeGroup, &str, &str, &str)] = &[
        (
            ProbeGroup::BlockMerge,
            "trace_block_rq_merge",
            "block",
            "block_rq_merge",
        ),
        (
            ProbeGroup::SchedulerWakeup,
            "trace_sched_wakeup",
            "sched",
            "sched_wakeup",
        ),
        (
            ProbeGroup::SchedulerWakeup,
            "trace_sched_wakeup_new",
            "sched",
            "sched_wakeup_new",
        ),
        (
            ProbeGroup::MemReclaim,
            "trace_reclaim_begin",
            "vmscan",
            "mm_vmscan_direct_reclaim_begin",
        ),
        (
            ProbeGroup::MemReclaim,
            "trace_reclaim_end",
            "vmscan",
            "mm_vmscan_direct_reclaim_end",
        ),
        (
            ProbeGroup::MemCompaction,
            "trace_compaction_begin",
            "compaction",
            "compaction_begin",
        ),
        (
            ProbeGroup::MemCompaction,
            "trace_compaction_end",
            "compaction",
            "compaction_end",
        ),
        (ProbeGroup::SwapIn, "trace_swapin", "swap", "swapin"),
        (ProbeGroup::SwapOut, "trace_swapout", "swap", "swapout"),
        (ProbeGroup::OomKill, "trace_oom_kill", "oom", "oom_kill"),
    ];

    for (group, prog_name, tp_group, tp_name) in optional_tracepoints {
        let block_merge_required_for_disk = *group == ProbeGroup::BlockMerge && disk_io_enabled;
        if disabled.contains(group) && !block_merge_required_for_disk {
            tracing::info!(probe = %group, program = prog_name, "skipping (disabled)");
            stats.tracepoints_skipped += 1;
            continue;
        }
        if disabled.contains(group) && block_merge_required_for_disk {
            tracing::warn!(
                probe = %group,
                program = prog_name,
                "configured disabled but disk_io is enabled; attaching to preserve disk I/O accounting"
            );
        }
        attach_tracepoint_optional(ebpf, prog_name, tp_group, tp_name, &mut stats);
    }

    // ---------------------------------------------------------------
    // Optional kprobes (with probe group gating)
    // ---------------------------------------------------------------
    let optional_kprobes: &[(ProbeGroup, &str, &str)] = &[
        (
            ProbeGroup::TcpRetransmit,
            "kprobe_tcp_retransmit_skb",
            "tcp_retransmit_skb",
        ),
        (
            ProbeGroup::TcpState,
            "kprobe_tcp_set_state",
            "tcp_set_state",
        ),
        (ProbeGroup::ProcessExit, "kprobe_do_exit", "do_exit"),
    ];

    for (group, prog_name, symbol) in optional_kprobes {
        if disabled.contains(group) {
            tracing::info!(probe = %group, program = prog_name, "skipping (disabled)");
            stats.kprobes_skipped += 1;
            continue;
        }
        attach_kprobe_optional(ebpf, prog_name, symbol, &mut stats);
    }

    Ok(stats)
}

fn attach_tracepoint_required(
    ebpf: &mut Ebpf,
    prog_name: &str,
    group: &str,
    name: &str,
    stats: &mut AttachmentStats,
) -> Result<()> {
    let prog: &mut TracePoint = ebpf
        .program_mut(prog_name)
        .ok_or_else(|| anyhow::anyhow!("tracepoint program '{prog_name}' not found"))?
        .try_into()
        .with_context(|| format!("'{prog_name}' is not a tracepoint program"))?;
    prog.load()
        .with_context(|| format!("loading tracepoint {group}/{name}"))?;
    prog.attach(group, name)
        .with_context(|| format!("attaching tracepoint {group}/{name}"))?;
    stats.tracepoints_attached += 1;
    tracing::debug!(group, name, "attached tracepoint");
    Ok(())
}

fn attach_tracepoint_optional(
    ebpf: &mut Ebpf,
    prog_name: &str,
    group: &str,
    name: &str,
    stats: &mut AttachmentStats,
) {
    let result: Result<()> = (|| {
        let prog: &mut TracePoint = ebpf
            .program_mut(prog_name)
            .ok_or_else(|| anyhow::anyhow!("program '{prog_name}' not found"))?
            .try_into()?;
        prog.load()?;
        prog.attach(group, name)?;
        Ok(())
    })();

    match result {
        Ok(()) => {
            stats.tracepoints_attached += 1;
            tracing::debug!(group, name, "attached optional tracepoint");
        }
        Err(e) => {
            stats.tracepoints_failed += 1;
            tracing::warn!(
                group,
                name,
                error = %e,
                "optional tracepoint attach failed"
            );
        }
    }
}

/// Attach a required kprobe or kretprobe. BPF programs with section `kretprobe/`
/// are detected by aya and attached as return probes automatically.
fn attach_kprobe_required(
    ebpf: &mut Ebpf,
    prog_name: &str,
    symbol: &str,
    stats: &mut AttachmentStats,
) -> Result<()> {
    let is_kretprobe = prog_name.starts_with("kretprobe_");

    let prog: &mut KProbe = ebpf
        .program_mut(prog_name)
        .ok_or_else(|| anyhow::anyhow!("kprobe program '{prog_name}' not found"))?
        .try_into()
        .with_context(|| format!("'{prog_name}' is not a kprobe program"))?;
    prog.load()
        .with_context(|| format!("loading kprobe {symbol}"))?;
    prog.attach(symbol, 0)
        .with_context(|| format!("attaching kprobe {symbol}"))?;

    if is_kretprobe {
        stats.kretprobes_attached += 1;
        tracing::debug!(symbol, "attached kretprobe");
    } else {
        stats.kprobes_attached += 1;
        tracing::debug!(symbol, "attached kprobe");
    }

    Ok(())
}

fn attach_kprobe_optional(
    ebpf: &mut Ebpf,
    prog_name: &str,
    symbol: &str,
    stats: &mut AttachmentStats,
) {
    let is_kretprobe = prog_name.starts_with("kretprobe_");

    let result: Result<()> = (|| {
        let prog: &mut KProbe = ebpf
            .program_mut(prog_name)
            .ok_or_else(|| anyhow::anyhow!("program '{prog_name}' not found"))?
            .try_into()?;
        prog.load()?;
        prog.attach(symbol, 0)?;
        Ok(())
    })();

    match result {
        Ok(()) => {
            if is_kretprobe {
                stats.kretprobes_attached += 1;
                tracing::debug!(symbol, "attached optional kretprobe");
            } else {
                stats.kprobes_attached += 1;
                tracing::debug!(symbol, "attached optional kprobe");
            }
        }
        Err(e) => {
            if is_kretprobe {
                stats.kretprobes_failed += 1;
            } else {
                stats.kprobes_failed += 1;
            }
            tracing::warn!(
                symbol,
                error = %e,
                "optional kprobe attach failed"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// BPF map helpers
// ---------------------------------------------------------------------------

/// Clear all entries in a BPF hash map.
fn clear_hash_map<K: aya::Pod, V: aya::Pod>(ebpf: &mut Ebpf, map_name: &str) -> Result<()> {
    // Phase 1: collect keys.
    let keys: Vec<K> = {
        let map: BpfHashMap<_, K, V> = BpfHashMap::try_from(
            ebpf.map_mut(map_name)
                .ok_or_else(|| anyhow::anyhow!("map '{map_name}' not found"))?,
        )?;
        map.keys().filter_map(|k| k.ok()).collect()
    };

    // Phase 2: delete.
    if !keys.is_empty() {
        let mut map: BpfHashMap<_, K, V> = BpfHashMap::try_from(
            ebpf.map_mut(map_name)
                .ok_or_else(|| anyhow::anyhow!("map '{map_name}' not found"))?,
        )?;
        for key in &keys {
            if let Err(e) = map.remove(key) {
                tracing::warn!(map = map_name, error = %e, "failed to delete key from BPF map");
            }
        }
    }

    Ok(())
}

fn log_attachment_stats(stats: &AttachmentStats) {
    tracing::info!(
        tracepoints_attached = stats.tracepoints_attached,
        tracepoints_failed = stats.tracepoints_failed,
        tracepoints_skipped = stats.tracepoints_skipped,
        kprobes_attached = stats.kprobes_attached,
        kprobes_failed = stats.kprobes_failed,
        kprobes_skipped = stats.kprobes_skipped,
        kretprobes_attached = stats.kretprobes_attached,
        kretprobes_failed = stats.kretprobes_failed,
        kretprobes_skipped = stats.kretprobes_skipped,
        "BPF program attachment summary"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bpf_object_is_valid_elf() {
        assert!(
            BPF_OBJ.len() > 64,
            "BPF object is too small: {} bytes",
            BPF_OBJ.len()
        );

        // ELF magic: 0x7f 'E' 'L' 'F'
        let magic = BPF_OBJ.get(..4).expect("BPF object too small for magic");
        assert_eq!(magic, b"\x7fELF", "invalid ELF magic: {magic:02x?}");

        // EI_CLASS should be ELFCLASS64 (2) for BPF.
        let ei_class = BPF_OBJ.get(4).copied().expect("missing EI_CLASS");
        assert_eq!(ei_class, 2, "not 64-bit ELF (EI_CLASS={ei_class})");

        // e_machine at offset 18 (2 bytes LE) should be EM_BPF (247).
        let em_lo = BPF_OBJ.get(18).copied().expect("missing e_machine lo");
        let em_hi = BPF_OBJ.get(19).copied().expect("missing e_machine hi");
        let e_machine = u16::from_le_bytes([em_lo, em_hi]);
        assert_eq!(e_machine, 247, "e_machine is not EM_BPF (got {e_machine})");
    }

    #[test]
    fn test_bpf_object_alignment() {
        // The BPF object pointer must be 8-byte aligned for aya-obj's ELF parser.
        // `aya::include_bytes_aligned!` guarantees 32-byte alignment.
        let ptr = BPF_OBJ.as_ptr() as usize;
        assert_eq!(
            ptr % 8,
            0,
            "BPF object pointer {ptr:#x} is not 8-byte aligned"
        );
    }
}
