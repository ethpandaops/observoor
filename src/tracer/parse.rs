//! Event parsing for raw BPF ring buffer samples.
//!
//! Decodes byte slices from the ring buffer into typed [`ParsedEvent`] values.
//! Length checks happen once per event payload, then fixed-width reads use
//! unchecked unaligned loads to minimize parser overhead.

use thiserror::Error;

use super::event::{
    BlockMergeEvent, Direction, DiskIOEvent, Event, EventType, MemLatencyEvent, NetIOEvent,
    NetTransport, OOMKillEvent, PageFaultEvent, ParsedEvent, ProcessExitEvent, SchedEvent,
    SchedRunqueueEvent, SwapEvent, SyscallEvent, TcpRetransmitEvent, TcpStateEvent, TypedEvent,
    MAX_CLIENT_TYPE,
};

/// Event header size in bytes (matches `struct event_header` in observoor.h).
const HEADER_SIZE: usize = 24;

/// Errors that can occur during event parsing.
#[derive(Error, Debug)]
pub enum ParseError {
    #[error("event too short: {size} bytes")]
    Truncated { size: usize },

    #[error("unknown event type: {raw}")]
    UnknownEventType { raw: u8 },

    #[error("unknown client type: {raw}")]
    UnknownClientType { raw: u8 },

    #[error("reading {event_name}: unexpected end of data")]
    PayloadTruncated { event_name: &'static str },

    #[error("reading {event_name}: invalid direction byte {raw}")]
    InvalidDirection { event_name: &'static str, raw: u8 },

    #[error("reading {event_name}: invalid transport byte {raw}")]
    InvalidNetTransport { event_name: &'static str, raw: u8 },
}

/// Parse a raw ring buffer sample into a [`ParsedEvent`].
pub fn parse_event(data: &[u8]) -> Result<ParsedEvent, ParseError> {
    if data.len() < HEADER_SIZE {
        return Err(ParseError::Truncated { size: data.len() });
    }

    let event_type_raw = read_u8(data, 16);
    let client_type_raw = read_u8(data, 17);

    if client_type_raw > MAX_CLIENT_TYPE as u8 {
        return Err(ParseError::UnknownClientType {
            raw: client_type_raw,
        });
    }

    // Decode the raw event tag once and build the typed payload from the same
    // dispatch to avoid a second hot-path match on `EventType`.
    // Safety: `data.len() >= HEADER_SIZE` is checked at function entry.
    let payload = unsafe { data.get_unchecked(HEADER_SIZE..) };
    let (event_type, typed) = match event_type_raw {
        1 => (
            EventType::SyscallRead,
            TypedEvent::SyscallRead(parse_syscall(payload)?),
        ),
        2 => (
            EventType::SyscallWrite,
            TypedEvent::SyscallWrite(parse_syscall(payload)?),
        ),
        3 => (
            EventType::SyscallFutex,
            TypedEvent::SyscallFutex(parse_syscall(payload)?),
        ),
        4 => (
            EventType::SyscallMmap,
            TypedEvent::SyscallMmap(parse_syscall(payload)?),
        ),
        5 => (
            EventType::SyscallEpollWait,
            TypedEvent::SyscallEpollWait(parse_syscall(payload)?),
        ),
        6 => (
            EventType::DiskIO,
            TypedEvent::DiskIO(parse_disk_io(payload)?),
        ),
        7 => (EventType::NetTX, TypedEvent::NetIO(parse_net_io(payload)?)),
        8 => (EventType::NetRX, TypedEvent::NetIO(parse_net_io(payload)?)),
        9 => (
            EventType::SchedSwitch,
            TypedEvent::Sched(parse_sched(payload)?),
        ),
        10 => (
            EventType::PageFault,
            TypedEvent::PageFault(parse_page_fault(payload)?),
        ),
        11 => (EventType::FDOpen, TypedEvent::FDOpen),
        12 => (EventType::FDClose, TypedEvent::FDClose),
        13 => (
            EventType::SyscallFsync,
            TypedEvent::SyscallFsync(parse_syscall(payload)?),
        ),
        14 => (
            EventType::SyscallFdatasync,
            TypedEvent::SyscallFdatasync(parse_syscall(payload)?),
        ),
        15 => (
            EventType::SyscallPwrite,
            TypedEvent::SyscallPwrite(parse_syscall(payload)?),
        ),
        16 => (
            EventType::SchedRunqueue,
            TypedEvent::SchedRunqueue(parse_sched_runqueue(payload)?),
        ),
        17 => (
            EventType::BlockMerge,
            TypedEvent::BlockMerge(parse_block_merge(payload)?),
        ),
        18 => (
            EventType::TcpRetransmit,
            TypedEvent::TcpRetransmit(parse_tcp_retransmit(payload)?),
        ),
        19 => (
            EventType::TcpState,
            TypedEvent::TcpState(parse_tcp_state(payload)?),
        ),
        20 => (
            EventType::MemReclaim,
            TypedEvent::MemReclaim(parse_mem_latency(payload)?),
        ),
        21 => (
            EventType::MemCompaction,
            TypedEvent::MemCompaction(parse_mem_latency(payload)?),
        ),
        22 => (EventType::SwapIn, TypedEvent::SwapIn(parse_swap(payload)?)),
        23 => (
            EventType::SwapOut,
            TypedEvent::SwapOut(parse_swap(payload)?),
        ),
        24 => (
            EventType::OOMKill,
            TypedEvent::OOMKill(parse_oom_kill(payload)?),
        ),
        25 => (
            EventType::ProcessExit,
            TypedEvent::ProcessExit(parse_process_exit(payload)?),
        ),
        _ => {
            return Err(ParseError::UnknownEventType {
                raw: event_type_raw,
            });
        }
    };

    let event = Event {
        timestamp_ns: read_u64_le(data, 0),
        pid: read_u32_le(data, 8),
        tid: read_u32_le(data, 12),
        event_type,
        client_type: client_type_raw,
    };

    Ok(ParsedEvent { raw: event, typed })
}

// ---------------------------------------------------------------------------
// Safe byte-reading helpers (no indexing, no panics)
// ---------------------------------------------------------------------------

#[inline(always)]
fn read_u8(data: &[u8], offset: usize) -> u8 {
    debug_assert!(offset < data.len());
    // Safety: callers verify payload lengths before reading fixed offsets.
    unsafe { *data.as_ptr().add(offset) }
}

#[inline(always)]
fn read_u16_le(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(read_fixed::<2>(data, offset))
}

#[inline(always)]
fn read_u32_le(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(read_fixed::<4>(data, offset))
}

#[inline(always)]
fn read_u64_le(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(read_fixed::<8>(data, offset))
}

#[inline(always)]
fn read_fixed<const N: usize>(data: &[u8], offset: usize) -> [u8; N] {
    debug_assert!(offset + N <= data.len());
    // Safety: callers ensure `offset + N <= data.len()` via upfront payload checks.
    unsafe { (data.as_ptr().add(offset) as *const [u8; N]).read_unaligned() }
}

fn ensure_payload(data: &[u8], need: usize, name: &'static str) -> Result<(), ParseError> {
    if data.len() < need {
        Err(ParseError::PayloadTruncated { event_name: name })
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Per-event-type parsers
// ---------------------------------------------------------------------------

/// Syscall events: types 1-5, 13-15. Payload: 8 bytes.
///
/// The kernel emits latency-only syscall payloads so the hottest event family
/// stays small on the ring buffer and in tracer batch handoff.
fn parse_syscall(data: &[u8]) -> Result<SyscallEvent, ParseError> {
    ensure_payload(data, 8, "syscall event")?;
    Ok(SyscallEvent {
        latency_ns: read_u64_le(data, 0),
    })
}

/// Disk I/O event: type 6. Payload: 24 bytes.
fn parse_disk_io(data: &[u8]) -> Result<DiskIOEvent, ParseError> {
    ensure_payload(data, 24, "disk IO event")?;
    Ok(DiskIOEvent {
        latency_ns: read_u64_le(data, 0),
        bytes: read_u32_le(data, 8),
        rw: read_u8(data, 12),
        // pad[3] at 13-15
        queue_depth: read_u32_le(data, 16),
        device_id: read_u32_le(data, 20),
    })
}

/// Net I/O event: types 7-8. Payload: 20 bytes minimum.
fn parse_net_io(data: &[u8]) -> Result<NetIOEvent, ParseError> {
    ensure_payload(data, 20, "net IO event")?;
    let direction_raw = read_u8(data, 8);
    if direction_raw > Direction::RX as u8 {
        return Err(ParseError::InvalidDirection {
            event_name: "net IO event",
            raw: direction_raw,
        });
    }
    let transport_raw = read_u8(data, 10);
    if transport_raw > NetTransport::Udp as u8 {
        return Err(ParseError::InvalidNetTransport {
            event_name: "net IO event",
            raw: transport_raw,
        });
    }
    Ok(NetIOEvent {
        bytes: read_u32_le(data, 0),
        src_port: read_u16_le(data, 4),
        dst_port: read_u16_le(data, 6),
        direction: direction_raw,
        transport: transport_raw,
        has_metrics: read_u8(data, 9) != 0,
        // pad[1] at 11
        srtt_us: read_u32_le(data, 12),
        cwnd: read_u32_le(data, 16),
    })
}

/// Scheduler context-switch event: type 9. Payload: 16 bytes.
fn parse_sched(data: &[u8]) -> Result<SchedEvent, ParseError> {
    ensure_payload(data, 16, "sched event")?;
    Ok(SchedEvent {
        on_cpu_ns: read_u64_le(data, 0),
        voluntary: read_u8(data, 8) != 0,
        cpu_id: read_u32_le(data, 12),
    })
}

/// Scheduler runqueue/off-CPU latency event: type 16. Payload: 24 bytes.
fn parse_sched_runqueue(data: &[u8]) -> Result<SchedRunqueueEvent, ParseError> {
    ensure_payload(data, 24, "sched runqueue event")?;
    Ok(SchedRunqueueEvent {
        runqueue_ns: read_u64_le(data, 0),
        off_cpu_ns: read_u64_le(data, 8),
        cpu_id: read_u32_le(data, 16),
    })
}

/// Page fault event: type 10. Payload: 8 bytes.
fn parse_page_fault(data: &[u8]) -> Result<PageFaultEvent, ParseError> {
    ensure_payload(data, 8, "page fault event")?;
    Ok(PageFaultEvent {
        major: read_u8(data, 0) != 0,
    })
}

/// Block merge event: type 17. Payload: 8 bytes.
fn parse_block_merge(data: &[u8]) -> Result<BlockMergeEvent, ParseError> {
    ensure_payload(data, 8, "block merge event")?;
    Ok(BlockMergeEvent {
        bytes: read_u32_le(data, 0),
        rw: read_u8(data, 4),
    })
}

/// TCP retransmit event: type 18. Payload: 16 bytes (8 meaningful + 8 pad).
fn parse_tcp_retransmit(data: &[u8]) -> Result<TcpRetransmitEvent, ParseError> {
    ensure_payload(data, 16, "tcp retransmit event")?;
    Ok(TcpRetransmitEvent {
        bytes: read_u32_le(data, 0),
        src_port: read_u16_le(data, 4),
        dst_port: read_u16_le(data, 6),
    })
}

/// TCP state change event: type 19. Payload: 16 bytes (6 meaningful + 10 pad).
fn parse_tcp_state(data: &[u8]) -> Result<TcpStateEvent, ParseError> {
    ensure_payload(data, 16, "tcp state event")?;
    Ok(TcpStateEvent {
        src_port: read_u16_le(data, 0),
        dst_port: read_u16_le(data, 2),
        new_state: read_u8(data, 4),
        old_state: read_u8(data, 5),
    })
}

/// Memory reclaim/compaction latency event: types 20-21. Payload: 8 bytes.
fn parse_mem_latency(data: &[u8]) -> Result<MemLatencyEvent, ParseError> {
    ensure_payload(data, 8, "mem latency event")?;
    Ok(MemLatencyEvent {
        duration_ns: read_u64_le(data, 0),
    })
}

/// Swap in/out event: types 22-23. Payload: 8 bytes.
fn parse_swap(data: &[u8]) -> Result<SwapEvent, ParseError> {
    ensure_payload(data, 8, "swap event")?;
    Ok(SwapEvent {
        pages: read_u64_le(data, 0),
    })
}

/// OOM kill event: type 24. Payload: 8 bytes.
fn parse_oom_kill(data: &[u8]) -> Result<OOMKillEvent, ParseError> {
    ensure_payload(data, 8, "oom kill event")?;
    Ok(OOMKillEvent {
        target_pid: read_u32_le(data, 0),
    })
}

/// Process exit event: type 25. Payload: 8 bytes.
fn parse_process_exit(data: &[u8]) -> Result<ProcessExitEvent, ParseError> {
    ensure_payload(data, 8, "process exit event")?;
    Ok(ProcessExitEvent {
        exit_code: read_u32_le(data, 0),
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    /// Build a 24-byte event header.
    fn header(ts: u64, pid: u32, tid: u32, event_type: u8, client_type: u8) -> Vec<u8> {
        let mut buf = Vec::with_capacity(HEADER_SIZE);
        buf.extend_from_slice(&ts.to_le_bytes());
        buf.extend_from_slice(&pid.to_le_bytes());
        buf.extend_from_slice(&tid.to_le_bytes());
        buf.push(event_type);
        buf.push(client_type);
        buf.extend_from_slice(&[0u8; 6]); // pad
        buf
    }

    fn assert_header(event: &Event, ts: u64, pid: u32, tid: u32, et: EventType, ct: u8) {
        assert_eq!(event.timestamp_ns, ts);
        assert_eq!(event.pid, pid);
        assert_eq!(event.tid, tid);
        assert_eq!(event.event_type, et);
        assert_eq!(event.client_type, ct);
    }

    // -- Error cases --

    #[test]
    fn test_truncated_data() {
        let result = parse_event(&[0u8; 10]);
        assert!(matches!(
            result.unwrap_err(),
            ParseError::Truncated { size: 10 }
        ));
    }

    #[test]
    fn test_empty_data() {
        let result = parse_event(&[]);
        assert!(matches!(
            result.unwrap_err(),
            ParseError::Truncated { size: 0 }
        ));
    }

    #[test]
    fn test_unknown_event_type() {
        let data = header(1000, 42, 43, 99, 1);
        assert!(matches!(
            parse_event(&data).unwrap_err(),
            ParseError::UnknownEventType { raw: 99 }
        ));
    }

    #[test]
    fn test_unknown_client_type() {
        let data = header(1000, 42, 43, 1, 99);
        assert!(matches!(
            parse_event(&data).unwrap_err(),
            ParseError::UnknownClientType { raw: 99 }
        ));
    }

    #[test]
    fn test_header_only_truncates_payload() {
        // SyscallRead needs 8 bytes of payload, none provided.
        let data = header(1000, 42, 43, 1, 1);
        assert!(matches!(
            parse_event(&data).unwrap_err(),
            ParseError::PayloadTruncated { .. }
        ));
    }

    #[test]
    fn test_syscall_short_payload() {
        let mut data = header(1000, 42, 43, 1, 1);
        data.extend_from_slice(&[0u8; 4]); // need 8
        assert!(matches!(
            parse_event(&data).unwrap_err(),
            ParseError::PayloadTruncated {
                event_name: "syscall event"
            }
        ));
    }

    #[test]
    fn test_net_io_invalid_direction() {
        let mut data = header(1000, 42, 43, 7, 1);
        data.extend_from_slice(&1024u32.to_le_bytes()); // bytes
        data.extend_from_slice(&80u16.to_le_bytes()); // sport
        data.extend_from_slice(&90u16.to_le_bytes()); // dport
        data.push(5); // invalid direction
        data.push(0);
        data.extend_from_slice(&[0u8; 10]); // rest of payload
        assert!(matches!(
            parse_event(&data).unwrap_err(),
            ParseError::InvalidDirection { raw: 5, .. }
        ));
    }

    #[test]
    fn test_net_io_invalid_transport() {
        let mut data = header(1000, 42, 43, 7, 1);
        data.extend_from_slice(&1024u32.to_le_bytes()); // bytes
        data.extend_from_slice(&80u16.to_le_bytes()); // sport
        data.extend_from_slice(&90u16.to_le_bytes()); // dport
        data.push(0); // TX
        data.push(0); // no metrics
        data.push(7); // invalid transport
        data.extend_from_slice(&[0u8; 9]); // rest of payload
        assert!(matches!(
            parse_event(&data).unwrap_err(),
            ParseError::InvalidNetTransport { raw: 7, .. }
        ));
    }

    // -- Syscall events --

    #[test]
    fn test_syscall_read() {
        let mut data = header(1_000_000, 100, 200, 1, 1); // SyscallRead, Geth
        data.extend_from_slice(&500_000u64.to_le_bytes());

        let parsed = parse_event(&data).unwrap();
        assert_header(&parsed.raw, 1_000_000, 100, 200, EventType::SyscallRead, 1);
        let TypedEvent::SyscallRead(e) = &parsed.typed else {
            panic!("expected SyscallRead");
        };
        assert_eq!(e.latency_ns, 500_000);
    }

    #[test]
    fn test_syscall_write_negative_return() {
        let mut data = header(2_000_000, 101, 201, 2, 2); // SyscallWrite, Reth
        data.extend_from_slice(&750_000u64.to_le_bytes());

        let parsed = parse_event(&data).unwrap();
        let TypedEvent::SyscallWrite(e) = &parsed.typed else {
            panic!("expected SyscallWrite");
        };
        assert_eq!(e.latency_ns, 750_000);
        assert_eq!(parsed.raw.event_type, EventType::SyscallWrite);
    }

    #[test]
    fn test_all_syscall_types_parse() {
        for event_type in [1u8, 2, 3, 4, 5, 13, 14, 15] {
            let mut data = header(1000, 42, 43, event_type, 0);
            data.extend_from_slice(&[0u8; 8]);
            let parsed = parse_event(&data).expect("syscall should parse");
            let matches_expected_variant = match event_type {
                1 => matches!(parsed.typed, TypedEvent::SyscallRead(_)),
                2 => matches!(parsed.typed, TypedEvent::SyscallWrite(_)),
                3 => matches!(parsed.typed, TypedEvent::SyscallFutex(_)),
                4 => matches!(parsed.typed, TypedEvent::SyscallMmap(_)),
                5 => matches!(parsed.typed, TypedEvent::SyscallEpollWait(_)),
                13 => matches!(parsed.typed, TypedEvent::SyscallFsync(_)),
                14 => matches!(parsed.typed, TypedEvent::SyscallFdatasync(_)),
                15 => matches!(parsed.typed, TypedEvent::SyscallPwrite(_)),
                _ => false,
            };
            assert!(
                matches_expected_variant,
                "event type {} should map to its specialized syscall variant",
                event_type
            );
        }
    }

    // -- Disk I/O --

    #[test]
    fn test_disk_io() {
        let mut data = header(3_000_000, 102, 202, 6, 3); // DiskIO, Besu
        data.extend_from_slice(&1_000_000u64.to_le_bytes()); // latency
        data.extend_from_slice(&4096u32.to_le_bytes()); // bytes
        data.push(1); // rw = write
        data.extend_from_slice(&[0u8; 3]); // pad
        data.extend_from_slice(&8u32.to_le_bytes()); // queue_depth
        data.extend_from_slice(&66304u32.to_le_bytes()); // device_id

        let parsed = parse_event(&data).unwrap();
        let TypedEvent::DiskIO(e) = &parsed.typed else {
            panic!("expected DiskIO");
        };
        assert_eq!(e.latency_ns, 1_000_000);
        assert_eq!(e.bytes, 4096);
        assert_eq!(e.rw, 1);
        assert_eq!(e.queue_depth, 8);
        assert_eq!(e.device_id, 66304);
    }

    // -- Net I/O --

    #[test]
    fn test_net_tx_with_metrics() {
        let mut data = header(4_000_000, 103, 203, 7, 1); // NetTX, Geth
        data.extend_from_slice(&1024u32.to_le_bytes()); // bytes
        data.extend_from_slice(&8080u16.to_le_bytes()); // sport
        data.extend_from_slice(&9090u16.to_le_bytes()); // dport
        data.push(0); // TX
        data.push(1); // has_metrics
        data.push(0); // TCP
        data.push(0); // pad
        data.extend_from_slice(&50_000u32.to_le_bytes()); // srtt_us
        data.extend_from_slice(&10u32.to_le_bytes()); // cwnd

        let parsed = parse_event(&data).unwrap();
        let TypedEvent::NetIO(e) = &parsed.typed else {
            panic!("expected NetIO");
        };
        assert_eq!(e.bytes, 1024);
        assert_eq!(e.src_port, 8080);
        assert_eq!(e.dst_port, 9090);
        assert_eq!(e.direction, Direction::TX as u8);
        assert_eq!(e.transport, NetTransport::Tcp as u8);
        assert!(e.has_metrics);
        assert_eq!(e.srtt_us, 50_000);
        assert_eq!(e.cwnd, 10);
    }

    #[test]
    fn test_net_rx_no_metrics() {
        let mut data = header(5_000_000, 104, 204, 8, 7); // NetRX, Lighthouse
        data.extend_from_slice(&2048u32.to_le_bytes());
        data.extend_from_slice(&443u16.to_le_bytes());
        data.extend_from_slice(&12345u16.to_le_bytes());
        data.push(1); // RX
        data.push(0); // no metrics
        data.push(1); // UDP
        data.push(0); // pad
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());

        let parsed = parse_event(&data).unwrap();
        let TypedEvent::NetIO(e) = &parsed.typed else {
            panic!("expected NetIO");
        };
        assert_eq!(e.direction, Direction::RX as u8);
        assert_eq!(e.transport, NetTransport::Udp as u8);
        assert!(!e.has_metrics);
        assert_eq!(e.bytes, 2048);
    }

    // -- Scheduler --

    #[test]
    fn test_sched_switch_voluntary() {
        let mut data = header(6_000_000, 105, 205, 9, 6); // SchedSwitch, Prysm
        data.extend_from_slice(&100_000u64.to_le_bytes());
        data.push(1); // voluntary
        data.extend_from_slice(&[0u8; 3]);
        data.extend_from_slice(&9u32.to_le_bytes());

        let parsed = parse_event(&data).unwrap();
        let TypedEvent::Sched(e) = &parsed.typed else {
            panic!("expected Sched");
        };
        assert_eq!(e.on_cpu_ns, 100_000);
        assert!(e.voluntary);
        assert_eq!(e.cpu_id, 9);
    }

    #[test]
    fn test_sched_switch_involuntary() {
        let mut data = header(6_000_000, 105, 205, 9, 6);
        data.extend_from_slice(&200_000u64.to_le_bytes());
        data.push(0); // involuntary
        data.extend_from_slice(&[0u8; 3]);
        data.extend_from_slice(&15u32.to_le_bytes());

        let parsed = parse_event(&data).unwrap();
        let TypedEvent::Sched(e) = &parsed.typed else {
            panic!("expected Sched");
        };
        assert_eq!(e.on_cpu_ns, 200_000);
        assert!(!e.voluntary);
        assert_eq!(e.cpu_id, 15);
    }

    #[test]
    fn test_sched_runqueue() {
        let mut data = header(7_000_000, 106, 206, 16, 7); // SchedRunqueue, Lighthouse
        data.extend_from_slice(&50_000u64.to_le_bytes());
        data.extend_from_slice(&200_000u64.to_le_bytes());
        data.extend_from_slice(&4u32.to_le_bytes());
        data.extend_from_slice(&[0u8; 4]);

        let parsed = parse_event(&data).unwrap();
        let TypedEvent::SchedRunqueue(e) = &parsed.typed else {
            panic!("expected SchedRunqueue");
        };
        assert_eq!(e.runqueue_ns, 50_000);
        assert_eq!(e.off_cpu_ns, 200_000);
        assert_eq!(e.cpu_id, 4);
    }

    // -- Page fault --

    #[test]
    fn test_page_fault_major() {
        let mut data = header(8_000_000, 107, 207, 10, 2); // PageFault, Reth
        data.push(1); // major
        data.extend_from_slice(&[0u8; 7]);

        let parsed = parse_event(&data).unwrap();
        let TypedEvent::PageFault(e) = &parsed.typed else {
            panic!("expected PageFault");
        };
        assert!(e.major);
    }

    #[test]
    fn test_page_fault_minor() {
        let mut data = header(8_000_000, 107, 207, 10, 2);
        data.push(0); // minor
        data.extend_from_slice(&[0u8; 7]);

        let parsed = parse_event(&data).unwrap();
        let TypedEvent::PageFault(e) = &parsed.typed else {
            panic!("expected PageFault");
        };
        assert!(!e.major);
    }

    // -- FD events --

    #[test]
    fn test_fd_open_header_only() {
        let data = header(9_000_000, 108, 208, 11, 1); // FDOpen, Geth

        let parsed = parse_event(&data).unwrap();
        let TypedEvent::FDOpen = &parsed.typed else {
            panic!("expected FDOpen");
        };
        assert_eq!(parsed.raw.pid, 108);
    }

    #[test]
    fn test_fd_close_header_only() {
        let data = header(10_000_000, 109, 209, 12, 4); // FDClose, Nethermind

        let parsed = parse_event(&data).unwrap();
        let TypedEvent::FDClose = &parsed.typed else {
            panic!("expected FDClose");
        };
        assert_eq!(parsed.raw.tid, 209);
    }

    // -- Block merge --

    #[test]
    fn test_block_merge_read() {
        let mut data = header(11_000_000, 110, 210, 17, 1); // BlockMerge, Geth
        data.extend_from_slice(&8192u32.to_le_bytes());
        data.push(0); // rw = read
        data.extend_from_slice(&[0u8; 3]);

        let parsed = parse_event(&data).unwrap();
        let TypedEvent::BlockMerge(e) = &parsed.typed else {
            panic!("expected BlockMerge");
        };
        assert_eq!(e.bytes, 8192);
        assert_eq!(e.rw, 0);
    }

    // -- TCP retransmit --

    #[test]
    fn test_tcp_retransmit() {
        let mut data = header(12_000_000, 111, 211, 18, 6); // TcpRetransmit, Prysm
        data.extend_from_slice(&512u32.to_le_bytes());
        data.extend_from_slice(&30303u16.to_le_bytes());
        data.extend_from_slice(&30304u16.to_le_bytes());
        data.extend_from_slice(&[0u8; 8]); // pad

        let parsed = parse_event(&data).unwrap();
        let TypedEvent::TcpRetransmit(e) = &parsed.typed else {
            panic!("expected TcpRetransmit");
        };
        assert_eq!(e.bytes, 512);
        assert_eq!(e.src_port, 30303);
        assert_eq!(e.dst_port, 30304);
    }

    // -- TCP state --

    #[test]
    fn test_tcp_state() {
        let mut data = header(13_000_000, 112, 212, 19, 7); // TcpState, Lighthouse
        data.extend_from_slice(&8080u16.to_le_bytes());
        data.extend_from_slice(&9090u16.to_le_bytes());
        data.push(1); // new_state
        data.push(2); // old_state
        data.extend_from_slice(&[0u8; 10]); // pad

        let parsed = parse_event(&data).unwrap();
        let TypedEvent::TcpState(e) = &parsed.typed else {
            panic!("expected TcpState");
        };
        assert_eq!(e.src_port, 8080);
        assert_eq!(e.dst_port, 9090);
        assert_eq!(e.new_state, 1);
        assert_eq!(e.old_state, 2);
    }

    // -- Memory latency --

    #[test]
    fn test_mem_reclaim() {
        let mut data = header(14_000_000, 113, 213, 20, 1); // MemReclaim, Geth
        data.extend_from_slice(&5_000_000u64.to_le_bytes());

        let parsed = parse_event(&data).unwrap();
        let TypedEvent::MemReclaim(e) = &parsed.typed else {
            panic!("expected MemReclaim");
        };
        assert_eq!(e.duration_ns, 5_000_000);
        assert_eq!(parsed.raw.event_type, EventType::MemReclaim);
    }

    #[test]
    fn test_mem_compaction() {
        let mut data = header(15_000_000, 114, 214, 21, 2); // MemCompaction, Reth
        data.extend_from_slice(&3_000_000u64.to_le_bytes());

        let parsed = parse_event(&data).unwrap();
        let TypedEvent::MemCompaction(_e) = &parsed.typed else {
            panic!("expected MemCompaction");
        };
        assert_eq!(parsed.raw.event_type, EventType::MemCompaction);
    }

    // -- Swap --

    #[test]
    fn test_swap_in() {
        let mut data = header(16_000_000, 115, 215, 22, 3); // SwapIn, Besu
        data.extend_from_slice(&1u64.to_le_bytes());

        let parsed = parse_event(&data).unwrap();
        let TypedEvent::SwapIn(e) = &parsed.typed else {
            panic!("expected SwapIn");
        };
        assert_eq!(e.pages, 1);
        assert_eq!(parsed.raw.event_type, EventType::SwapIn);
    }

    #[test]
    fn test_swap_out() {
        let mut data = header(17_000_000, 116, 216, 23, 4); // SwapOut, Nethermind
        data.extend_from_slice(&100u64.to_le_bytes());

        let parsed = parse_event(&data).unwrap();
        let TypedEvent::SwapOut(e) = &parsed.typed else {
            panic!("expected SwapOut");
        };
        assert_eq!(e.pages, 100);
        assert_eq!(parsed.raw.event_type, EventType::SwapOut);
    }

    // -- OOM kill --

    #[test]
    fn test_oom_kill() {
        let mut data = header(18_000_000, 117, 217, 24, 1); // OOMKill, Geth
        data.extend_from_slice(&999u32.to_le_bytes());
        data.extend_from_slice(&[0u8; 4]); // pad

        let parsed = parse_event(&data).unwrap();
        let TypedEvent::OOMKill(e) = &parsed.typed else {
            panic!("expected OOMKill");
        };
        assert_eq!(e.target_pid, 999);
    }

    // -- Process exit --

    #[test]
    fn test_process_exit() {
        let mut data = header(19_000_000, 118, 218, 25, 5); // ProcessExit, Erigon
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&[0u8; 4]); // pad

        let parsed = parse_event(&data).unwrap();
        let TypedEvent::ProcessExit(e) = &parsed.typed else {
            panic!("expected ProcessExit");
        };
        assert_eq!(e.exit_code, 1);
    }

    // -- Edge cases --

    #[test]
    fn test_extra_trailing_data_ignored() {
        let mut data = header(1000, 42, 43, 1, 1);
        data.extend_from_slice(&[0u8; 8]); // syscall payload
        data.extend_from_slice(&[0xFF; 100]); // trailing garbage

        assert!(parse_event(&data).is_ok());
    }

    #[test]
    fn test_all_client_types_accepted() {
        for ct in 0..=11u8 {
            let mut data = header(1000, 42, 43, 1, ct); // SyscallRead
            data.extend_from_slice(&[0u8; 8]);
            assert!(
                parse_event(&data).is_ok(),
                "client type {} should be accepted",
                ct
            );
        }
    }

    #[test]
    fn test_exactly_minimum_payload() {
        // OOM kill needs exactly 8 bytes of payload.
        let mut data = header(1000, 42, 43, 24, 1);
        data.extend_from_slice(&[0u8; 8]);
        assert!(parse_event(&data).is_ok());

        // One byte short should fail.
        let mut data = header(1000, 42, 43, 24, 1);
        data.extend_from_slice(&[0u8; 7]);
        assert!(parse_event(&data).is_err());
    }

    #[test]
    fn test_parse_error_display() {
        let e = ParseError::Truncated { size: 5 };
        assert_eq!(e.to_string(), "event too short: 5 bytes");

        let e = ParseError::UnknownEventType { raw: 99 };
        assert_eq!(e.to_string(), "unknown event type: 99");

        let e = ParseError::PayloadTruncated {
            event_name: "syscall event",
        };
        assert_eq!(
            e.to_string(),
            "reading syscall event: unexpected end of data"
        );
    }
}
