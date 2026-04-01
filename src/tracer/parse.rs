//! Event parsing for raw BPF ring buffer samples.
//!
//! Decodes byte slices from the ring buffer into typed [`ParsedEvent`] values.
//! Length checks happen once per event payload, then fixed-width records are
//! decoded with single unaligned struct loads to minimize parser overhead.

use std::mem::size_of;

use thiserror::Error;

use super::event::{
    BlockMergeEvent, Direction, DiskIOEvent, Event, EventType, MemLatencyEvent, NetIOEvent,
    NetTransport, OOMKillEvent, PageFaultEvent, ParsedEvent, ProcessExitEvent, SchedCombinedEvent,
    SchedEvent, SchedRunqueueEvent, SwapEvent, SyscallEvent, TcpRetransmitEvent, TcpStateEvent,
    TypedEvent, MAX_CLIENT_TYPE,
};

#[repr(C)]
#[derive(Clone, Copy)]
struct RawEventHeader {
    timestamp_ns: u64,
    pid: u32,
    tid: u32,
    event_type: u8,
    client_type: u8,
    pad: [u8; 6],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RawSyscallPayload {
    latency_ns: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RawDiskIOPayload {
    latency_ns: u64,
    bytes: u32,
    rw: u8,
    _pad: [u8; 3],
    queue_depth: u32,
    device_id: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RawNetIOPayload {
    bytes: u32,
    src_port: u16,
    dst_port: u16,
    transport: u8,
    _pad: [u8; 3],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RawNetIOMetricsPayload {
    srtt_us: u32,
    cwnd: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RawSchedPayload {
    on_cpu_ns: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RawBlockMergePayload {
    bytes: u32,
    rw: u8,
    _pad: [u8; 3],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RawTcpRetransmitPayload {
    bytes: u32,
    src_port: u16,
    dst_port: u16,
    _pad: [u8; 8],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RawTcpStatePayload {
    src_port: u16,
    dst_port: u16,
    new_state: u8,
    old_state: u8,
    _pad: [u8; 10],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RawMemLatencyPayload {
    duration_ns: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RawSwapPayload {
    pages: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RawOOMKillPayload {
    target_pid: u32,
    _pad: [u8; 4],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RawProcessExitPayload {
    exit_code: u32,
    _pad: [u8; 4],
}

/// Event header size in bytes (matches `struct event_header` in observoor.h).
const HEADER_SIZE: usize = size_of::<RawEventHeader>();
const SCHED_COMBINED_PAYLOAD_SIZE: usize = 36;

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

    #[error("reading {event_name}: invalid transport byte {raw}")]
    InvalidNetTransport { event_name: &'static str, raw: u8 },
}

/// Parse a raw ring buffer sample into a [`ParsedEvent`].
pub fn parse_event(data: &[u8]) -> Result<ParsedEvent, ParseError> {
    if data.len() < HEADER_SIZE {
        return Err(ParseError::Truncated { size: data.len() });
    }

    // Safety: `data.len() >= HEADER_SIZE` is checked above and the raw header
    // layout matches the BPF event header exactly.
    let header = unsafe { read_unaligned_struct::<RawEventHeader>(data) };
    let event_type_raw = header.event_type;
    let client_type_raw = header.client_type;

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
        7 => (
            EventType::NetTX,
            TypedEvent::NetIO(parse_net_io(payload, Direction::TX as u8)?),
        ),
        8 => (
            EventType::NetRX,
            TypedEvent::NetIO(parse_net_io(payload, Direction::RX as u8)?),
        ),
        9 => (
            EventType::SchedSwitch,
            parse_sched_variant(&header, payload)?,
        ),
        10 => (
            EventType::PageFault,
            TypedEvent::PageFault(parse_page_fault(&header)),
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
            TypedEvent::SchedRunqueue(parse_sched_runqueue(&header, payload)?),
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
        timestamp_ns: u64::from_le(header.timestamp_ns),
        pid: u32::from_le(header.pid),
        tid: u32::from_le(header.tid),
        event_type,
        client_type: client_type_raw,
    };

    Ok(ParsedEvent { raw: event, typed })
}

// ---------------------------------------------------------------------------
// Safe fixed-record helpers (no indexing, no panics)
// ---------------------------------------------------------------------------

#[inline(always)]
fn ensure_payload(data: &[u8], need: usize, name: &'static str) -> Result<(), ParseError> {
    if data.len() < need {
        Err(ParseError::PayloadTruncated { event_name: name })
    } else {
        Ok(())
    }
}

#[inline(always)]
unsafe fn read_unaligned_struct<T: Copy>(data: &[u8]) -> T {
    debug_assert!(size_of::<T>() <= data.len());
    (data.as_ptr() as *const T).read_unaligned()
}

#[inline(always)]
fn read_payload<T: Copy>(data: &[u8], name: &'static str) -> Result<T, ParseError> {
    ensure_payload(data, size_of::<T>(), name)?;
    // Safety: `ensure_payload` guarantees the payload is large enough for `T`.
    Ok(unsafe { read_unaligned_struct::<T>(data) })
}

#[inline(always)]
fn read_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

#[inline(always)]
fn read_u64(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ])
}

#[inline(always)]
fn read_u64_checked(
    data: &[u8],
    offset: usize,
    event_name: &'static str,
) -> Result<u64, ParseError> {
    ensure_payload(data, offset + size_of::<u64>(), event_name)?;
    Ok(read_u64(data, offset))
}

#[inline(always)]
fn decode_u32_from_pad(pad: &[u8; 6], offset: usize) -> u32 {
    debug_assert!(offset <= 2);
    u32::from_le_bytes([
        pad[offset],
        pad[offset + 1],
        pad[offset + 2],
        pad[offset + 3],
    ])
}

// ---------------------------------------------------------------------------
// Per-event-type parsers
// ---------------------------------------------------------------------------

/// Syscall events: types 1-5, 13-15. Payload: 4 bytes.
///
/// The kernel emits latency-only syscall payloads so the hottest event family
/// stays small on the ring buffer and in tracer batch handoff.
fn parse_syscall(data: &[u8]) -> Result<SyscallEvent, ParseError> {
    let raw = read_payload::<RawSyscallPayload>(data, "syscall event")?;
    Ok(SyscallEvent {
        latency_ns: u64::from(u32::from_le(raw.latency_ns)),
    })
}

/// Disk I/O event: type 6. Payload: 24 bytes.
fn parse_disk_io(data: &[u8]) -> Result<DiskIOEvent, ParseError> {
    let raw = read_payload::<RawDiskIOPayload>(data, "disk IO event")?;
    Ok(DiskIOEvent {
        latency_ns: u64::from_le(raw.latency_ns),
        bytes: u32::from_le(raw.bytes),
        rw: raw.rw,
        queue_depth: u32::from_le(raw.queue_depth),
        device_id: u32::from_le(raw.device_id),
    })
}

/// Net I/O event: types 7-8. Common payload: 12 bytes, TCP-TX metrics tail: 8 bytes.
fn parse_net_io(data: &[u8], direction: u8) -> Result<NetIOEvent, ParseError> {
    let raw = read_payload::<RawNetIOPayload>(data, "net IO event")?;
    let transport_raw = raw.transport;
    if transport_raw > NetTransport::Udp as u8 {
        return Err(ParseError::InvalidNetTransport {
            event_name: "net IO event",
            raw: transport_raw,
        });
    }
    let (has_metrics, srtt_us, cwnd) =
        if data.len() >= size_of::<RawNetIOPayload>() + size_of::<RawNetIOMetricsPayload>() {
            let metrics = read_payload::<RawNetIOMetricsPayload>(
                // Safety: length check above guarantees the metrics tail exists.
                unsafe { data.get_unchecked(size_of::<RawNetIOPayload>()..) },
                "net IO event",
            )?;
            (
                true,
                u32::from_le(metrics.srtt_us),
                u32::from_le(metrics.cwnd),
            )
        } else {
            (false, 0, 0)
        };

    Ok(NetIOEvent {
        bytes: u32::from_le(raw.bytes),
        src_port: u16::from_le(raw.src_port),
        dst_port: u16::from_le(raw.dst_port),
        direction,
        transport: transport_raw,
        has_metrics,
        srtt_us,
        cwnd,
    })
}

/// Scheduler context-switch event: type 9.
/// The common payload is 8 bytes, but the BPF side can also attach the
/// incoming tracked thread to collapse the usual sched_switch + sched_runqueue
/// pair into one ring-buffer record.
fn parse_sched_variant(header: &RawEventHeader, data: &[u8]) -> Result<TypedEvent, ParseError> {
    if data.len() >= SCHED_COMBINED_PAYLOAD_SIZE {
        return Ok(TypedEvent::SchedCombined(parse_sched_combined(
            header, data,
        )?));
    }

    Ok(TypedEvent::Sched(parse_sched(header, data)?))
}

/// Scheduler context-switch event payload: 8 bytes.
/// voluntary is stored in `hdr.pad[0]`, cpu_id in `hdr.pad[1..4]`.
fn parse_sched(header: &RawEventHeader, data: &[u8]) -> Result<SchedEvent, ParseError> {
    let raw = read_payload::<RawSchedPayload>(data, "sched event")?;
    Ok(SchedEvent {
        on_cpu_ns: u64::from_le(raw.on_cpu_ns),
        voluntary: header.pad[0] != 0,
        cpu_id: decode_u32_from_pad(&header.pad, 1),
    })
}

/// Combined scheduler switch-out + switch-in payload: 36 bytes.
fn parse_sched_combined(
    header: &RawEventHeader,
    data: &[u8],
) -> Result<SchedCombinedEvent, ParseError> {
    ensure_payload(data, SCHED_COMBINED_PAYLOAD_SIZE, "sched combined event")?;
    let next_client_type = data[32];
    if next_client_type > MAX_CLIENT_TYPE as u8 {
        return Err(ParseError::UnknownClientType {
            raw: next_client_type,
        });
    }

    Ok(SchedCombinedEvent {
        on_cpu_ns: read_u64(data, 0),
        voluntary: header.pad[0] != 0,
        cpu_id: decode_u32_from_pad(&header.pad, 1),
        runqueue_ns: read_u64(data, 8),
        off_cpu_ns: read_u64(data, 16),
        next_pid: read_u32(data, 24),
        next_tid: read_u32(data, 28),
        next_client_type,
    })
}

/// Scheduler runqueue/off-CPU latency event: type 16. Payload: 16 bytes.
/// cpu_id is stored in `hdr.pad[0..3]`.
fn parse_sched_runqueue(
    header: &RawEventHeader,
    data: &[u8],
) -> Result<SchedRunqueueEvent, ParseError> {
    Ok(SchedRunqueueEvent {
        runqueue_ns: read_u64_checked(data, 0, "sched runqueue event")?,
        off_cpu_ns: read_u64_checked(data, 8, "sched runqueue event")?,
        cpu_id: decode_u32_from_pad(&header.pad, 0),
    })
}

/// Page fault event: type 10. No payload; major/minor is carried in `hdr.pad[0]`.
fn parse_page_fault(header: &RawEventHeader) -> PageFaultEvent {
    PageFaultEvent {
        major: header.pad[0] != 0,
    }
}

/// Block merge event: type 17. Payload: 8 bytes.
fn parse_block_merge(data: &[u8]) -> Result<BlockMergeEvent, ParseError> {
    let raw = read_payload::<RawBlockMergePayload>(data, "block merge event")?;
    Ok(BlockMergeEvent {
        bytes: u32::from_le(raw.bytes),
        rw: raw.rw,
    })
}

/// TCP retransmit event: type 18. Payload: 16 bytes (8 meaningful + 8 pad).
fn parse_tcp_retransmit(data: &[u8]) -> Result<TcpRetransmitEvent, ParseError> {
    let raw = read_payload::<RawTcpRetransmitPayload>(data, "tcp retransmit event")?;
    Ok(TcpRetransmitEvent {
        bytes: u32::from_le(raw.bytes),
        src_port: u16::from_le(raw.src_port),
        dst_port: u16::from_le(raw.dst_port),
    })
}

/// TCP state change event: type 19. Payload: 16 bytes (6 meaningful + 10 pad).
fn parse_tcp_state(data: &[u8]) -> Result<TcpStateEvent, ParseError> {
    let raw = read_payload::<RawTcpStatePayload>(data, "tcp state event")?;
    Ok(TcpStateEvent {
        src_port: u16::from_le(raw.src_port),
        dst_port: u16::from_le(raw.dst_port),
        new_state: raw.new_state,
        old_state: raw.old_state,
    })
}

/// Memory reclaim/compaction latency event: types 20-21. Payload: 8 bytes.
fn parse_mem_latency(data: &[u8]) -> Result<MemLatencyEvent, ParseError> {
    let raw = read_payload::<RawMemLatencyPayload>(data, "mem latency event")?;
    Ok(MemLatencyEvent {
        duration_ns: u64::from_le(raw.duration_ns),
    })
}

/// Swap in/out event: types 22-23. Payload: 8 bytes.
fn parse_swap(data: &[u8]) -> Result<SwapEvent, ParseError> {
    let raw = read_payload::<RawSwapPayload>(data, "swap event")?;
    Ok(SwapEvent {
        pages: u64::from_le(raw.pages),
    })
}

/// OOM kill event: type 24. Payload: 8 bytes.
fn parse_oom_kill(data: &[u8]) -> Result<OOMKillEvent, ParseError> {
    let raw = read_payload::<RawOOMKillPayload>(data, "oom kill event")?;
    Ok(OOMKillEvent {
        target_pid: u32::from_le(raw.target_pid),
    })
}

/// Process exit event: type 25. Payload: 8 bytes.
fn parse_process_exit(data: &[u8]) -> Result<ProcessExitEvent, ParseError> {
    let raw = read_payload::<RawProcessExitPayload>(data, "process exit event")?;
    Ok(ProcessExitEvent {
        exit_code: u32::from_le(raw.exit_code),
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    const HEADER_PAD_OFFSET: usize = HEADER_SIZE - 6;

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

    fn set_header_pad_u32(data: &mut [u8], offset: usize, value: u32) {
        data[HEADER_PAD_OFFSET + offset..HEADER_PAD_OFFSET + offset + 4]
            .copy_from_slice(&value.to_le_bytes());
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
        data.extend_from_slice(&[0u8; 2]); // need 4
        assert!(matches!(
            parse_event(&data).unwrap_err(),
            ParseError::PayloadTruncated {
                event_name: "syscall event"
            }
        ));
    }

    #[test]
    fn test_net_io_invalid_transport() {
        let mut data = header(1000, 42, 43, 7, 1);
        data.extend_from_slice(&1024u32.to_le_bytes()); // bytes
        data.extend_from_slice(&80u16.to_le_bytes()); // sport
        data.extend_from_slice(&90u16.to_le_bytes()); // dport
        data.push(7); // invalid transport
        data.extend_from_slice(&[0u8; 3]); // pad
        assert!(matches!(
            parse_event(&data).unwrap_err(),
            ParseError::InvalidNetTransport { raw: 7, .. }
        ));
    }

    // -- Syscall events --

    #[test]
    fn test_syscall_read() {
        let mut data = header(1_000_000, 100, 200, 1, 1); // SyscallRead, Geth
        data.extend_from_slice(&500_000u32.to_le_bytes());

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
        data.extend_from_slice(&750_000u32.to_le_bytes());

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
            data.extend_from_slice(&[0u8; 4]);
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
        data.push(0); // TCP
        data.extend_from_slice(&[0u8; 3]); // pad
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
        data.push(1); // UDP
        data.extend_from_slice(&[0u8; 3]); // pad

        let parsed = parse_event(&data).unwrap();
        let TypedEvent::NetIO(e) = &parsed.typed else {
            panic!("expected NetIO");
        };
        assert_eq!(e.direction, Direction::RX as u8);
        assert_eq!(e.transport, NetTransport::Udp as u8);
        assert!(!e.has_metrics);
        assert_eq!(e.bytes, 2048);
        assert_eq!(e.srtt_us, 0);
        assert_eq!(e.cwnd, 0);
    }

    // -- Scheduler --

    #[test]
    fn test_sched_switch_voluntary() {
        let mut data = header(6_000_000, 105, 205, 9, 6); // SchedSwitch, Prysm
        data.extend_from_slice(&100_000u64.to_le_bytes());
        data[HEADER_PAD_OFFSET] = 1; // voluntary
        set_header_pad_u32(&mut data, 1, 9);

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
        set_header_pad_u32(&mut data, 1, 15);

        let parsed = parse_event(&data).unwrap();
        let TypedEvent::Sched(e) = &parsed.typed else {
            panic!("expected Sched");
        };
        assert_eq!(e.on_cpu_ns, 200_000);
        assert!(!e.voluntary);
        assert_eq!(e.cpu_id, 15);
    }

    #[test]
    fn test_sched_switch_combined() {
        let mut data = header(6_500_000, 105, 205, 9, 6);
        data.extend_from_slice(&200_000u64.to_le_bytes());
        data.extend_from_slice(&50_000u64.to_le_bytes());
        data.extend_from_slice(&70_000u64.to_le_bytes());
        data.extend_from_slice(&303u32.to_le_bytes());
        data.extend_from_slice(&404u32.to_le_bytes());
        data.push(2);
        data.extend_from_slice(&[0u8; 3]);
        data[HEADER_PAD_OFFSET] = 1;
        set_header_pad_u32(&mut data, 1, 15);

        let parsed = parse_event(&data).unwrap();
        let TypedEvent::SchedCombined(e) = &parsed.typed else {
            panic!("expected SchedCombined");
        };
        assert_eq!(e.on_cpu_ns, 200_000);
        assert_eq!(e.runqueue_ns, 50_000);
        assert_eq!(e.off_cpu_ns, 70_000);
        assert_eq!(e.next_pid, 303);
        assert_eq!(e.next_tid, 404);
        assert_eq!(e.next_client_type, 2);
        assert!(e.voluntary);
        assert_eq!(e.cpu_id, 15);
    }

    #[test]
    fn test_sched_runqueue() {
        let mut data = header(7_000_000, 106, 206, 16, 7); // SchedRunqueue, Lighthouse
        data.extend_from_slice(&50_000u64.to_le_bytes());
        data.extend_from_slice(&200_000u64.to_le_bytes());
        set_header_pad_u32(&mut data, 0, 4);

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
        data[18] = 1; // hdr.pad[0] = major

        let parsed = parse_event(&data).unwrap();
        let TypedEvent::PageFault(e) = &parsed.typed else {
            panic!("expected PageFault");
        };
        assert!(e.major);
    }

    #[test]
    fn test_page_fault_minor() {
        let mut data = header(8_000_000, 107, 207, 10, 2);
        data[18] = 0; // hdr.pad[0] = minor

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
        data.extend_from_slice(&[0u8; 4]); // syscall payload
        data.extend_from_slice(&[0xFF; 100]); // trailing garbage

        assert!(parse_event(&data).is_ok());
    }

    #[test]
    fn test_all_client_types_accepted() {
        for ct in 0..=11u8 {
            let mut data = header(1000, 42, 43, 1, ct); // SyscallRead
            data.extend_from_slice(&[0u8; 4]);
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
