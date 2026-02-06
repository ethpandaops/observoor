//go:build linux

package tracer

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/sirupsen/logrus"

	"github.com/ethpandaops/observoor/internal/export"
)

// AttachmentStats tracks BPF program attachment status.
type AttachmentStats struct {
	TracepointsAttached int
	TracepointsFailed   int
	KprobesAttached     int
	KprobesFailed       int
	KretprobesAttached  int
	KretprobesFailed    int
}

type tracer struct {
	log           logrus.FieldLogger
	ringBufSize   int
	health        *export.HealthMetrics
	handlers      []EventHandler
	errorHandlers []ErrorHandler
	statsHandlers []RingbufStatsHandler
	links         []link.Link
	reader        *ringbuf.Reader
	objs          *observoorObjects
	cancel        context.CancelFunc
	wg            sync.WaitGroup
	attachStats   AttachmentStats
}

type trackedTidVal struct {
	PID        uint32
	ClientType uint8
	Pad        [3]byte
}

// New creates a new BPF tracer.
func New(
	log logrus.FieldLogger,
	ringBufSize int,
	health *export.HealthMetrics,
) Tracer {
	return &tracer{
		log:           log.WithField("component", "tracer"),
		ringBufSize:   ringBufSize,
		health:        health,
		handlers:      make([]EventHandler, 0, 4),
		errorHandlers: make([]ErrorHandler, 0, 2),
		statsHandlers: make([]RingbufStatsHandler, 0, 2),
	}
}

func (t *tracer) OnEvent(handler EventHandler) {
	t.handlers = append(t.handlers, handler)
}

func (t *tracer) OnError(handler ErrorHandler) {
	t.errorHandlers = append(t.errorHandlers, handler)
}

func (t *tracer) OnRingbufStats(handler RingbufStatsHandler) {
	t.statsHandlers = append(t.statsHandlers, handler)
}

func (t *tracer) Start(ctx context.Context) error {
	ctx, t.cancel = context.WithCancel(ctx)

	// Load BPF objects.
	spec, err := loadObservoor()
	if err != nil {
		return fmt.Errorf("loading BPF spec: %w", err)
	}

	// Override ring buffer size.
	for name, m := range spec.Maps {
		if name == "events" {
			m.MaxEntries = uint32(t.ringBufSize)
		}
	}

	t.objs = &observoorObjects{}
	if err := spec.LoadAndAssign(t.objs, nil); err != nil {
		return fmt.Errorf("loading BPF objects: %w", err)
	}

	// Attach all BPF programs.
	if err := t.attachPrograms(); err != nil {
		t.cleanup()

		return fmt.Errorf("attaching BPF programs: %w", err)
	}

	// Report attachment metrics.
	t.reportAttachmentMetrics()

	// Open ring buffer reader.
	t.reader, err = ringbuf.NewReader(t.objs.Events)
	if err != nil {
		t.cleanup()

		return fmt.Errorf("creating ring buffer reader: %w", err)
	}

	// Report ring buffer capacity.
	if t.health != nil {
		t.health.RingbufCapacityBytes.Set(float64(t.reader.BufferSize()))
	}

	// Start event reading goroutine.
	t.wg.Add(1)

	go t.readLoop(ctx)

	t.log.Info("BPF tracer started")

	return nil
}

func (t *tracer) Stop() error {
	if t.cancel != nil {
		t.cancel()
	}

	if t.reader != nil {
		t.reader.Close()
	}

	t.wg.Wait()
	t.cleanup()

	t.log.Info("BPF tracer stopped")

	return nil
}

func (t *tracer) UpdatePIDs(
	pids []uint32,
	clientTypes map[uint32]ClientType,
) error {
	if t.objs == nil {
		return fmt.Errorf("BPF objects not loaded")
	}

	// Clear existing entries.
	var (
		key uint32
		val uint8
	)

	iter := t.objs.TrackedPids.Iterate()
	keysToDelete := make([]uint32, 0, 64)

	for iter.Next(&key, &val) {
		keysToDelete = append(keysToDelete, key)
	}

	for _, k := range keysToDelete {
		if err := t.objs.TrackedPids.Delete(k); err != nil &&
			!errors.Is(err, ebpf.ErrKeyNotExist) {
			t.log.WithError(err).WithField("pid", k).
				Warn("Failed to delete PID from BPF map")
		}
	}

	// Add new PIDs.
	for _, pid := range pids {
		ct := ClientTypeUnknown
		if c, ok := clientTypes[pid]; ok {
			ct = c
		}

		if err := t.objs.TrackedPids.Put(pid, uint8(ct)); err != nil {
			return fmt.Errorf("adding PID %d to BPF map: %w", pid, err)
		}

		t.log.WithFields(logrus.Fields{
			"pid":    pid,
			"client": ct.String(),
		}).Debug("Added PID to BPF map")
	}

	return nil
}

func (t *tracer) UpdateTIDs(
	tids []uint32,
	tidInfo map[uint32]TrackedTidInfo,
) error {
	if t.objs == nil {
		return fmt.Errorf("BPF objects not loaded")
	}

	// Clear existing tracked_tids entries.
	var (
		tidKey uint32
		tidVal trackedTidVal
	)

	tidIter := t.objs.TrackedTids.Iterate()
	tidKeysToDelete := make([]uint32, 0, 4096)

	for tidIter.Next(&tidKey, &tidVal) {
		tidKeysToDelete = append(tidKeysToDelete, tidKey)
	}

	for _, k := range tidKeysToDelete {
		if err := t.objs.TrackedTids.Delete(k); err != nil &&
			!errors.Is(err, ebpf.ErrKeyNotExist) {
			t.log.WithError(err).WithField("tid", k).
				Warn("Failed to delete TID from BPF map")
		}
	}

	// Clear sched_on_ts entries.
	var (
		tsKey uint32
		tsVal uint64
	)

	tsIter := t.objs.SchedOnTs.Iterate()
	tsKeysToDelete := make([]uint32, 0, 4096)

	for tsIter.Next(&tsKey, &tsVal) {
		tsKeysToDelete = append(tsKeysToDelete, tsKey)
	}

	for _, k := range tsKeysToDelete {
		if err := t.objs.SchedOnTs.Delete(k); err != nil &&
			!errors.Is(err, ebpf.ErrKeyNotExist) {
			t.log.WithError(err).WithField("tid", k).
				Warn("Failed to delete TID from sched_on_ts map")
		}
	}

	// Clear wakeup_ts entries.
	wakeupIter := t.objs.WakeupTs.Iterate()
	wakeupKeysToDelete := make([]uint32, 0, 4096)

	for wakeupIter.Next(&tsKey, &tsVal) {
		wakeupKeysToDelete = append(wakeupKeysToDelete, tsKey)
	}

	for _, k := range wakeupKeysToDelete {
		if err := t.objs.WakeupTs.Delete(k); err != nil &&
			!errors.Is(err, ebpf.ErrKeyNotExist) {
			t.log.WithError(err).WithField("tid", k).
				Warn("Failed to delete TID from wakeup_ts map")
		}
	}

	// Clear offcpu_ts entries.
	offcpuIter := t.objs.OffcpuTs.Iterate()
	offcpuKeysToDelete := make([]uint32, 0, 4096)

	for offcpuIter.Next(&tsKey, &tsVal) {
		offcpuKeysToDelete = append(offcpuKeysToDelete, tsKey)
	}

	for _, k := range offcpuKeysToDelete {
		if err := t.objs.OffcpuTs.Delete(k); err != nil &&
			!errors.Is(err, ebpf.ErrKeyNotExist) {
			t.log.WithError(err).WithField("tid", k).
				Warn("Failed to delete TID from offcpu_ts map")
		}
	}

	// Add new TIDs.
	for _, tid := range tids {
		info, ok := tidInfo[tid]
		ct := ClientTypeUnknown
		pid := uint32(0)
		if ok {
			ct = info.Client
			pid = info.PID
		}

		val := trackedTidVal{
			PID:        pid,
			ClientType: uint8(ct),
		}

		if err := t.objs.TrackedTids.Put(tid, val); err != nil {
			return fmt.Errorf("adding TID %d to BPF map: %w", tid, err)
		}
	}

	t.log.WithField("count", len(tids)).
		Debug("Updated tracked TIDs")

	return nil
}

func (t *tracer) readLoop(ctx context.Context) {
	defer t.wg.Done()

	// Only report stats every N events to reduce overhead.
	const statsInterval = 1000
	eventCount := 0
	var record ringbuf.Record

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if err := t.reader.ReadInto(&record); err != nil {
			if errors.Is(err, os.ErrClosed) {
				return
			}

			// Check for ring buffer overflow.
			if errors.Is(err, ringbuf.ErrClosed) {
				t.log.WithError(err).Warn("Ring buffer closed")
			} else {
				t.log.WithError(err).Warn("Ring buffer read error")
			}

			t.reportError(err)

			continue
		}

		// Check if this is a lost record (overflow indicator).
		if len(record.RawSample) == 0 {
			if t.health != nil {
				t.health.BPFRingbufOverflows.Inc()
			}

			t.log.Warn("Ring buffer overflow detected")

			continue
		}

		// Report stats periodically, not on every event.
		eventCount++
		if eventCount >= statsInterval {
			t.reportRingbufStats(record.Remaining)
			eventCount = 0
		}

		event, err := parseEvent(record.RawSample)
		if err != nil {
			t.log.WithError(err).Debug("Event parse error")
			t.reportError(err)
			t.reportParseError(err)

			continue
		}

		for _, handler := range t.handlers {
			handler(event)
		}
	}
}

func (t *tracer) reportError(err error) {
	for _, handler := range t.errorHandlers {
		handler(err)
	}
}

func (t *tracer) reportRingbufStats(remaining int) {
	if t.reader == nil {
		return
	}

	size := t.reader.BufferSize()
	used := size - remaining
	if used < 0 {
		used = 0
	}

	stats := RingbufStats{
		UsedBytes: used,
		SizeBytes: size,
	}

	for _, handler := range t.statsHandlers {
		handler(stats)
	}
}

// reportAttachmentMetrics reports BPF program attachment statistics.
func (t *tracer) reportAttachmentMetrics() {
	if t.health == nil {
		return
	}

	t.health.BPFProgramsAttached.WithLabelValues("tracepoint").
		Set(float64(t.attachStats.TracepointsAttached))
	t.health.BPFProgramsAttached.WithLabelValues("kprobe").
		Set(float64(t.attachStats.KprobesAttached))
	t.health.BPFProgramsAttached.WithLabelValues("kretprobe").
		Set(float64(t.attachStats.KretprobesAttached))

	t.health.BPFProgramsFailed.WithLabelValues("tracepoint").
		Set(float64(t.attachStats.TracepointsFailed))
	t.health.BPFProgramsFailed.WithLabelValues("kprobe").
		Set(float64(t.attachStats.KprobesFailed))
	t.health.BPFProgramsFailed.WithLabelValues("kretprobe").
		Set(float64(t.attachStats.KretprobesFailed))

	t.log.WithFields(logrus.Fields{
		"tracepoints_attached": t.attachStats.TracepointsAttached,
		"tracepoints_failed":   t.attachStats.TracepointsFailed,
		"kprobes_attached":     t.attachStats.KprobesAttached,
		"kprobes_failed":       t.attachStats.KprobesFailed,
		"kretprobes_attached":  t.attachStats.KretprobesAttached,
		"kretprobes_failed":    t.attachStats.KretprobesFailed,
	}).Info("BPF program attachment summary")
}

// reportParseError reports a parse error with categorized error type.
func (t *tracer) reportParseError(err error) {
	if t.health == nil {
		return
	}

	errorType := categorizeParseError(err)
	t.health.EventParseErrors.WithLabelValues(errorType).Inc()
}

// categorizeParseError determines the error type for metrics labeling.
func categorizeParseError(err error) string {
	errStr := err.Error()

	switch {
	case strings.Contains(errStr, "event too short"):
		return "truncated"
	case strings.Contains(errStr, "unknown event type"):
		return "unknown_type"
	case strings.Contains(errStr, "reading event header"):
		return "header_decode"
	case strings.Contains(errStr, "reading"):
		return "payload_decode"
	default:
		return "other"
	}
}

const eventHeaderSize = 24

// parseEvent decodes a raw ring buffer sample into a ParsedEvent.
func parseEvent(data []byte) (ParsedEvent, error) {
	if len(data) < eventHeaderSize {
		return ParsedEvent{}, fmt.Errorf(
			"event too short: %d bytes", len(data),
		)
	}

	event := Event{
		TimestampNs: binary.LittleEndian.Uint64(data[0:8]),
		PID:         binary.LittleEndian.Uint32(data[8:12]),
		TID:         binary.LittleEndian.Uint32(data[12:16]),
		Type:        EventType(data[16]),
		Client:      ClientType(data[17]),
	}

	payload := data[eventHeaderSize:]
	parsed := ParsedEvent{Raw: event}

	var err error

	switch event.Type {
	case EventTypeSyscallRead, EventTypeSyscallWrite,
		EventTypeSyscallFutex, EventTypeSyscallMmap,
		EventTypeSyscallEpollWait, EventTypeSyscallFsync,
		EventTypeSyscallFdatasync, EventTypeSyscallPwrite:
		parsed.Typed, err = parseSyscallEvent(event, payload)
	case EventTypeDiskIO:
		parsed.Typed, err = parseDiskIOEvent(event, payload)
	case EventTypeNetTX, EventTypeNetRX:
		parsed.Typed, err = parseNetIOEvent(event, payload)
	case EventTypeSchedSwitch:
		parsed.Typed, err = parseSchedEvent(event, payload)
	case EventTypeSchedRunqueue:
		parsed.Typed, err = parseSchedRunqueueEvent(event, payload)
	case EventTypePageFault:
		parsed.Typed, err = parsePageFaultEvent(event, payload)
	case EventTypeFDOpen, EventTypeFDClose:
		parsed.Typed, err = parseFDEvent(event, payload)
	case EventTypeBlockMerge:
		parsed.Typed, err = parseBlockMergeEvent(event, payload)
	case EventTypeTcpRetransmit:
		parsed.Typed, err = parseTcpRetransmitEvent(event, payload)
	case EventTypeTcpState:
		parsed.Typed, err = parseTcpStateEvent(event, payload)
	case EventTypeMemReclaim, EventTypeMemCompaction:
		parsed.Typed, err = parseMemLatencyEvent(event, payload)
	case EventTypeSwapIn, EventTypeSwapOut:
		parsed.Typed, err = parseSwapEvent(event, payload)
	case EventTypeOOMKill:
		parsed.Typed, err = parseOOMKillEvent(event, payload)
	case EventTypeProcessExit:
		parsed.Typed, err = parseProcessExitEvent(event, payload)
	default:
		return ParsedEvent{}, fmt.Errorf(
			"unknown event type: %d", event.Type,
		)
	}

	if err != nil {
		return ParsedEvent{}, err
	}

	return parsed, nil
}

func ensurePayloadSize(data []byte, need int, eventName string) error {
	if len(data) < need {
		return fmt.Errorf(
			"reading %s: %w", eventName, io.ErrUnexpectedEOF,
		)
	}

	return nil
}

func parseSyscallEvent(
	base Event,
	data []byte,
) (SyscallEvent, error) {
	if err := ensurePayloadSize(data, 24, "syscall event"); err != nil {
		return SyscallEvent{}, err
	}

	return SyscallEvent{
		Event:     base,
		LatencyNs: binary.LittleEndian.Uint64(data[0:8]),
		Return:    int64(binary.LittleEndian.Uint64(data[8:16])),
		SyscallNr: binary.LittleEndian.Uint32(data[16:20]),
		FD:        int32(binary.LittleEndian.Uint32(data[20:24])),
	}, nil
}

func parseDiskIOEvent(
	base Event,
	data []byte,
) (DiskIOEvent, error) {
	if err := ensurePayloadSize(data, 24, "disk IO event"); err != nil {
		return DiskIOEvent{}, err
	}

	return DiskIOEvent{
		Event:      base,
		LatencyNs:  binary.LittleEndian.Uint64(data[0:8]),
		Bytes:      binary.LittleEndian.Uint32(data[8:12]),
		ReadWrite:  data[12],
		QueueDepth: binary.LittleEndian.Uint32(data[16:20]),
		DeviceID:   binary.LittleEndian.Uint32(data[20:24]),
	}, nil
}

func parseNetIOEvent(
	base Event,
	data []byte,
) (NetIOEvent, error) {
	if err := ensurePayloadSize(data, 20, "net IO event"); err != nil {
		return NetIOEvent{}, err
	}

	return NetIOEvent{
		Event:      base,
		Bytes:      binary.LittleEndian.Uint32(data[0:4]),
		SrcPort:    binary.LittleEndian.Uint16(data[4:6]),
		DstPort:    binary.LittleEndian.Uint16(data[6:8]),
		Dir:        Direction(data[8]),
		HasMetrics: data[9] != 0,
		SrttUs:     binary.LittleEndian.Uint32(data[12:16]),
		Cwnd:       binary.LittleEndian.Uint32(data[16:20]),
	}, nil
}

func parseSchedEvent(
	base Event,
	data []byte,
) (SchedEvent, error) {
	if err := ensurePayloadSize(data, 16, "sched event"); err != nil {
		return SchedEvent{}, err
	}

	return SchedEvent{
		Event:     base,
		OnCpuNs:   binary.LittleEndian.Uint64(data[0:8]),
		Voluntary: data[8] != 0,
	}, nil
}

func parsePageFaultEvent(
	base Event,
	data []byte,
) (PageFaultEvent, error) {
	if err := ensurePayloadSize(data, 16, "page fault event"); err != nil {
		return PageFaultEvent{}, err
	}

	return PageFaultEvent{
		Event:   base,
		Address: binary.LittleEndian.Uint64(data[0:8]),
		Major:   data[8] != 0,
	}, nil
}

func parseFDEvent(
	base Event,
	data []byte,
) (FDEvent, error) {
	if err := ensurePayloadSize(data, 72, "FD event"); err != nil {
		return FDEvent{}, err
	}

	filename := string(bytes.TrimRight(data[8:72], "\x00"))

	return FDEvent{
		Event:    base,
		FD:       int32(binary.LittleEndian.Uint32(data[0:4])),
		Filename: filename,
	}, nil
}

func parseSchedRunqueueEvent(
	base Event,
	data []byte,
) (SchedRunqueueEvent, error) {
	if err := ensurePayloadSize(data, 16, "sched runqueue event"); err != nil {
		return SchedRunqueueEvent{}, err
	}

	return SchedRunqueueEvent{
		Event:      base,
		RunqueueNs: binary.LittleEndian.Uint64(data[0:8]),
		OffCpuNs:   binary.LittleEndian.Uint64(data[8:16]),
	}, nil
}

func parseBlockMergeEvent(
	base Event,
	data []byte,
) (BlockMergeEvent, error) {
	if err := ensurePayloadSize(data, 8, "block merge event"); err != nil {
		return BlockMergeEvent{}, err
	}

	return BlockMergeEvent{
		Event:     base,
		Bytes:     binary.LittleEndian.Uint32(data[0:4]),
		ReadWrite: data[4],
	}, nil
}

func parseTcpRetransmitEvent(
	base Event,
	data []byte,
) (TcpRetransmitEvent, error) {
	if err := ensurePayloadSize(data, 16, "tcp retransmit event"); err != nil {
		return TcpRetransmitEvent{}, err
	}

	return TcpRetransmitEvent{
		Event:   base,
		Bytes:   binary.LittleEndian.Uint32(data[0:4]),
		SrcPort: binary.LittleEndian.Uint16(data[4:6]),
		DstPort: binary.LittleEndian.Uint16(data[6:8]),
	}, nil
}

func parseTcpStateEvent(
	base Event,
	data []byte,
) (TcpStateEvent, error) {
	if err := ensurePayloadSize(data, 16, "tcp state event"); err != nil {
		return TcpStateEvent{}, err
	}

	return TcpStateEvent{
		Event:    base,
		SrcPort:  binary.LittleEndian.Uint16(data[0:2]),
		DstPort:  binary.LittleEndian.Uint16(data[2:4]),
		NewState: data[4],
		OldState: data[5],
	}, nil
}

func parseMemLatencyEvent(
	base Event,
	data []byte,
) (MemLatencyEvent, error) {
	if err := ensurePayloadSize(data, 8, "mem latency event"); err != nil {
		return MemLatencyEvent{}, err
	}

	return MemLatencyEvent{
		Event:      base,
		DurationNs: binary.LittleEndian.Uint64(data[0:8]),
	}, nil
}

func parseSwapEvent(
	base Event,
	data []byte,
) (SwapEvent, error) {
	if err := ensurePayloadSize(data, 8, "swap event"); err != nil {
		return SwapEvent{}, err
	}

	return SwapEvent{
		Event: base,
		Pages: binary.LittleEndian.Uint64(data[0:8]),
	}, nil
}

func parseOOMKillEvent(
	base Event,
	data []byte,
) (OOMKillEvent, error) {
	if err := ensurePayloadSize(data, 8, "oom kill event"); err != nil {
		return OOMKillEvent{}, err
	}

	return OOMKillEvent{
		Event:     base,
		TargetPID: binary.LittleEndian.Uint32(data[0:4]),
	}, nil
}

func parseProcessExitEvent(
	base Event,
	data []byte,
) (ProcessExitEvent, error) {
	if err := ensurePayloadSize(data, 8, "process exit event"); err != nil {
		return ProcessExitEvent{}, err
	}

	return ProcessExitEvent{
		Event:    base,
		ExitCode: binary.LittleEndian.Uint32(data[0:4]),
	}, nil
}

func (t *tracer) attachPrograms() error {
	var err error

	// Reset attachment stats.
	t.attachStats = AttachmentStats{}

	attachTracepoint := func(group, name string, prog *ebpf.Program) {
		if err != nil || prog == nil {
			return
		}

		var l link.Link

		l, err = link.Tracepoint(group, name, prog, nil)
		if err != nil {
			t.attachStats.TracepointsFailed++
			err = fmt.Errorf(
				"attaching tracepoint %s/%s: %w", group, name, err,
			)

			return
		}

		t.attachStats.TracepointsAttached++
		t.links = append(t.links, l)

		t.log.WithFields(logrus.Fields{
			"group": group,
			"name":  name,
		}).Debug("Attached tracepoint")
	}

	attachTracepointOptional := func(group, name string, prog *ebpf.Program) {
		if prog == nil {
			return
		}

		l, attachErr := link.Tracepoint(group, name, prog, nil)
		if attachErr != nil {
			t.attachStats.TracepointsFailed++
			t.log.WithError(attachErr).WithFields(logrus.Fields{
				"group": group,
				"name":  name,
			}).Warn("Optional tracepoint attach failed")

			return
		}

		t.attachStats.TracepointsAttached++
		t.links = append(t.links, l)
		t.log.WithFields(logrus.Fields{
			"group": group,
			"name":  name,
		}).Debug("Attached optional tracepoint")
	}

	attachKprobe := func(symbol string, prog *ebpf.Program) {
		if err != nil || prog == nil {
			return
		}

		var l link.Link

		l, err = link.Kprobe(symbol, prog, nil)
		if err != nil {
			t.attachStats.KprobesFailed++
			err = fmt.Errorf(
				"attaching kprobe %s: %w", symbol, err,
			)

			return
		}

		t.attachStats.KprobesAttached++
		t.links = append(t.links, l)

		t.log.WithField("symbol", symbol).
			Debug("Attached kprobe")
	}

	attachKprobeOptional := func(symbol string, prog *ebpf.Program) {
		if prog == nil {
			return
		}

		l, attachErr := link.Kprobe(symbol, prog, nil)
		if attachErr != nil {
			t.attachStats.KprobesFailed++
			t.log.WithError(attachErr).WithField("symbol", symbol).
				Warn("Optional kprobe attach failed")

			return
		}

		t.attachStats.KprobesAttached++
		t.links = append(t.links, l)
		t.log.WithField("symbol", symbol).
			Debug("Attached optional kprobe")
	}

	attachKretprobe := func(symbol string, prog *ebpf.Program) {
		if err != nil || prog == nil {
			return
		}

		var l link.Link

		l, err = link.Kretprobe(symbol, prog, nil)
		if err != nil {
			t.attachStats.KretprobesFailed++
			err = fmt.Errorf(
				"attaching kretprobe %s: %w", symbol, err,
			)

			return
		}

		t.attachStats.KretprobesAttached++
		t.links = append(t.links, l)

		t.log.WithField("symbol", symbol).
			Debug("Attached kretprobe")
	}

	// Syscall tracers
	attachTracepoint("syscalls", "sys_enter_read",
		t.objs.TraceSysEnterRead)
	attachTracepoint("syscalls", "sys_exit_read",
		t.objs.TraceSysExitRead)
	attachTracepoint("syscalls", "sys_enter_write",
		t.objs.TraceSysEnterWrite)
	attachTracepoint("syscalls", "sys_exit_write",
		t.objs.TraceSysExitWrite)
	attachTracepoint("syscalls", "sys_enter_futex",
		t.objs.TraceSysEnterFutex)
	attachTracepoint("syscalls", "sys_exit_futex",
		t.objs.TraceSysExitFutex)
	attachTracepoint("syscalls", "sys_enter_mmap",
		t.objs.TraceSysEnterMmap)
	attachTracepoint("syscalls", "sys_exit_mmap",
		t.objs.TraceSysExitMmap)
	attachTracepoint("syscalls", "sys_enter_epoll_wait",
		t.objs.TraceSysEnterEpollWait)
	attachTracepoint("syscalls", "sys_exit_epoll_wait",
		t.objs.TraceSysExitEpollWait)
	attachTracepoint("syscalls", "sys_enter_fsync",
		t.objs.TraceSysEnterFsync)
	attachTracepoint("syscalls", "sys_exit_fsync",
		t.objs.TraceSysExitFsync)
	attachTracepoint("syscalls", "sys_enter_fdatasync",
		t.objs.TraceSysEnterFdatasync)
	attachTracepoint("syscalls", "sys_exit_fdatasync",
		t.objs.TraceSysExitFdatasync)
	attachTracepoint("syscalls", "sys_enter_pwrite64",
		t.objs.TraceSysEnterPwrite64)
	attachTracepoint("syscalls", "sys_exit_pwrite64",
		t.objs.TraceSysExitPwrite64)

	// FD tracers
	attachTracepoint("syscalls", "sys_enter_openat",
		t.objs.TraceSysEnterOpenat)
	attachTracepoint("syscalls", "sys_exit_openat",
		t.objs.TraceSysExitOpenat)
	attachTracepoint("syscalls", "sys_enter_close",
		t.objs.TraceSysEnterClose)

	// Disk I/O tracers
	attachTracepoint("block", "block_rq_issue",
		t.objs.TraceBlockRqIssue)
	attachTracepoint("block", "block_rq_complete",
		t.objs.TraceBlockRqComplete)
	attachTracepointOptional("block", "block_rq_merge",
		t.objs.TraceBlockRqMerge)

	// Network tracers
	attachKprobe("tcp_sendmsg", t.objs.KprobeTcpSendmsg)
	attachKprobe("tcp_recvmsg", t.objs.KprobeTcpRecvmsg)
	attachKretprobe("tcp_recvmsg", t.objs.KretprobeTcpRecvmsg)
	attachKprobeOptional("tcp_retransmit_skb", t.objs.KprobeTcpRetransmitSkb)
	attachKprobeOptional("tcp_set_state", t.objs.KprobeTcpSetState)

	// Scheduler tracer
	attachTracepoint("sched", "sched_switch",
		t.objs.TraceSchedSwitch)
	attachTracepointOptional("sched", "sched_wakeup",
		t.objs.TraceSchedWakeup)
	attachTracepointOptional("sched", "sched_wakeup_new",
		t.objs.TraceSchedWakeupNew)

	// Memory tracers
	attachKprobe("handle_mm_fault", t.objs.KprobeHandleMmFault)
	attachKretprobe("handle_mm_fault", t.objs.KretprobeHandleMmFault)

	// Memory pressure/oom/process lifecycle (optional).
	attachTracepointOptional("vmscan", "mm_vmscan_direct_reclaim_begin",
		t.objs.TraceReclaimBegin)
	attachTracepointOptional("vmscan", "mm_vmscan_direct_reclaim_end",
		t.objs.TraceReclaimEnd)
	attachTracepointOptional("compaction", "compaction_begin",
		t.objs.TraceCompactionBegin)
	attachTracepointOptional("compaction", "compaction_end",
		t.objs.TraceCompactionEnd)
	attachTracepointOptional("swap", "swapin",
		t.objs.TraceSwapin)
	attachTracepointOptional("swap", "swapout",
		t.objs.TraceSwapout)
	attachTracepointOptional("oom", "oom_kill",
		t.objs.TraceOomKill)
	attachKprobeOptional("do_exit", t.objs.KprobeDoExit)

	return err
}

func (t *tracer) cleanup() {
	for _, l := range t.links {
		l.Close()
	}

	t.links = nil

	if t.objs != nil {
		t.objs.Close()
		t.objs = nil
	}
}
