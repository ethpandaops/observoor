//go:build linux

package tracer

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/sirupsen/logrus"
)

type tracer struct {
	log         logrus.FieldLogger
	ringBufSize int
	handlers    []EventHandler
	links       []link.Link
	reader      *ringbuf.Reader
	objs        *observoorObjects
	cancel      context.CancelFunc
	wg          sync.WaitGroup
}

// New creates a new BPF tracer.
func New(
	log logrus.FieldLogger,
	ringBufSize int,
) Tracer {
	return &tracer{
		log:         log.WithField("component", "tracer"),
		ringBufSize: ringBufSize,
		handlers:    make([]EventHandler, 0, 4),
	}
}

func (t *tracer) OnEvent(handler EventHandler) {
	t.handlers = append(t.handlers, handler)
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

	// Open ring buffer reader.
	t.reader, err = ringbuf.NewReader(t.objs.Events)
	if err != nil {
		t.cleanup()

		return fmt.Errorf("creating ring buffer reader: %w", err)
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
	clientTypes map[uint32]ClientType,
) error {
	if t.objs == nil {
		return fmt.Errorf("BPF objects not loaded")
	}

	// Clear existing tracked_tids entries.
	var (
		tidKey uint32
		tidVal uint8
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

	// Add new TIDs.
	for _, tid := range tids {
		ct := ClientTypeUnknown
		if c, ok := clientTypes[tid]; ok {
			ct = c
		}

		if err := t.objs.TrackedTids.Put(tid, uint8(ct)); err != nil {
			return fmt.Errorf("adding TID %d to BPF map: %w", tid, err)
		}
	}

	t.log.WithField("count", len(tids)).
		Debug("Updated tracked TIDs")

	return nil
}

func (t *tracer) readLoop(ctx context.Context) {
	defer t.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		record, err := t.reader.Read()
		if err != nil {
			if errors.Is(err, os.ErrClosed) {
				return
			}

			t.log.WithError(err).Warn("Ring buffer read error")

			continue
		}

		event, err := parseEvent(record.RawSample)
		if err != nil {
			t.log.WithError(err).Debug("Event parse error")

			continue
		}

		for _, handler := range t.handlers {
			handler(event)
		}
	}
}

// parseEvent decodes a raw ring buffer sample into a ParsedEvent.
func parseEvent(data []byte) (ParsedEvent, error) {
	if len(data) < 24 {
		return ParsedEvent{}, fmt.Errorf(
			"event too short: %d bytes", len(data),
		)
	}

	reader := bytes.NewReader(data)

	var header struct {
		TimestampNs uint64
		PID         uint32
		TID         uint32
		EventType   uint8
		ClientType  uint8
		Pad         [6]byte
	}

	if err := binary.Read(reader, binary.LittleEndian, &header); err != nil {
		return ParsedEvent{}, fmt.Errorf("reading event header: %w", err)
	}

	event := Event{
		TimestampNs: header.TimestampNs,
		PID:         header.PID,
		TID:         header.TID,
		Type:        EventType(header.EventType),
		Client:      ClientType(header.ClientType),
	}

	parsed := ParsedEvent{Raw: event}

	var err error

	switch event.Type {
	case EventTypeSyscallRead, EventTypeSyscallWrite,
		EventTypeSyscallFutex, EventTypeSyscallMmap,
		EventTypeSyscallEpollWait:
		parsed.Typed, err = parseSyscallEvent(event, reader)
	case EventTypeDiskIO:
		parsed.Typed, err = parseDiskIOEvent(event, reader)
	case EventTypeNetTX, EventTypeNetRX:
		parsed.Typed, err = parseNetIOEvent(event, reader)
	case EventTypeSchedSwitch:
		parsed.Typed, err = parseSchedEvent(event, reader)
	case EventTypePageFault:
		parsed.Typed, err = parsePageFaultEvent(event, reader)
	case EventTypeFDOpen, EventTypeFDClose:
		parsed.Typed, err = parseFDEvent(event, reader)
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

func parseSyscallEvent(
	base Event,
	reader *bytes.Reader,
) (SyscallEvent, error) {
	var raw struct {
		LatencyNs uint64
		Return    int64
		SyscallNr uint32
		FD        int32
	}

	if err := binary.Read(reader, binary.LittleEndian, &raw); err != nil {
		return SyscallEvent{}, fmt.Errorf("reading syscall event: %w", err)
	}

	return SyscallEvent{
		Event:     base,
		LatencyNs: raw.LatencyNs,
		Return:    raw.Return,
		SyscallNr: raw.SyscallNr,
		FD:        raw.FD,
	}, nil
}

func parseDiskIOEvent(
	base Event,
	reader *bytes.Reader,
) (DiskIOEvent, error) {
	var raw struct {
		LatencyNs uint64
		Bytes     uint32
		ReadWrite uint8
		Pad       [3]byte
	}

	if err := binary.Read(reader, binary.LittleEndian, &raw); err != nil {
		return DiskIOEvent{}, fmt.Errorf("reading disk IO event: %w", err)
	}

	return DiskIOEvent{
		Event:     base,
		LatencyNs: raw.LatencyNs,
		Bytes:     raw.Bytes,
		ReadWrite: raw.ReadWrite,
	}, nil
}

func parseNetIOEvent(
	base Event,
	reader *bytes.Reader,
) (NetIOEvent, error) {
	var raw struct {
		Bytes uint32
		Sport uint16
		Dport uint16
		Dir   uint8
		Pad   [3]byte
	}

	if err := binary.Read(reader, binary.LittleEndian, &raw); err != nil {
		return NetIOEvent{}, fmt.Errorf("reading net IO event: %w", err)
	}

	return NetIOEvent{
		Event:   base,
		Bytes:   raw.Bytes,
		SrcPort: raw.Sport,
		DstPort: raw.Dport,
		Dir:     Direction(raw.Dir),
	}, nil
}

func parseSchedEvent(
	base Event,
	reader *bytes.Reader,
) (SchedEvent, error) {
	var raw struct {
		OnCpuNs   uint64
		Voluntary uint8
		Pad       [7]byte
	}

	if err := binary.Read(reader, binary.LittleEndian, &raw); err != nil {
		return SchedEvent{}, fmt.Errorf("reading sched event: %w", err)
	}

	return SchedEvent{
		Event:     base,
		OnCpuNs:   raw.OnCpuNs,
		Voluntary: raw.Voluntary != 0,
	}, nil
}

func parsePageFaultEvent(
	base Event,
	reader *bytes.Reader,
) (PageFaultEvent, error) {
	var raw struct {
		Address uint64
		Major   uint8
		Pad     [7]byte
	}

	if err := binary.Read(reader, binary.LittleEndian, &raw); err != nil {
		return PageFaultEvent{}, fmt.Errorf(
			"reading page fault event: %w", err,
		)
	}

	return PageFaultEvent{
		Event:   base,
		Address: raw.Address,
		Major:   raw.Major != 0,
	}, nil
}

func parseFDEvent(
	base Event,
	reader *bytes.Reader,
) (FDEvent, error) {
	var raw struct {
		FD       int32
		Pad      [4]byte
		Filename [64]byte
	}

	if err := binary.Read(reader, binary.LittleEndian, &raw); err != nil {
		return FDEvent{}, fmt.Errorf("reading FD event: %w", err)
	}

	// Null-terminate the filename.
	filename := string(bytes.TrimRight(raw.Filename[:], "\x00"))

	return FDEvent{
		Event:    base,
		FD:       raw.FD,
		Filename: filename,
	}, nil
}

func (t *tracer) attachPrograms() error {
	var err error

	attachTracepoint := func(group, name string, prog *ebpf.Program) {
		if err != nil || prog == nil {
			return
		}

		var l link.Link

		l, err = link.Tracepoint(group, name, prog, nil)
		if err != nil {
			err = fmt.Errorf(
				"attaching tracepoint %s/%s: %w", group, name, err,
			)

			return
		}

		t.links = append(t.links, l)

		t.log.WithFields(logrus.Fields{
			"group": group,
			"name":  name,
		}).Debug("Attached tracepoint")
	}

	attachKprobe := func(symbol string, prog *ebpf.Program) {
		if err != nil || prog == nil {
			return
		}

		var l link.Link

		l, err = link.Kprobe(symbol, prog, nil)
		if err != nil {
			err = fmt.Errorf(
				"attaching kprobe %s: %w", symbol, err,
			)

			return
		}

		t.links = append(t.links, l)

		t.log.WithField("symbol", symbol).
			Debug("Attached kprobe")
	}

	attachKretprobe := func(symbol string, prog *ebpf.Program) {
		if err != nil || prog == nil {
			return
		}

		var l link.Link

		l, err = link.Kretprobe(symbol, prog, nil)
		if err != nil {
			err = fmt.Errorf(
				"attaching kretprobe %s: %w", symbol, err,
			)

			return
		}

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

	// Network tracers
	attachKprobe("tcp_sendmsg", t.objs.KprobeTcpSendmsg)
	attachKprobe("tcp_recvmsg", t.objs.KprobeTcpRecvmsg)
	attachKretprobe("tcp_recvmsg", t.objs.KretprobeTcpRecvmsg)

	// Scheduler tracer
	attachTracepoint("sched", "sched_switch",
		t.objs.TraceSchedSwitch)

	// Memory tracers
	attachKprobe("handle_mm_fault", t.objs.KprobeHandleMmFault)
	attachKretprobe("handle_mm_fault", t.objs.KretprobeHandleMmFault)

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
