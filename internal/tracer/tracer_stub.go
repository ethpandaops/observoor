//go:build !linux

package tracer

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"
)

type tracer struct {
	log           logrus.FieldLogger
	ringBufSize   int
	handlers      []EventHandler
	errorHandlers []ErrorHandler
	statsHandlers []RingbufStatsHandler
}

// New creates a new BPF tracer.
// On non-Linux platforms, this returns a stub that errors on Start.
func New(
	log logrus.FieldLogger,
	ringBufSize int,
) Tracer {
	return &tracer{
		log:           log.WithField("component", "tracer"),
		ringBufSize:   ringBufSize,
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

func (t *tracer) Start(_ context.Context) error {
	return fmt.Errorf("BPF tracer requires Linux")
}

func (t *tracer) Stop() error {
	return nil
}

func (t *tracer) UpdatePIDs(
	_ []uint32,
	_ map[uint32]ClientType,
) error {
	return fmt.Errorf("BPF tracer requires Linux")
}

func (t *tracer) UpdateTIDs(
	_ []uint32,
	_ map[uint32]ClientType,
) error {
	return fmt.Errorf("BPF tracer requires Linux")
}
