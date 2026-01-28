package sink

import (
	"context"

	"github.com/ethpandaops/observoor/internal/tracer"
)

// Config holds configuration for all sinks.
type Config struct {
	Raw    RawConfig    `yaml:"raw"`
	Slot   SlotConfig   `yaml:"slot"`
	Window WindowConfig `yaml:"window"`
}

// Sink defines the interface for event consumers.
type Sink interface {
	// Name returns the sink's name for logging.
	Name() string
	// Start initializes the sink.
	Start(ctx context.Context) error
	// Stop shuts down the sink.
	Stop() error
	// HandleEvent processes a single parsed event.
	HandleEvent(event tracer.ParsedEvent)
	// OnSlotChanged is called at slot boundaries.
	OnSlotChanged(newSlot uint64)
}
