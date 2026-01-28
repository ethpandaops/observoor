package clock

import (
	"context"
	"fmt"
	"time"

	"github.com/ethpandaops/ethwallclock"
	"github.com/sirupsen/logrus"
)

// SlotChangedFunc is called when the wall clock advances to a new slot.
type SlotChangedFunc func(slot uint64)

// Clock wraps ethwallclock to provide Ethereum slot timing.
type Clock interface {
	// Start begins the clock, subscribing to slot changes.
	Start(ctx context.Context) error
	// Stop terminates the clock.
	Stop() error
	// CurrentSlot returns the current Ethereum slot number.
	CurrentSlot() uint64
	// SlotStartTime returns the wall-clock start time of the given slot.
	SlotStartTime(slot uint64) time.Time
	// MillisIntoSlot returns how many milliseconds have elapsed
	// in the current slot.
	MillisIntoSlot() uint64
	// OnSlotChanged registers a callback for slot transitions.
	OnSlotChanged(fn SlotChangedFunc)
}

type clock struct {
	log            logrus.FieldLogger
	genesisTime    time.Time
	secondsPerSlot uint64
	slotsPerEpoch  uint64
	wallclock      *ethwallclock.EthereumBeaconChain
	callbacks      []SlotChangedFunc
}

// New creates a new Clock from genesis parameters.
func New(
	log logrus.FieldLogger,
	genesisTime time.Time,
	secondsPerSlot uint64,
	slotsPerEpoch uint64,
) (Clock, error) {
	if secondsPerSlot == 0 {
		return nil, fmt.Errorf("secondsPerSlot must be > 0")
	}

	if slotsPerEpoch == 0 {
		return nil, fmt.Errorf("slotsPerEpoch must be > 0")
	}

	wc := ethwallclock.NewEthereumBeaconChain(
		genesisTime,
		time.Duration(secondsPerSlot)*time.Second,
		slotsPerEpoch,
	)

	return &clock{
		log:            log.WithField("component", "clock"),
		genesisTime:    genesisTime,
		secondsPerSlot: secondsPerSlot,
		slotsPerEpoch:  slotsPerEpoch,
		wallclock:      wc,
		callbacks:      make([]SlotChangedFunc, 0, 4),
	}, nil
}

func (c *clock) Start(_ context.Context) error {
	// Register our callback with ethwallclock.
	// ethwallclock calls this in a new goroutine on each slot change.
	c.wallclock.OnSlotChanged(func(slot ethwallclock.Slot) {
		slotNum := slot.Number()

		c.log.WithField("slot", slotNum).
			Debug("Slot changed")

		for _, fn := range c.callbacks {
			fn(slotNum)
		}
	})

	c.log.WithFields(logrus.Fields{
		"genesis_time":     c.genesisTime,
		"seconds_per_slot": c.secondsPerSlot,
		"slots_per_epoch":  c.slotsPerEpoch,
	}).Info("Clock started")

	return nil
}

func (c *clock) Stop() error {
	if c.wallclock != nil {
		c.wallclock.Stop()
	}

	return nil
}

func (c *clock) CurrentSlot() uint64 {
	slot := c.wallclock.Slots().Current()

	return slot.Number()
}

func (c *clock) SlotStartTime(slot uint64) time.Time {
	dur := time.Duration(slot*c.secondsPerSlot) * time.Second

	return c.genesisTime.Add(dur)
}

func (c *clock) MillisIntoSlot() uint64 {
	slot := c.wallclock.Slots().Current()
	elapsed := time.Since(slot.TimeWindow().Start())

	return uint64(elapsed.Milliseconds())
}

func (c *clock) OnSlotChanged(fn SlotChangedFunc) {
	c.callbacks = append(c.callbacks, fn)
}
