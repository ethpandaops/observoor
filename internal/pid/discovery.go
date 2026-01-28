package pid

import (
	"context"

	"github.com/sirupsen/logrus"
)

// Discovery defines the interface for PID discovery mechanisms.
type Discovery interface {
	// Discover finds PIDs matching the configured criteria.
	Discover(ctx context.Context) ([]uint32, error)
}

// NewDiscovery creates a composite discovery that uses both
// process-name and cgroup-based PID discovery.
func NewDiscovery(
	log logrus.FieldLogger,
	cfg Config,
) Discovery {
	return &compositeDiscovery{
		log:     log.WithField("component", "pid"),
		process: newProcessDiscovery(log, cfg.ProcessNames),
		cgroup:  newCgroupDiscovery(log, cfg.CgroupPath),
	}
}

type compositeDiscovery struct {
	log     logrus.FieldLogger
	process *processDiscovery
	cgroup  *cgroupDiscovery
}

func (d *compositeDiscovery) Discover(
	ctx context.Context,
) ([]uint32, error) {
	seen := make(map[uint32]struct{}, 64)
	result := make([]uint32, 0, 64)

	if d.process != nil && len(d.process.names) > 0 {
		pids, err := d.process.Discover(ctx)
		if err != nil {
			d.log.WithError(err).Warn(
				"Process name discovery failed",
			)
		}

		for _, pid := range pids {
			if _, ok := seen[pid]; !ok {
				seen[pid] = struct{}{}
				result = append(result, pid)
			}
		}
	}

	if d.cgroup != nil && d.cgroup.path != "" {
		pids, err := d.cgroup.Discover(ctx)
		if err != nil {
			d.log.WithError(err).Warn(
				"Cgroup discovery failed",
			)
		}

		for _, pid := range pids {
			if _, ok := seen[pid]; !ok {
				seen[pid] = struct{}{}
				result = append(result, pid)
			}
		}
	}

	if len(result) == 0 {
		d.log.Warn("No PIDs discovered")
	} else {
		d.log.WithField("count", len(result)).
			Info("Discovered PIDs")
	}

	return result, nil
}
