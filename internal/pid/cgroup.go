package pid

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
)

type cgroupDiscovery struct {
	log  logrus.FieldLogger
	path string
}

func newCgroupDiscovery(
	log logrus.FieldLogger,
	path string,
) *cgroupDiscovery {
	return &cgroupDiscovery{
		log:  log.WithField("discovery", "cgroup"),
		path: path,
	}
}

// Discover reads PIDs from the cgroup.procs file at the configured
// cgroup path. This supports cgroup v2.
func (d *cgroupDiscovery) Discover(
	ctx context.Context,
) ([]uint32, error) {
	if d.path == "" {
		return nil, nil
	}

	procsPath := filepath.Join(d.path, "cgroup.procs")

	f, err := os.Open(procsPath)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", procsPath, err)
	}
	defer f.Close()

	pids := make([]uint32, 0, 16)
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		pidVal, err := strconv.ParseUint(line, 10, 32)
		if err != nil {
			d.log.WithField("line", line).
				Warn("Non-numeric line in cgroup.procs")

			continue
		}

		d.log.WithField("pid", pidVal).
			Debug("Found PID in cgroup")

		pids = append(pids, uint32(pidVal))
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading %s: %w", procsPath, err)
	}

	return pids, nil
}
