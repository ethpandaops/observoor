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

type processDiscovery struct {
	log   logrus.FieldLogger
	names []string
}

func newProcessDiscovery(
	log logrus.FieldLogger,
	names []string,
) *processDiscovery {
	return &processDiscovery{
		log:   log.WithField("discovery", "process"),
		names: names,
	}
}

// Discover scans /proc to find PIDs matching the configured
// process names.
func (d *processDiscovery) Discover(
	ctx context.Context,
) ([]uint32, error) {
	if len(d.names) == 0 {
		return nil, nil
	}

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("reading /proc: %w", err)
	}

	nameSet := make(map[string]struct{}, len(d.names))
	for _, n := range d.names {
		nameSet[n] = struct{}{}
	}

	pids := make([]uint32, 0, 16)

	for _, entry := range entries {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		if !entry.IsDir() {
			continue
		}

		pidVal, err := strconv.ParseUint(entry.Name(), 10, 32)
		if err != nil {
			continue // Not a PID directory.
		}

		comm, err := readComm(entry.Name())
		if err != nil {
			continue
		}

		if _, ok := nameSet[comm]; ok {
			d.log.WithFields(logrus.Fields{
				"pid":  pidVal,
				"comm": comm,
			}).Debug("Found matching process")

			pids = append(pids, uint32(pidVal))
		}
	}

	return pids, nil
}

// readComm reads the process name from /proc/<pid>/comm
// or falls back to /proc/<pid>/status.
func readComm(pidStr string) (string, error) {
	commPath := filepath.Join("/proc", pidStr, "comm")

	data, err := os.ReadFile(commPath)
	if err == nil {
		return strings.TrimSpace(string(data)), nil
	}

	// Fall back to /proc/<pid>/status which has "Name:\t<name>".
	statusPath := filepath.Join("/proc", pidStr, "status")

	f, err := os.Open(statusPath)
	if err != nil {
		return "", fmt.Errorf("reading process info for pid %s: %w", pidStr, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Name:") {
			parts := strings.SplitN(line, "\t", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1]), nil
			}
		}
	}

	return "", fmt.Errorf("could not determine process name for pid %s", pidStr)
}
