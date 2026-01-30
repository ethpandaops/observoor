package agent

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/ethpandaops/observoor/internal/tracer"
)

// PortInfo contains discovered ports for a PID.
type PortInfo struct {
	PID        uint32
	ClientType tracer.ClientType
	Ports      map[uint16]struct{}
}

// DefaultPorts defines well-known ports per client type.
// Used as fallback when ports can't be parsed from cmdline.
var DefaultPorts = map[tracer.ClientType][]uint16{
	// Execution clients
	tracer.ClientTypeGeth:       {8545, 8546, 8551, 30303},
	tracer.ClientTypeReth:       {8545, 8546, 8551, 30303},
	tracer.ClientTypeBesu:       {8545, 8546, 8551, 30303},
	tracer.ClientTypeNethermind: {8545, 8551, 30303},
	tracer.ClientTypeErigon:     {8545, 8551, 30303},
	// Consensus clients
	tracer.ClientTypeLighthouse: {5052, 9000, 9001},
	tracer.ClientTypePrysm:      {3500, 4000, 13000, 12000},
	tracer.ClientTypeTeku:       {5051, 5052, 9000},
	tracer.ClientTypeLodestar:   {9596, 9000},
	tracer.ClientTypeNimbus:     {5052, 9000},
}

// PortFlags defines command-line flags that specify ports per client.
// Format: flag name -> whether it uses "=" separator (--flag=value vs --flag value).
var PortFlags = map[tracer.ClientType][]string{
	// Geth-style flags (--flag value or --flag=value)
	tracer.ClientTypeGeth: {
		"--http.port", "--ws.port", "--authrpc.port", "--port",
		"--discovery.port",
	},
	tracer.ClientTypeReth: {
		"--http.port", "--ws.port", "--authrpc.port", "--port",
		"--discovery.port", "--discovery.v5.port",
	},
	tracer.ClientTypeErigon: {
		"--http.port", "--ws.port", "--authrpc.port", "--port",
		"--p2p.port",
	},
	// Besu-style flags
	tracer.ClientTypeBesu: {
		"--rpc-http-port", "--rpc-ws-port", "--engine-rpc-port",
		"--p2p-port", "--discovery-port",
	},
	// Nethermind-style flags
	tracer.ClientTypeNethermind: {
		"--JsonRpc.Port", "--JsonRpc.EnginePort", "--Network.P2PPort",
		"--Network.DiscoveryPort",
	},
	// Lighthouse flags
	tracer.ClientTypeLighthouse: {
		"--http-port", "--port", "--discovery-port", "--quic-port",
	},
	// Prysm flags
	tracer.ClientTypePrysm: {
		"--grpc-gateway-port", "--rpc-port", "--p2p-tcp-port",
		"--p2p-udp-port",
	},
	// Teku flags
	tracer.ClientTypeTeku: {
		"--rest-api-port", "--p2p-port", "--p2p-udp-port",
	},
	// Lodestar flags
	tracer.ClientTypeLodestar: {
		"--rest.port", "--port", "--discoveryPort",
	},
	// Nimbus flags
	tracer.ClientTypeNimbus: {
		"--rest-port", "--tcp-port", "--udp-port",
	},
}

// DiscoverPorts extracts port numbers from process command lines.
// Falls back to default ports if parsing fails or no ports found.
func DiscoverPorts(
	log logrus.FieldLogger,
	pids []uint32,
	clientTypes map[uint32]tracer.ClientType,
) map[uint32]*PortInfo {
	result := make(map[uint32]*PortInfo, len(pids))

	for _, pid := range pids {
		clientType := tracer.ClientTypeUnknown
		if ct, ok := clientTypes[pid]; ok {
			clientType = ct
		}

		info := &PortInfo{
			PID:        pid,
			ClientType: clientType,
			Ports:      make(map[uint16]struct{}, 8),
		}

		// Try to parse ports from cmdline.
		cmdline, err := readProcCmdlineRaw(pid)
		if err != nil {
			log.WithError(err).WithField("pid", pid).
				Debug("Failed to read cmdline for port discovery")
		} else {
			parsedPorts := parsePortsFromCmdline(cmdline, clientType)
			for _, port := range parsedPorts {
				info.Ports[port] = struct{}{}
			}
		}

		// If no ports found, use defaults.
		if len(info.Ports) == 0 {
			if defaults, ok := DefaultPorts[clientType]; ok {
				for _, port := range defaults {
					info.Ports[port] = struct{}{}
				}

				log.WithFields(logrus.Fields{
					"pid":    pid,
					"client": clientType.String(),
					"ports":  defaults,
				}).Debug("Using default ports")
			}
		} else {
			ports := make([]uint16, 0, len(info.Ports))
			for p := range info.Ports {
				ports = append(ports, p)
			}

			log.WithFields(logrus.Fields{
				"pid":    pid,
				"client": clientType.String(),
				"ports":  ports,
			}).Debug("Discovered ports from cmdline")
		}

		result[pid] = info
	}

	return result
}

// GetAllTrackedPorts returns a deduplicated set of all ports across all PIDs.
func GetAllTrackedPorts(portInfos map[uint32]*PortInfo) map[uint16]struct{} {
	result := make(map[uint16]struct{}, 32)

	for _, info := range portInfos {
		for port := range info.Ports {
			result[port] = struct{}{}
		}
	}

	return result
}

// parsePortsFromCmdline extracts port numbers from a command line string.
func parsePortsFromCmdline(cmdline string, clientType tracer.ClientType) []uint16 {
	flags, ok := PortFlags[clientType]
	if !ok {
		return nil
	}

	var ports []uint16

	// Split cmdline into args (null-separated in /proc, but we've replaced with spaces).
	args := strings.Fields(cmdline)

	for i, arg := range args {
		for _, flag := range flags {
			// Check for --flag=value format.
			if strings.HasPrefix(arg, flag+"=") {
				value := strings.TrimPrefix(arg, flag+"=")
				if port := parsePort(value); port > 0 {
					ports = append(ports, port)
				}

				continue
			}

			// Check for --flag value format.
			if arg == flag && i+1 < len(args) {
				if port := parsePort(args[i+1]); port > 0 {
					ports = append(ports, port)
				}
			}
		}
	}

	// Also try to find any port-like patterns for unknown clients.
	if clientType == tracer.ClientTypeUnknown {
		ports = append(ports, findPortPatterns(cmdline)...)
	}

	return ports
}

// parsePort converts a string to a port number.
func parsePort(s string) uint16 {
	// Remove any trailing characters (commas, brackets, etc.).
	s = strings.TrimRight(s, ",;)]}")
	s = strings.TrimSpace(s)

	port, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0
	}

	// Sanity check: valid port range.
	if port < 1 || port > 65535 {
		return 0
	}

	return uint16(port)
}

// findPortPatterns looks for common port flag patterns in cmdline.
var portPattern = regexp.MustCompile(`(?:port|PORT)[=:\s]+(\d+)`)

func findPortPatterns(cmdline string) []uint16 {
	matches := portPattern.FindAllStringSubmatch(cmdline, -1)

	var ports []uint16

	for _, match := range matches {
		if len(match) >= 2 {
			if port := parsePort(match[1]); port > 0 {
				ports = append(ports, port)
			}
		}
	}

	return ports
}

// readProcCmdlineRaw reads /proc/<pid>/cmdline and returns it as a string.
func readProcCmdlineRaw(pid uint32) (string, error) {
	path := fmt.Sprintf("/proc/%d/cmdline", pid)

	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", path, err)
	}

	// cmdline uses null bytes as separators.
	return strings.ReplaceAll(string(data), "\x00", " "), nil
}
