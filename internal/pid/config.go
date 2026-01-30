package pid

// DefaultProcessNames contains the binary names for all supported
// Ethereum execution and consensus layer clients. Used when no
// explicit process_names or cgroup_path is configured.
var DefaultProcessNames = []string{
	// Execution layer clients
	"geth",
	"reth",
	"besu",
	"nethermind",
	"erigon",
	"ethrex",
	// Consensus layer clients
	"lighthouse",
	"prysm",
	"beacon-chain", // Prysm beacon node binary
	"validator",    // Prysm validator binary
	"teku",
	"lodestar",
	"nimbus",
	"nimbus_beacon_n", // Truncated in /proc/comm (15 char limit)
	// Generic runtime names (client type resolved via cmdline)
	"java",       // Besu/Teku run as java
	"node",       // Lodestar runs as node
	"MainThread", // Node.js main thread name
}

// Config holds configuration for PID discovery.
type Config struct {
	// ProcessNames is a list of process names to discover by
	// scanning /proc. E.g. ["geth", "reth", "besu", "nethermind"].
	// If empty and CgroupPath is also empty, defaults to all
	// known Ethereum client binaries.
	ProcessNames []string `yaml:"process_names"`

	// CgroupPath is the cgroup v2 path containing the target
	// processes. E.g. "/sys/fs/cgroup/ethereum.slice".
	CgroupPath string `yaml:"cgroup_path"`
}
