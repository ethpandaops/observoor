package pid

// Config holds configuration for PID discovery.
type Config struct {
	// ProcessNames is a list of process names to discover by
	// scanning /proc. E.g. ["geth", "reth", "besu", "nethermind"].
	ProcessNames []string `yaml:"process_names"`

	// CgroupPath is the cgroup v2 path containing the target
	// processes. E.g. "/sys/fs/cgroup/ethereum.slice".
	CgroupPath string `yaml:"cgroup_path"`
}
