package aggregated

// BasicDimension is the key for metrics that only need PID + client type.
// Used for syscalls, page faults, scheduler events, memory events.
type BasicDimension struct {
	PID        uint32
	ClientType string
}

// NetworkDimension is the key for network I/O metrics.
// Includes local port and direction for detailed network breakdown.
type NetworkDimension struct {
	PID        uint32
	ClientType string
	LocalPort  uint16
	Direction  uint8 // 0=TX, 1=RX
}

// TCPMetricsDimension is the key for TCP metrics (RTT, CWND).
// Similar to network but without direction since these are connection-level.
type TCPMetricsDimension struct {
	PID        uint32
	ClientType string
	LocalPort  uint16
}

// DiskDimension is the key for disk I/O metrics.
// Includes device ID and read/write for per-device breakdown.
type DiskDimension struct {
	PID        uint32
	ClientType string
	DeviceID   uint32
	ReadWrite  uint8 // 0=read, 1=write
}

// DirectionString returns a human-readable direction string.
func DirectionString(dir uint8) string {
	if dir == 0 {
		return "tx"
	}

	return "rx"
}

// RWString returns a human-readable read/write string.
func RWString(rw uint8) string {
	if rw == 0 {
		return "read"
	}

	return "write"
}
