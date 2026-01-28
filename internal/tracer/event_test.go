package tracer

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEventType_String(t *testing.T) {
	tests := []struct {
		eventType EventType
		want      string
	}{
		{EventTypeSyscallRead, "syscall_read"},
		{EventTypeSyscallWrite, "syscall_write"},
		{EventTypeSyscallFutex, "syscall_futex"},
		{EventTypeSyscallMmap, "syscall_mmap"},
		{EventTypeSyscallEpollWait, "syscall_epoll_wait"},
		{EventTypeDiskIO, "disk_io"},
		{EventTypeNetTX, "net_tx"},
		{EventTypeNetRX, "net_rx"},
		{EventTypeSchedSwitch, "sched_switch"},
		{EventTypePageFault, "page_fault"},
		{EventTypeFDOpen, "fd_open"},
		{EventTypeFDClose, "fd_close"},
		{EventType(255), "unknown(255)"},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.want, tt.eventType.String())
	}
}

func TestClientType_String(t *testing.T) {
	tests := []struct {
		clientType ClientType
		want       string
	}{
		{ClientTypeUnknown, "unknown"},
		{ClientTypeGeth, "geth"},
		{ClientTypeReth, "reth"},
		{ClientTypeBesu, "besu"},
		{ClientTypeNethermind, "nethermind"},
		{ClientTypeErigon, "erigon"},
		{ClientTypePrysm, "prysm"},
		{ClientTypeLighthouse, "lighthouse"},
		{ClientTypeTeku, "teku"},
		{ClientTypeLodestar, "lodestar"},
		{ClientTypeNimbus, "nimbus"},
		{ClientType(99), "unknown"},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.want, tt.clientType.String())
	}
}

func TestEventTypeValues(t *testing.T) {
	// Verify event type constants match BPF C enum values.
	assert.Equal(t, EventType(1), EventTypeSyscallRead)
	assert.Equal(t, EventType(2), EventTypeSyscallWrite)
	assert.Equal(t, EventType(3), EventTypeSyscallFutex)
	assert.Equal(t, EventType(4), EventTypeSyscallMmap)
	assert.Equal(t, EventType(5), EventTypeSyscallEpollWait)
	assert.Equal(t, EventType(6), EventTypeDiskIO)
	assert.Equal(t, EventType(7), EventTypeNetTX)
	assert.Equal(t, EventType(8), EventTypeNetRX)
	assert.Equal(t, EventType(9), EventTypeSchedSwitch)
	assert.Equal(t, EventType(10), EventTypePageFault)
	assert.Equal(t, EventType(11), EventTypeFDOpen)
	assert.Equal(t, EventType(12), EventTypeFDClose)
}

func TestClientTypeValues(t *testing.T) {
	// Verify client type constants match BPF C values.
	assert.Equal(t, ClientType(0), ClientTypeUnknown)
	assert.Equal(t, ClientType(1), ClientTypeGeth)
	assert.Equal(t, ClientType(2), ClientTypeReth)
	assert.Equal(t, ClientType(3), ClientTypeBesu)
	assert.Equal(t, ClientType(4), ClientTypeNethermind)
	assert.Equal(t, ClientType(5), ClientTypeErigon)
	assert.Equal(t, ClientType(6), ClientTypePrysm)
	assert.Equal(t, ClientType(7), ClientTypeLighthouse)
	assert.Equal(t, ClientType(8), ClientTypeTeku)
	assert.Equal(t, ClientType(9), ClientTypeLodestar)
	assert.Equal(t, ClientType(10), ClientTypeNimbus)
}
