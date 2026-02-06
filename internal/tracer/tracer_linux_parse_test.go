//go:build linux

package tracer

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func buildRawEvent(
	eventType EventType,
	clientType ClientType,
	payload []byte,
) []byte {
	data := make([]byte, eventHeaderSize+len(payload))
	binary.LittleEndian.PutUint64(data[0:8], 111)
	binary.LittleEndian.PutUint32(data[8:12], 222)
	binary.LittleEndian.PutUint32(data[12:16], 333)
	data[16] = byte(eventType)
	data[17] = byte(clientType)
	copy(data[eventHeaderSize:], payload)

	return data
}

func TestParseEvent_NetIOWithMetrics(t *testing.T) {
	payload := make([]byte, 20)
	binary.LittleEndian.PutUint32(payload[0:4], 1200)
	binary.LittleEndian.PutUint16(payload[4:6], 30303)
	binary.LittleEndian.PutUint16(payload[6:8], 9000)
	payload[8] = byte(DirectionTX)
	payload[9] = 1
	binary.LittleEndian.PutUint32(payload[12:16], 45000)
	binary.LittleEndian.PutUint32(payload[16:20], 128)

	parsed, err := parseEvent(
		buildRawEvent(EventTypeNetTX, ClientTypeLodestar, payload),
	)
	require.NoError(t, err)

	assert.Equal(t, uint64(111), parsed.Raw.TimestampNs)
	assert.Equal(t, uint32(222), parsed.Raw.PID)
	assert.Equal(t, uint32(333), parsed.Raw.TID)
	assert.Equal(t, EventTypeNetTX, parsed.Raw.Type)
	assert.Equal(t, ClientTypeLodestar, parsed.Raw.Client)

	netEvent, ok := parsed.Typed.(NetIOEvent)
	require.True(t, ok)
	assert.Equal(t, uint32(1200), netEvent.Bytes)
	assert.Equal(t, uint16(30303), netEvent.SrcPort)
	assert.Equal(t, uint16(9000), netEvent.DstPort)
	assert.Equal(t, DirectionTX, netEvent.Dir)
	assert.True(t, netEvent.HasMetrics)
	assert.Equal(t, uint32(45000), netEvent.SrttUs)
	assert.Equal(t, uint32(128), netEvent.Cwnd)
}

func TestParseEvent_FDOpenFilenameTrimmed(t *testing.T) {
	payload := make([]byte, 72)
	binary.LittleEndian.PutUint32(payload[0:4], 42)
	copy(payload[8:72], []byte("beacon.db"))

	parsed, err := parseEvent(
		buildRawEvent(EventTypeFDOpen, ClientTypeLighthouse, payload),
	)
	require.NoError(t, err)

	fdEvent, ok := parsed.Typed.(FDEvent)
	require.True(t, ok)
	assert.Equal(t, int32(42), fdEvent.FD)
	assert.Equal(t, "beacon.db", fdEvent.Filename)
}

func TestParseEvent_TruncatedCases(t *testing.T) {
	_, err := parseEvent([]byte{1, 2, 3})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "event too short")

	shortPayload := make([]byte, 7)
	_, err = parseEvent(
		buildRawEvent(EventTypeProcessExit, ClientTypeBesu, shortPayload),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reading process exit event")
}
