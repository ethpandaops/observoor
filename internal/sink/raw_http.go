package sink

import (
	"time"
)

// RawEventJSON is the JSON schema for HTTP export of raw events.
type RawEventJSON struct {
	TimestampNs                uint64 `json:"timestamp_ns"`
	WallclockSlot              uint64 `json:"wallclock_slot"`
	WallclockSlotStartDateTime string `json:"wallclock_slot_start_date_time"`
	PID                        uint32 `json:"pid"`
	TID                        uint32 `json:"tid"`
	EventType                  string `json:"event_type"`
	ClientType                 string `json:"client_type"`
	LatencyNs                  uint64 `json:"latency_ns,omitempty"`
	Bytes                      int64  `json:"bytes,omitempty"`
	SrcPort                    uint16 `json:"src_port,omitempty"`
	DstPort                    uint16 `json:"dst_port,omitempty"`
	FD                         int32  `json:"fd,omitempty"`
	Filename                   string `json:"filename,omitempty"`
	Voluntary                  bool   `json:"voluntary,omitempty"`
	Major                      bool   `json:"major,omitempty"`
	Address                    uint64 `json:"address,omitempty"`
	OnCpuNs                    uint64 `json:"on_cpu_ns,omitempty"`
	RW                         uint8  `json:"rw,omitempty"`
	QueueDepth                 uint32 `json:"queue_depth,omitempty"`
	DeviceID                   uint32 `json:"device_id,omitempty"`
	RunqueueNs                 uint64 `json:"runqueue_ns,omitempty"`
	OffCpuNs                   uint64 `json:"off_cpu_ns,omitempty"`
	TcpState                   uint8  `json:"tcp_state,omitempty"`
	TcpOldState                uint8  `json:"tcp_old_state,omitempty"`
	TcpSrttUs                  uint32 `json:"tcp_srtt_us,omitempty"`
	TcpCwnd                    uint32 `json:"tcp_cwnd,omitempty"`
	Pages                      uint64 `json:"pages,omitempty"`
	ExitCode                   uint32 `json:"exit_code,omitempty"`
	TargetPID                  uint32 `json:"target_pid,omitempty"`
	CLSyncing                  bool   `json:"cl_syncing"`
	ELOptimistic               bool   `json:"el_optimistic"`
	ELOffline                  bool   `json:"el_offline"`
	MetaClientName             string `json:"meta_client_name,omitempty"`
	MetaNetworkName            string `json:"meta_network_name,omitempty"`
}

// toRawEventJSON converts a rawRow to RawEventJSON for HTTP export.
func toRawEventJSON(row rawRow, metaClientName, metaNetworkName string) RawEventJSON {
	return RawEventJSON{
		TimestampNs:                row.TimestampNs,
		WallclockSlot:              row.WallclockSlot,
		WallclockSlotStartDateTime: row.SlotStart.Format(time.RFC3339Nano),
		PID:                        row.PID,
		TID:                        row.TID,
		EventType:                  row.EventType,
		ClientType:                 row.ClientType,
		LatencyNs:                  row.LatencyNs,
		Bytes:                      row.Bytes,
		SrcPort:                    row.SrcPort,
		DstPort:                    row.DstPort,
		FD:                         row.FD,
		Filename:                   row.Filename,
		Voluntary:                  row.Voluntary,
		Major:                      row.Major,
		Address:                    row.Address,
		OnCpuNs:                    row.OnCpuNs,
		RW:                         row.RW,
		QueueDepth:                 row.QueueDepth,
		DeviceID:                   row.DeviceID,
		RunqueueNs:                 row.RunqueueNs,
		OffCpuNs:                   row.OffCpuNs,
		TcpState:                   row.TcpState,
		TcpOldState:                row.TcpOldState,
		TcpSrttUs:                  row.TcpSrttUs,
		TcpCwnd:                    row.TcpCwnd,
		Pages:                      row.Pages,
		ExitCode:                   row.ExitCode,
		TargetPID:                  row.TargetPID,
		CLSyncing:                  row.CLSyncing,
		ELOptimistic:               row.ELOptimistic,
		ELOffline:                  row.ELOffline,
		MetaClientName:             metaClientName,
		MetaNetworkName:            metaNetworkName,
	}
}
