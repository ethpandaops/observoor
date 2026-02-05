package aggregated

import (
	"context"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/ethpandaops/observoor/internal/export"
)

// ClickHouseExporter exports metrics to ClickHouse.
type ClickHouseExporter struct {
	log    logrus.FieldLogger
	writer *export.ClickHouseWriter
	cfg    export.ClickHouseConfig
	health *export.HealthMetrics
}

// Ensure ClickHouseExporter implements MetricExporter.
var _ MetricExporter = (*ClickHouseExporter)(nil)

// NewClickHouseExporter creates a new ClickHouse exporter.
func NewClickHouseExporter(
	log logrus.FieldLogger,
	writer *export.ClickHouseWriter,
	cfg export.ClickHouseConfig,
	health *export.HealthMetrics,
) *ClickHouseExporter {
	return &ClickHouseExporter{
		log:    log.WithField("exporter", "clickhouse"),
		writer: writer,
		cfg:    cfg,
		health: health,
	}
}

// Name returns the exporter identifier.
func (e *ClickHouseExporter) Name() string {
	return "clickhouse"
}

// Start initializes the exporter (no-op, writer is started separately).
func (e *ClickHouseExporter) Start(_ context.Context) error {
	return nil
}

// Stop shuts down the exporter (no-op, writer is stopped separately).
func (e *ClickHouseExporter) Stop() error {
	return nil
}

// Export writes the metric batch to ClickHouse.
func (e *ClickHouseExporter) Export(ctx context.Context, batch MetricBatch) error {
	var totalRows int

	// Export latency metrics grouped by table.
	latencyByTable := e.groupLatencyByTable(batch.Latency)
	for table, metrics := range latencyByTable {
		if err := e.exportLatencyTable(ctx, table, metrics, batch.Metadata); err != nil {
			return err
		}

		totalRows += len(metrics)
	}

	// Export counter metrics grouped by table.
	counterByTable := e.groupCounterByTable(batch.Counter)
	for table, metrics := range counterByTable {
		if err := e.exportCounterTable(ctx, table, metrics, batch.Metadata); err != nil {
			return err
		}

		totalRows += len(metrics)
	}

	// Export gauge metrics grouped by table.
	gaugeByTable := e.groupGaugeByTable(batch.Gauge)
	for table, metrics := range gaugeByTable {
		if err := e.exportGaugeTable(ctx, table, metrics, batch.Metadata); err != nil {
			return err
		}

		totalRows += len(metrics)
	}

	if totalRows > 0 {
		if e.health != nil {
			e.health.SinkBatchSize.WithLabelValues("aggregated").Observe(float64(totalRows))
		}

		e.log.WithField("rows", totalRows).Debug("Flushed aggregated metrics")
	}

	return nil
}

// groupLatencyByTable groups latency metrics by their table name.
func (e *ClickHouseExporter) groupLatencyByTable(
	metrics []LatencyMetric,
) map[string][]LatencyMetric {
	result := make(map[string][]LatencyMetric, 16)
	for _, m := range metrics {
		result[m.MetricType] = append(result[m.MetricType], m)
	}

	return result
}

// groupCounterByTable groups counter metrics by their table name.
func (e *ClickHouseExporter) groupCounterByTable(
	metrics []CounterMetric,
) map[string][]CounterMetric {
	result := make(map[string][]CounterMetric, 16)
	for _, m := range metrics {
		result[m.MetricType] = append(result[m.MetricType], m)
	}

	return result
}

// groupGaugeByTable groups gauge metrics by their table name.
func (e *ClickHouseExporter) groupGaugeByTable(metrics []GaugeMetric) map[string][]GaugeMetric {
	result := make(map[string][]GaugeMetric, 4)
	for _, m := range metrics {
		result[m.MetricType] = append(result[m.MetricType], m)
	}

	return result
}

// exportLatencyTable writes latency metrics to a specific table.
func (e *ClickHouseExporter) exportLatencyTable(
	ctx context.Context,
	tableName string,
	metrics []LatencyMetric,
	meta BatchMetadata,
) error {
	if len(metrics) == 0 {
		return nil
	}

	conn := e.writer.Conn()
	table := fmt.Sprintf("%s.%s", e.cfg.Database, tableName)

	// Check if this table has disk dimensions.
	hasDiskDimensions := tableName == "disk_latency"

	var query string
	if hasDiskDimensions {
		query = fmt.Sprintf(`INSERT INTO %s (
			updated_date_time, window_start, interval_ms, wallclock_slot, wallclock_slot_start_date_time,
			pid, client_type, device_id, rw,
			sum, count, min, max,
			histogram,
			meta_client_name, meta_network_name
		)`, table)
	} else {
		query = fmt.Sprintf(`INSERT INTO %s (
			updated_date_time, window_start, interval_ms, wallclock_slot, wallclock_slot_start_date_time,
			pid, client_type, sum, count, min, max,
			histogram,
			meta_client_name, meta_network_name
		)`, table)
	}

	batch, err := conn.PrepareBatch(ctx, query)
	if err != nil {
		return fmt.Errorf("preparing %s batch: %w", tableName, err)
	}

	for _, m := range metrics {
		if hasDiskDimensions {
			deviceID := uint32(0)
			if m.DeviceID != nil {
				deviceID = *m.DeviceID
			}

			rw := "read"
			if m.RW != nil {
				rw = *m.RW
			}

			if err := batch.Append(
				meta.UpdatedTime, m.Window.Start, m.Window.IntervalMs, m.Slot.Number, m.Slot.StartTime,
				m.PID, m.ClientType, deviceID, rw,
				m.Sum, m.Count, m.Min, m.Max,
				m.Histogram,
				meta.ClientName, meta.NetworkName,
			); err != nil {
				return fmt.Errorf("appending %s row: %w", tableName, err)
			}
		} else {
			if err := batch.Append(
				meta.UpdatedTime, m.Window.Start, m.Window.IntervalMs, m.Slot.Number, m.Slot.StartTime,
				m.PID, m.ClientType, m.Sum, m.Count, m.Min, m.Max,
				m.Histogram,
				meta.ClientName, meta.NetworkName,
			); err != nil {
				return fmt.Errorf("appending %s row: %w", tableName, err)
			}
		}
	}

	if err := batch.Send(); err != nil {
		e.recordBatchError(tableName)

		return fmt.Errorf("sending %s batch: %w", tableName, err)
	}

	return nil
}

// exportCounterTable writes counter metrics to a specific table.
func (e *ClickHouseExporter) exportCounterTable(
	ctx context.Context,
	tableName string,
	metrics []CounterMetric,
	meta BatchMetadata,
) error {
	if len(metrics) == 0 {
		return nil
	}

	conn := e.writer.Conn()
	table := fmt.Sprintf("%s.%s", e.cfg.Database, tableName)

	// Determine table schema based on dimensions present.
	hasNetworkDimensions := tableName == "net_io" || tableName == "tcp_retransmit"
	hasDiskDimensions := tableName == "disk_bytes" || tableName == "block_merge"

	var query string

	switch {
	case hasNetworkDimensions:
		query = fmt.Sprintf(`INSERT INTO %s (
			updated_date_time, window_start, interval_ms, wallclock_slot, wallclock_slot_start_date_time,
			pid, client_type, local_port, direction, sum, count,
			meta_client_name, meta_network_name
		)`, table)
	case hasDiskDimensions:
		query = fmt.Sprintf(`INSERT INTO %s (
			updated_date_time, window_start, interval_ms, wallclock_slot, wallclock_slot_start_date_time,
			pid, client_type, device_id, rw, sum, count,
			meta_client_name, meta_network_name
		)`, table)
	default:
		query = fmt.Sprintf(`INSERT INTO %s (
			updated_date_time, window_start, interval_ms, wallclock_slot, wallclock_slot_start_date_time,
			pid, client_type, sum, count,
			meta_client_name, meta_network_name
		)`, table)
	}

	batch, err := conn.PrepareBatch(ctx, query)
	if err != nil {
		return fmt.Errorf("preparing %s batch: %w", tableName, err)
	}

	for _, m := range metrics {
		switch {
		case hasNetworkDimensions:
			localPort := uint16(0)
			if m.LocalPort != nil {
				localPort = *m.LocalPort
			}

			direction := "tx"
			if m.Direction != nil {
				direction = *m.Direction
			}

			if err := batch.Append(
				meta.UpdatedTime, m.Window.Start, m.Window.IntervalMs, m.Slot.Number, m.Slot.StartTime,
				m.PID, m.ClientType, localPort, direction, m.Sum, m.Count,
				meta.ClientName, meta.NetworkName,
			); err != nil {
				return fmt.Errorf("appending %s row: %w", tableName, err)
			}
		case hasDiskDimensions:
			deviceID := uint32(0)
			if m.DeviceID != nil {
				deviceID = *m.DeviceID
			}

			rw := "read"
			if m.RW != nil {
				rw = *m.RW
			}

			if err := batch.Append(
				meta.UpdatedTime, m.Window.Start, m.Window.IntervalMs, m.Slot.Number, m.Slot.StartTime,
				m.PID, m.ClientType, deviceID, rw, m.Sum, m.Count,
				meta.ClientName, meta.NetworkName,
			); err != nil {
				return fmt.Errorf("appending %s row: %w", tableName, err)
			}
		default:
			if err := batch.Append(
				meta.UpdatedTime, m.Window.Start, m.Window.IntervalMs, m.Slot.Number, m.Slot.StartTime,
				m.PID, m.ClientType, m.Sum, m.Count,
				meta.ClientName, meta.NetworkName,
			); err != nil {
				return fmt.Errorf("appending %s row: %w", tableName, err)
			}
		}
	}

	if err := batch.Send(); err != nil {
		e.recordBatchError(tableName)

		return fmt.Errorf("sending %s batch: %w", tableName, err)
	}

	return nil
}

// exportGaugeTable writes gauge metrics to a specific table.
func (e *ClickHouseExporter) exportGaugeTable(
	ctx context.Context,
	tableName string,
	metrics []GaugeMetric,
	meta BatchMetadata,
) error {
	if len(metrics) == 0 {
		return nil
	}

	conn := e.writer.Conn()
	table := fmt.Sprintf("%s.%s", e.cfg.Database, tableName)

	// Determine table schema based on dimensions present.
	hasTCPDimensions := tableName == "tcp_rtt" || tableName == "tcp_cwnd"
	hasDiskDimensions := tableName == "disk_queue_depth"

	var query string

	switch {
	case hasTCPDimensions:
		query = fmt.Sprintf(`INSERT INTO %s (
			updated_date_time, window_start, interval_ms, wallclock_slot, wallclock_slot_start_date_time,
			pid, client_type, local_port, sum, count, min, max,
			meta_client_name, meta_network_name
		)`, table)
	case hasDiskDimensions:
		query = fmt.Sprintf(`INSERT INTO %s (
			updated_date_time, window_start, interval_ms, wallclock_slot, wallclock_slot_start_date_time,
			pid, client_type, device_id, rw, sum, count, min, max,
			meta_client_name, meta_network_name
		)`, table)
	default:
		query = fmt.Sprintf(`INSERT INTO %s (
			updated_date_time, window_start, interval_ms, wallclock_slot, wallclock_slot_start_date_time,
			pid, client_type, sum, count, min, max,
			meta_client_name, meta_network_name
		)`, table)
	}

	batch, err := conn.PrepareBatch(ctx, query)
	if err != nil {
		return fmt.Errorf("preparing %s batch: %w", tableName, err)
	}

	for _, m := range metrics {
		switch {
		case hasTCPDimensions:
			localPort := uint16(0)
			if m.LocalPort != nil {
				localPort = *m.LocalPort
			}

			if err := batch.Append(
				meta.UpdatedTime, m.Window.Start, m.Window.IntervalMs, m.Slot.Number, m.Slot.StartTime,
				m.PID, m.ClientType, localPort, m.Sum, m.Count, m.Min, m.Max,
				meta.ClientName, meta.NetworkName,
			); err != nil {
				return fmt.Errorf("appending %s row: %w", tableName, err)
			}
		case hasDiskDimensions:
			deviceID := uint32(0)
			if m.DeviceID != nil {
				deviceID = *m.DeviceID
			}

			rw := "read"
			if m.RW != nil {
				rw = *m.RW
			}

			if err := batch.Append(
				meta.UpdatedTime, m.Window.Start, m.Window.IntervalMs, m.Slot.Number, m.Slot.StartTime,
				m.PID, m.ClientType, deviceID, rw, m.Sum, m.Count, m.Min, m.Max,
				meta.ClientName, meta.NetworkName,
			); err != nil {
				return fmt.Errorf("appending %s row: %w", tableName, err)
			}
		default:
			if err := batch.Append(
				meta.UpdatedTime, m.Window.Start, m.Window.IntervalMs, m.Slot.Number, m.Slot.StartTime,
				m.PID, m.ClientType, m.Sum, m.Count, m.Min, m.Max,
				meta.ClientName, meta.NetworkName,
			); err != nil {
				return fmt.Errorf("appending %s row: %w", tableName, err)
			}
		}
	}

	if err := batch.Send(); err != nil {
		e.recordBatchError(tableName)

		return fmt.Errorf("sending %s batch: %w", tableName, err)
	}

	return nil
}

// recordBatchError increments the batch error counter.
func (e *ClickHouseExporter) recordBatchError(table string) {
	if e.health != nil {
		e.health.ExportBatchErrors.WithLabelValues("aggregated", table).Inc()
	}
}

// SyncStateRow is the data for a sync state record.
type SyncStateRow struct {
	UpdatedDateTime            time.Time
	EventTime                  time.Time
	WallclockSlot              uint32
	WallclockSlotStartDateTime time.Time
	CLSyncing                  bool
	ELOptimistic               bool
	ELOffline                  bool
}

// ExportSyncState writes a sync state row to ClickHouse.
func (e *ClickHouseExporter) ExportSyncState(
	ctx context.Context,
	row SyncStateRow,
	meta BatchMetadata,
) error {
	conn := e.writer.Conn()
	table := fmt.Sprintf("%s.sync_state", e.cfg.Database)

	batch, err := conn.PrepareBatch(ctx, fmt.Sprintf(`INSERT INTO %s (
		updated_date_time, event_time, wallclock_slot, wallclock_slot_start_date_time,
		cl_syncing, el_optimistic, el_offline,
		meta_client_name, meta_network_name
	)`, table))
	if err != nil {
		return fmt.Errorf("preparing sync_state batch: %w", err)
	}

	if err := batch.Append(
		row.UpdatedDateTime, row.EventTime, row.WallclockSlot, row.WallclockSlotStartDateTime,
		row.CLSyncing, row.ELOptimistic, row.ELOffline,
		meta.ClientName, meta.NetworkName,
	); err != nil {
		return fmt.Errorf("appending sync_state row: %w", err)
	}

	if err := batch.Send(); err != nil {
		e.recordBatchError("sync_state")

		return fmt.Errorf("sending sync_state batch: %w", err)
	}

	return nil
}
