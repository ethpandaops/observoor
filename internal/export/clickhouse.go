package export

import (
	"context"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/sirupsen/logrus"
)

// ClickHouseConfig configures the ClickHouse writer.
type ClickHouseConfig struct {
	// Endpoint is the ClickHouse native protocol address.
	Endpoint string `yaml:"endpoint"`

	// Database is the target database name.
	Database string `yaml:"database"`

	// Table is the target table name.
	Table string `yaml:"table"`

	// BatchSize is the number of events per batch insert.
	// Defaults to 10000.
	BatchSize int `yaml:"batch_size"`

	// FlushInterval is the maximum time between flushes.
	// Defaults to 1s.
	FlushInterval time.Duration `yaml:"flush_interval"`

	// Username for ClickHouse authentication.
	Username string `yaml:"username"`

	// Password for ClickHouse authentication.
	Password string `yaml:"password"`

	// MetaClientName is the observoor client/node name for metadata.
	MetaClientName string `yaml:"meta_client_name"`

	// MetaNetworkName is the Ethereum network name (e.g., mainnet, holesky).
	MetaNetworkName string `yaml:"meta_network_name"`
}

// ClickHouseWriter manages writes to ClickHouse.
type ClickHouseWriter struct {
	log  logrus.FieldLogger
	cfg  ClickHouseConfig
	conn clickhouse.Conn
}

// NewClickHouseWriter creates a new ClickHouse writer.
func NewClickHouseWriter(
	log logrus.FieldLogger,
	cfg ClickHouseConfig,
) *ClickHouseWriter {
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 10000
	}

	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = time.Second
	}

	return &ClickHouseWriter{
		log: log.WithField("component", "clickhouse"),
		cfg: cfg,
	}
}

// Start opens the ClickHouse connection.
func (w *ClickHouseWriter) Start(ctx context.Context) error {
	opts := &clickhouse.Options{
		Addr: []string{w.cfg.Endpoint},
		Auth: clickhouse.Auth{
			Database: w.cfg.Database,
			Username: w.cfg.Username,
			Password: w.cfg.Password,
		},
		Settings: clickhouse.Settings{
			"max_execution_time": 60,
		},
		Compression: &clickhouse.Compression{
			Method: clickhouse.CompressionLZ4,
		},
		MaxOpenConns: 5,
		MaxIdleConns: 2,
	}

	conn, err := clickhouse.Open(opts)
	if err != nil {
		return fmt.Errorf("opening ClickHouse connection: %w", err)
	}

	if err := conn.Ping(ctx); err != nil {
		return fmt.Errorf("pinging ClickHouse: %w", err)
	}

	w.conn = conn

	w.log.WithField("endpoint", w.cfg.Endpoint).
		Info("ClickHouse writer connected")

	return nil
}

// Conn returns the underlying ClickHouse connection.
func (w *ClickHouseWriter) Conn() clickhouse.Conn {
	return w.conn
}

// Config returns the writer configuration.
func (w *ClickHouseWriter) Config() ClickHouseConfig {
	return w.cfg
}

// Stop closes the ClickHouse connection.
func (w *ClickHouseWriter) Stop() error {
	if w.conn != nil {
		return w.conn.Close()
	}

	return nil
}
