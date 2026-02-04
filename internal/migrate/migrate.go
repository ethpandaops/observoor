package migrate

import (
	"context"
	"embed"
	"errors"
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/clickhouse" // ClickHouse driver.
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/sirupsen/logrus"
)

//go:embed sql/*.sql
var migrations embed.FS

// Migrator manages ClickHouse schema migrations.
type Migrator interface {
	// Up applies all pending migrations.
	Up(ctx context.Context) error
	// Down rolls back the last migration.
	Down(ctx context.Context) error
	// Status returns the current migration version.
	Status(ctx context.Context) (version uint, dirty bool, err error)
}

type migrator struct {
	log logrus.FieldLogger
	dsn string
}

// New creates a new Migrator.
// The dsn should be a ClickHouse connection string (e.g., "clickhouse://host:9000/database").
func New(log logrus.FieldLogger, dsn string) Migrator {
	return &migrator{
		log: log.WithField("component", "migrate"),
		dsn: dsn,
	}
}

// Up applies all pending migrations.
func (m *migrator) Up(ctx context.Context) error {
	mig, err := m.newMigrate()
	if err != nil {
		return err
	}
	defer mig.Close()

	m.log.Info("Running migrations...")

	if err := mig.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("running migrations: %w", err)
	}

	version, _, _ := mig.Version()
	m.log.WithField("version", version).Info("Migrations completed successfully")

	return nil
}

// Down rolls back the last migration.
func (m *migrator) Down(ctx context.Context) error {
	mig, err := m.newMigrate()
	if err != nil {
		return err
	}
	defer mig.Close()

	m.log.Info("Rolling back last migration...")

	if err := mig.Steps(-1); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("rolling back migration: %w", err)
	}

	m.log.Info("Rollback completed successfully")

	return nil
}

// Status returns the current migration version.
func (m *migrator) Status(ctx context.Context) (uint, bool, error) {
	mig, err := m.newMigrate()
	if err != nil {
		return 0, false, err
	}
	defer mig.Close()

	version, dirty, err := mig.Version()
	if err != nil && !errors.Is(err, migrate.ErrNilVersion) {
		return 0, false, fmt.Errorf("getting migration version: %w", err)
	}

	return version, dirty, nil
}

// newMigrate creates a new migrate instance.
func (m *migrator) newMigrate() (*migrate.Migrate, error) {
	source, err := iofs.New(migrations, "sql")
	if err != nil {
		return nil, fmt.Errorf("creating migration source: %w", err)
	}

	// Add x-multi-statement=true for ClickHouse multi-statement support.
	dsn := m.dsn + "?x-multi-statement=true"

	mig, err := migrate.NewWithSourceInstance("iofs", source, dsn)
	if err != nil {
		return nil, fmt.Errorf("creating migrate instance: %w", err)
	}

	return mig, nil
}
