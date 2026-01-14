package database

import (
	"embed"
	"fmt"
	"log/slog"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/l3montree-dev/devguard/shared"
)

var (
	//go:embed migrations/*.sql
	migrationFiles   embed.FS
	migrationVersion uint
	migrator         *migrate.Migrate
	migratorErr      error
	migrationDirty   bool
)

func getMigrator(gormDB shared.DB) (*migrate.Migrate, error) {
	sqlDB, err := gormDB.DB()
	if err != nil {
		migratorErr = err
		return nil, migratorErr
	}

	driver, err := postgres.WithInstance(sqlDB, &postgres.Config{})
	if err != nil {
		migratorErr = err
		return nil, migratorErr
	}

	source, err := iofs.New(migrationFiles, "migrations")
	if err != nil {
		migratorErr = err
		return nil, migratorErr
	}

	migrator, migratorErr = migrate.NewWithInstance(
		"iofs",
		source,
		"postgres",
		driver,
	)

	return migrator, migratorErr
}

// RunMigrations runs all pending database migrations using an existing GORM database instance
func RunMigrations(db shared.DB) error {
	// if no shared db is provided, create a new one
	// only provide a db during testing
	if db == nil {
		db = NewGormDB(NewPgxConnPool(GetPoolConfigFromEnv()))
	}
	// Get the underlying sql.DB from GORM
	migrator, err := getMigrator(db)
	if err != nil {
		return fmt.Errorf("failed to create migrator: %w", err)
	}
	if db == nil {
		// only close the connetion pool if WE own it.
		defer migrator.Close()
	}
	// Run all pending migrations
	if err := migrator.Up(); err != nil {
		if err == migrate.ErrNoChange {
			slog.Info("no pending migrations")
			return nil
		}
		return fmt.Errorf("failed to run migrations: %w", err)
	}

	migrationVersion, migrationDirty, migratorErr = migrator.Version()
	slog.Info("migrations completed successfully")
	return nil
}

// GetMigrationVersionWithDB returns the current migration version using an existing GORM database instance
func GetMigrationVersionWithDB() (uint, bool, error) {
	return migrationVersion, migrationDirty, migratorErr
}
