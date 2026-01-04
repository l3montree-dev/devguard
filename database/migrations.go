package database

import (
	"embed"
	"fmt"
	"log/slog"
	"sync"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/l3montree-dev/devguard/shared"
)

var (
	migratorOnce sync.Once
	migrator     *migrate.Migrate
	migratorErr  error
)

func getMigrator(gormDB shared.DB) (*migrate.Migrate, error) {
	migratorOnce.Do(func() {
		sqlDB, err := gormDB.DB()
		if err != nil {
			migratorErr = err
			return
		}

		driver, err := postgres.WithInstance(sqlDB, &postgres.Config{})
		if err != nil {
			migratorErr = err
			return
		}

		source, err := iofs.New(migrationFiles, "migrations")
		if err != nil {
			migratorErr = err
			return
		}

		migrator, migratorErr = migrate.NewWithInstance(
			"iofs",
			source,
			"postgres",
			driver,
		)
	})

	return migrator, migratorErr
}

//go:embed migrations/*.sql
var migrationFiles embed.FS

// RunMigrationsWithDB runs all pending database migrations using an existing GORM database instance
func RunMigrationsWithDB(gormDB shared.DB) error {
	// Get the underlying sql.DB from GORM
	migrator, err := getMigrator(gormDB)
	if err != nil {
		return fmt.Errorf("failed to create migrator: %w", err)
	}

	// Run all pending migrations
	if err := migrator.Up(); err != nil {
		if err == migrate.ErrNoChange {
			slog.Info("no pending migrations")
			return nil
		}
		return fmt.Errorf("failed to run migrations: %w", err)
	}

	slog.Info("migrations completed successfully")
	return nil
}

// GetMigrationVersionWithDB returns the current migration version using an existing GORM database instance
func GetMigrationVersionWithDB(gormDB shared.DB) (uint, bool, error) {
	migrator, err := getMigrator(gormDB)
	if err != nil {
		return 0, false, fmt.Errorf("failed to create migrator: %w", err)
	}
	return migrator.Version()
}
