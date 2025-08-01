package database

import (
	"embed"
	"fmt"
	"log/slog"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"gorm.io/gorm"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

// RunMigrationsWithDB runs all pending database migrations using an existing GORM database instance
func RunMigrationsWithDB(gormDB *gorm.DB) error {
	// Get the underlying sql.DB from GORM
	sqlDB, err := gormDB.DB()
	if err != nil {
		return fmt.Errorf("failed to get underlying sql.DB from GORM: %w", err)
	}

	// Test the connection
	if err := sqlDB.Ping(); err != nil {
		return fmt.Errorf("failed to ping database: %w", err)
	}

	// Create postgres driver instance
	driver, err := postgres.WithInstance(sqlDB, &postgres.Config{})
	if err != nil {
		return fmt.Errorf("failed to create postgres driver: %w", err)
	}

	// Create source from embedded files
	sourceDriver, err := iofs.New(migrationFiles, "migrations")
	if err != nil {
		return fmt.Errorf("failed to create source driver: %w", err)
	}

	// Create migrate instance
	migrator, err := migrate.NewWithInstance("iofs", sourceDriver, "postgres", driver)
	if err != nil {
		return fmt.Errorf("failed to create migrator: %w", err)
	}
	defer func() {
		if sourceErr, dbErr := migrator.Close(); sourceErr != nil || dbErr != nil {
			slog.Error("failed to close migrator", "sourceErr", sourceErr, "dbErr", dbErr)
		}
	}()

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
func GetMigrationVersionWithDB(gormDB *gorm.DB) (uint, bool, error) {
	// Get the underlying sql.DB from GORM
	sqlDB, err := gormDB.DB()
	if err != nil {
		return 0, false, fmt.Errorf("failed to get underlying sql.DB from GORM: %w", err)
	}

	// Create postgres driver instance
	driver, err := postgres.WithInstance(sqlDB, &postgres.Config{})
	if err != nil {
		return 0, false, fmt.Errorf("failed to create postgres driver: %w", err)
	}

	// Create source from embedded files
	sourceDriver, err := iofs.New(migrationFiles, "migrations")
	if err != nil {
		return 0, false, fmt.Errorf("failed to create source driver: %w", err)
	}

	// Create migrate instance
	migrator, err := migrate.NewWithInstance("iofs", sourceDriver, "postgres", driver)
	if err != nil {
		return 0, false, fmt.Errorf("failed to create migrator: %w", err)
	}
	defer func() {
		if sourceErr, dbErr := migrator.Close(); sourceErr != nil || dbErr != nil {
			slog.Error("failed to close migrator", "sourceErr", sourceErr, "dbErr", dbErr)
		}
	}()

	return migrator.Version()
}
