package database

import (
	"embed"
	"fmt"
	"log/slog"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/l3montree-dev/devguard/monitoring"
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
	ownedPool := db == nil
	if ownedPool {
		cfg := GetPoolConfigFromEnv()
		cfg.MaxOpenConns = 1
		cfg.MinConns = 0
		db = NewGormDB(NewPgxConnPool(cfg))
	}
	// Get the underlying sql.DB from GORM
	migrator, err := getMigrator(db)
	if err != nil {
		return fmt.Errorf("failed to create migrator: %w", err)
	}
	if ownedPool {
		// only close the connection pool if WE own it.
		defer migrator.Close()
	}
	versionBefore, _, _ := migrator.Version()

	// Run all pending migrations
	if migrateErr := migrator.Up(); migrateErr != nil {
		if migrateErr == migrate.ErrNoChange {
			slog.Info("no pending migrations")
			return nil
		}
		// Release the migrator's connection (advisory lock + any open tx) before
		// touching schema_migrations on the same pool — with MaxOpenConns=1 this
		// would otherwise deadlock.
		migrator.Close()
		// clear dirty flag and restore version so the migration can be retried — safe in postgres since DDL is transactional
		sqlDB, dbErr := db.DB()
		if dbErr == nil {
			_, err = sqlDB.Exec("UPDATE schema_migrations SET dirty = false, version = $1", versionBefore)
			if err != nil {
				monitoring.Alert("failed to reset migration state after failed migration", err)
			}
		}
		return fmt.Errorf("failed to run migrations: %w", migrateErr)
	}

	migrationVersion, migrationDirty, migratorErr = migrator.Version()
	slog.Info("migrations completed successfully")
	return nil
}

// GetMigrationVersionWithDB returns the current migration version using an existing GORM database instance
func GetMigrationVersionWithDB() (uint, bool, error) {
	if migrationVersion != 0 || migratorErr != nil {
		// create a dedicated db connection for this
		db := NewGormDB(NewPgxConnPool(GetPoolConfigFromEnv()))
		migrator, _ = getMigrator(db)
		defer migrator.Close()
		migrationVersion, migrationDirty, migratorErr = migrator.Version()
	}

	return migrationVersion, migrationDirty, migratorErr
}
