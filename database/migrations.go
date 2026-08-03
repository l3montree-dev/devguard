package database

import (
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	migsource "github.com/golang-migrate/migrate/v4/source"
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

// RunMigrations runs all pending migrations inside a single transaction, so a failure
// anywhere in the batch rolls back the whole thing instead of leaving partial state.
func RunMigrations(db shared.DB) error {
	src, err := iofs.New(migrationFiles, "migrations")
	if err != nil {
		return fmt.Errorf("failed to load migration source: %w", err)
	}
	defer src.Close()

	return RunMigrationsFromSource(db, src)
}

// RunMigrationsFromSource is RunMigrations with an injectable migration source, so tests
// can exercise it against crafted migrations instead of the real embedded ones.
func RunMigrationsFromSource(db shared.DB, src migsource.Driver) error {
	ownedPool := db == nil
	if ownedPool {
		cfg := GetPoolConfigFromEnv()
		cfg.MaxOpenConns = 1
		cfg.MinConns = 0
		db = NewGormDB(NewPgxConnPool(cfg))
	}

	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("failed to get sql.DB: %w", err)
	}
	if ownedPool {
		defer sqlDB.Close()
	}

	// postgres.WithInstance's Close() closes the whole *sql.DB it's given, not just its own
	// connection, which would kill a caller-supplied pool - so schema_migrations is handled directly.
	if _, err := sqlDB.Exec("CREATE TABLE IF NOT EXISTS public.schema_migrations (version bigint not null primary key, dirty boolean not null)"); err != nil {
		return fmt.Errorf("failed to ensure schema_migrations exists: %w", err)
	}

	currentVersion := -1
	dirty := false
	row := sqlDB.QueryRow("SELECT version, dirty FROM public.schema_migrations LIMIT 1")
	if err := row.Scan(&currentVersion, &dirty); err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("failed to read migration version: %w", err)
	}
	if dirty {
		return fmt.Errorf("database is in a dirty migration state at version %d - manual intervention required", currentVersion)
	}

	versions, err := pendingVersions(src, currentVersion)
	if err != nil {
		return fmt.Errorf("failed to determine pending migrations: %w", err)
	}
	if len(versions) == 0 {
		slog.Info("no pending migrations")
		return nil
	}

	tx, err := sqlDB.Begin()
	if err != nil {
		return fmt.Errorf("failed to start migration transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	for _, v := range versions {
		r, identifier, err := src.ReadUp(v)
		if err != nil {
			return fmt.Errorf("failed to read migration %d: %w", v, err)
		}
		content, readErr := io.ReadAll(r)
		r.Close()
		if readErr != nil {
			return fmt.Errorf("failed to read migration %d (%s): %w", v, identifier, readErr)
		}
		if _, err := tx.Exec(string(content)); err != nil {
			return fmt.Errorf("migration %d (%s) failed, all pending migrations in this run were rolled back: %w", v, identifier, err)
		}
		slog.Info("applied migration", "version", v, "name", identifier)
	}

	if _, err := tx.Exec("SET search_path TO public"); err != nil {
		return fmt.Errorf("failed to restore search_path: %w", err)
	}

	lastVersion := versions[len(versions)-1]
	if _, err := tx.Exec("TRUNCATE public.schema_migrations"); err != nil {
		return fmt.Errorf("failed to update migration version: %w", err)
	}
	if _, err := tx.Exec("INSERT INTO public.schema_migrations (version, dirty) VALUES ($1, false)", lastVersion); err != nil {
		return fmt.Errorf("failed to update migration version: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit migrations: %w", err)
	}
	committed = true

	migrationVersion, migrationDirty, migratorErr = uint(lastVersion), false, nil
	slog.Info("migrations completed successfully")
	return nil
}

// pendingVersions returns every migration version after currentVersion (-1 = none applied yet), in order.
func pendingVersions(src migsource.Driver, currentVersion int) ([]uint, error) {
	var versions []uint
	var next uint
	var err error

	if currentVersion < 0 {
		next, err = src.First()
	} else {
		next, err = src.Next(uint(currentVersion))
	}
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	versions = append(versions, next)

	for {
		next, err = src.Next(next)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				break
			}
			return nil, err
		}
		versions = append(versions, next)
	}

	return versions, nil
}

// GetMigrationVersionWithDB returns the current migration version using an existing GORM database instance
func GetMigrationVersionWithDB() (uint, bool, error) {
	if migrationVersion != 0 || migratorErr != nil {
		db := NewGormDB(NewPgxConnPool(GetPoolConfigFromEnv()))
		migrator, _ = getMigrator(db)
		defer migrator.Close()
		migrationVersion, migrationDirty, migratorErr = migrator.Version()
	}

	return migrationVersion, migrationDirty, migratorErr
}
