package commands

import (
	"errors"
	"log/slog"
	"os"
	"slices"

	"github.com/golang-migrate/migrate/v4"
	"github.com/l3montree-dev/devguard/database"
	"github.com/l3montree-dev/devguard/vulndb"
	"github.com/spf13/cobra"
)

func NewVulndbCommand() *cobra.Command {
	vulndbCmd := cobra.Command{
		Use:   "vulndb",
		Short: "Manage the vulnerability database",
		Long:  "Commands for managing, synchronizing, and maintaining the vulnerability database from multiple upstream sources including NVD, OSV, ExploitDB, and others.",
	}

	vulndbCmd.AddCommand(newSyncCommand())
	vulndbCmd.AddCommand(newImportCommand())
	vulndbCmd.AddCommand(newExportIncrementalCommand())
	vulndbCmd.AddCommand(newAliasMappingCommand())
	vulndbCmd.AddCommand(newCleanupCommand())
	return &vulndbCmd
}

func emptyOrContains(s []string, e string) bool {
	if len(s) == 0 {
		return true
	}
	return slices.Contains(s, e)
}

func migrateDB() {
	var err error
	var migrator *migrate.Migrate

	pool := database.NewPgxConnPool(database.GetPoolConfigFromEnv())
	db := database.NewGormDB(pool)
	// Run database migrations using the existing database connection
	disableAutoMigrate := os.Getenv("DISABLE_AUTOMIGRATE")
	if disableAutoMigrate != "true" {
		slog.Info("running database migrations...")
		if migrator, err = database.RunMigrationsWithDB(db); err != nil {
			slog.Error("failed to run database migrations", "error", err)
			panic(errors.New("Failed to run database migrations"))
		}

		// Run hash migrations if needed (when algorithm version changes)
		if err := vulndb.RunHashMigrationsIfNeeded(db); err != nil {
			slog.Error("failed to run hash migrations", "error", err)
			panic(errors.New("Failed to run hash migrations"))
		}
	} else {
		slog.Info("automatic migrations disabled via DISABLE_AUTOMIGRATE=true")
	}
	migrator.Close()
}
