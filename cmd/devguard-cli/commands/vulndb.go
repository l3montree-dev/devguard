package commands

import (
	"errors"
	"log/slog"
	"os"
	"regexp"
	"slices"
	"time"

	"github.com/l3montree-dev/devguard/cmd/devguard/hashmigrations"
	"github.com/l3montree-dev/devguard/database"
	"github.com/l3montree-dev/devguard/database/repositories"
	"github.com/l3montree-dev/devguard/services"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/l3montree-dev/devguard/vulndb"
	"github.com/spf13/cobra"
)

func NewVulndbCommand() *cobra.Command {
	vulndbCmd := cobra.Command{
		Use:   "vulndb",
		Short: "Vulnerability Database",
	}

	vulndbCmd.AddCommand(newSyncCommand())
	vulndbCmd.AddCommand(newImportCommand())
	vulndbCmd.AddCommand(newExportIncrementalCommand())
	return &vulndbCmd
}

func emptyOrContains(s []string, e string) bool {
	if len(s) == 0 {
		return true
	}
	return slices.Contains(s, e)
}

func isValidCVE(cveID string) bool {
	// should either be just 2023-1234 or cve-2023-1234
	if len(cveID) == 0 {
		return false
	}

	r := regexp.MustCompile(`^CVE-\d{4}-\d{4,7}$`)
	if r.MatchString(cveID) {
		return true
	}

	r = regexp.MustCompile(`^\d{4}-\d{4,7}$`)
	return r.MatchString(cveID)
}

func migrateDB(db shared.DB) {
	// Run database migrations using the existing database connection
	disableAutoMigrate := os.Getenv("DISABLE_AUTOMIGRATE")
	if disableAutoMigrate != "true" {
		slog.Info("running database migrations...")
		if err := database.RunMigrationsWithDB(db); err != nil {
			slog.Error("failed to run database migrations", "error", err)
			panic(errors.New("Failed to run database migrations"))
		}

		// Run hash migrations if needed (when algorithm version changes)
		if err := hashmigrations.RunHashMigrationsIfNeeded(db); err != nil {
			slog.Error("failed to run hash migrations", "error", err)
			panic(errors.New("Failed to run hash migrations"))
		}
	} else {
		slog.Info("automatic migrations disabled via DISABLE_AUTOMIGRATE=true")
	}
}

func newImportCommand() *cobra.Command {
	importCmd := &cobra.Command{
		Use:   "import",
		Short: "Will import the vulnerability database",
		Args:  cobra.MaximumNArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			shared.LoadConfig() // nolint
			database, err := shared.DatabaseFactory()
			if err != nil {
				slog.Error("could not connect to database", "error", err)
				return
			}
			migrateDB(database)

			cveRepository := repositories.NewCVERepository(database)
			cweRepository := repositories.NewCWERepository(database)
			exploitsRepository := repositories.NewExploitRepository(database)
			affectedComponentsRepository := repositories.NewAffectedComponentRepository(database)
			configService := services.NewConfigService(database)
			v := vulndb.NewImportService(cveRepository, cweRepository, exploitsRepository, affectedComponentsRepository, configService)

			err = v.ImportFromDiff(nil)
			if err != nil {
				slog.Error("error when trying to import with diff files", "err", err)
			}
		},
	}

	return importCmd
}

func newSyncCommand() *cobra.Command {
	syncCmd := cobra.Command{
		Use:   "sync",
		Short: "Will sync the vulnerability database",
		Args:  cobra.ExactArgs(0),
		Run: func(cmd *cobra.Command, args []string) {

			shared.LoadConfig() // nolint

			db, err := shared.DatabaseFactory()
			if err != nil {
				slog.Error("could not connect to database", "err", err)
				return
			}

			migrateDB(db)

			databasesToSync, _ := cmd.Flags().GetStringArray("databases")

			cveRepository := repositories.NewCVERepository(db)
			// cweRepository := repositories.NewCWERepository(db)
			affectedCmpRepository := repositories.NewAffectedComponentRepository(db)
			// mitreService := vulndb.NewMitreService(cweRepository)

			// epssService := vulndb.NewEPSSService(cveRepository)

			osvService := vulndb.NewOSVService(affectedCmpRepository, cveRepository, repositories.NewCveRelationshipRepository(db))
			// cvelistService := vulndb.NewCVEListService(cveRepository)
			// debianSecurityTracker := vulndb.NewDebianSecurityTracker(affectedCmpRepository)

			// exploitDBService := vulndb.NewExploitDBService(repositories.NewExploitRepository(db))

			// githubExploitDBService := vulndb.NewGithubExploitDBService(repositories.NewExploitRepository(db))

			slog.Info("start updating vulnDB components:")
			start := time.Now()
			// if emptyOrContains(databasesToSync, "cwe") {
			// 	now := time.Now()
			// 	slog.Info("starting cwe database sync")
			// 	if err := mitreService.Mirror(); err != nil {
			// 		slog.Error("could not mirror cwe database", "err", err)
			// 	}
			// 	slog.Info("finished cwe database sync", "duration", time.Since(now))
			// }

			// if emptyOrContains(databasesToSync, "epss") {
			// 	slog.Info("starting epss database sync")
			// 	now := time.Now()

			// 	if err := epssService.Mirror(); err != nil {
			// 		slog.Error("could not sync epss database", "err", err)
			// 	}
			// 	slog.Info("finished epss database sync", "duration", time.Since(now))
			// }

			if emptyOrContains(databasesToSync, "osv") {
				slog.Info("starting osv database sync")
				now := time.Now()
				if err := osvService.Mirror(); err != nil {
					slog.Error("could not sync osv database", "err", err)
				}
				slog.Info("finished osv database sync", "duration", time.Since(now))
			}

			// if emptyOrContains(databasesToSync, "exploitdb") {
			// 	slog.Info("starting exploitdb database sync")
			// 	now := time.Now()
			// 	if err := exploitDBService.Mirror(); err != nil {
			// 		slog.Error("could not sync exploitdb database", "err", err)
			// 	}
			// 	slog.Info("finished exploitdb database sync", "duration", time.Since(now))
			// }

			// if emptyOrContains(databasesToSync, "github-poc") {
			// 	slog.Info("starting github-poc database sync")
			// 	now := time.Now()
			// 	if err := githubExploitDBService.Mirror(); err != nil {
			// 		slog.Error("could not sync github-poc database", "err", err)
			// 	}
			// 	slog.Info("finished github-poc database sync", "duration", time.Since(now))
			// }

			// if emptyOrContains(databasesToSync, "dsa") {
			// 	slog.Info("starting dsa database sync")
			// 	now := time.Now()
			// 	if err := debianSecurityTracker.Mirror(); err != nil {
			// 		slog.Error("could not sync dsa database", "err", err)
			// 	}
			// 	slog.Info("finished dsa database sync", "duration", time.Since(now))
			// }
			slog.Info("Finished database sync", "time elapsed", time.Since(start))
		},
	}
	syncCmd.Flags().String("after", "", "allows to only sync a subset of data. This is used to identify the 'last correct' date in the nvd database. The sync will only include cve modifications in the interval [after, now]. Format: 2006-01-02")
	syncCmd.Flags().Int("startIndex", 0, "provide a start index to fetch the data from. This is useful after an initial sync failed")
	syncCmd.Flags().StringArray("databases", []string{}, "provide a list of databases to sync. Possible values are: nvd, cvelist, exploitdb, github-poc, cwe, epss, osv, dsa")

	return &syncCmd
}

func newExportIncrementalCommand() *cobra.Command {
	exportCmd := cobra.Command{
		Use:   "export",
		Short: "Will import the new vuln db after sync and export the diff of the old and new state of the vuln db",
		Args:  cobra.ExactArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			// first import the new state
			shared.LoadConfig() // nolint
			os.RemoveAll("diffs-tmp/")
			shared.LoadConfig() // nolint
			database, err := shared.DatabaseFactory()
			if err != nil {
				slog.Error("could not connect to database", "error", err)
				return
			}
			migrateDB(database)

			cveRepository := repositories.NewCVERepository(database)
			cweRepository := repositories.NewCWERepository(database)
			exploitsRepository := repositories.NewExploitRepository(database)
			affectedComponentsRepository := repositories.NewAffectedComponentRepository(database)
			configService := services.NewConfigService(database)
			v := vulndb.NewImportService(cveRepository, cweRepository, exploitsRepository, affectedComponentsRepository, configService)
			for _, arg := range args {
				slog.Info(arg)
			}

			// import the last vulndb version into some clean tables
			// we use the _diff suffix to identify those tables
			err = v.CreateTablesWithSuffix("_diff")
			if err != nil {
				slog.Error("error when trying to create tables with suffix", "err", err)
				return
			}
			err = v.ImportFromDiff(utils.Ptr("_diff"))
			if err != nil {
				slog.Error("error when trying to import with diff files", "err", err)
				return
			}
			err = vulndb.ExportDiffs("_diff")
			if err != nil {
				return
			}
		},
	}
	return &exportCmd
}
