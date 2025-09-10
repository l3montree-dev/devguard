package commands

import (
	"errors"
	"log/slog"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/config"
	"github.com/l3montree-dev/devguard/internal/core/vulndb"
	"github.com/l3montree-dev/devguard/internal/database"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
	"github.com/spf13/cobra"
)

var primaryKeysFromTables = map[string][]string{"cves": {"cve"}, "cwes": {"cwe"}, "affected_components": {"id"}, "cve_affected_component": {"affected_component_id", "cvecve"}, "exploits": {"id"}}

func NewVulndbCommand() *cobra.Command {
	vulndbCmd := cobra.Command{
		Use:   "vulndb",
		Short: "Vulnerability Database",
	}

	vulndbCmd.AddCommand(newImportCVECommand())
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

func migrateDB(db core.DB) {
	// Run database migrations using the existing database connection
	disableAutoMigrate := os.Getenv("DISABLE_AUTOMIGRATE")
	if disableAutoMigrate != "true" {
		slog.Info("running database migrations...")
		if err := database.RunMigrationsWithDB(db); err != nil {
			slog.Error("failed to run database migrations", "error", err)
			panic(errors.New("Failed to run database migrations"))
		}

		// Run hash migrations if needed (when algorithm version changes)
		if err := models.RunHashMigrationsIfNeeded(db); err != nil {
			slog.Error("failed to run hash migrations", "error", err)
			panic(errors.New("Failed to run hash migrations"))
		}
	} else {
		slog.Info("automatic migrations disabled via DISABLE_AUTOMIGRATE=true")
	}
}

func newImportCVECommand() *cobra.Command {
	importCmd := &cobra.Command{
		Use:   "import-cve",
		Short: "Will import the vulnerability database",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			core.LoadConfig() // nolint
			db, err := core.DatabaseFactory()
			if err != nil {
				slog.Error("could not connect to database", "err", err)
				return
			}

			migrateDB(db)

			cveID := args[0]
			cveID = strings.TrimSpace(strings.ToUpper(cveID))
			// check if first argument is valid cve
			if !isValidCVE(cveID) {
				slog.Error("invalid cve id", "cve", cveID)
				return
			}

			cveRepository := repositories.NewCVERepository(db)
			nvdService := vulndb.NewNVDService(cveRepository)
			osvService := vulndb.NewOSVService(repositories.NewAffectedComponentRepository(db))

			cve, err := nvdService.ImportCVE(cveID)

			if err != nil {
				slog.Error("could not import cve", "err", err)
				return
			}

			// the osv database provides additional information about affected packages
			affectedPackages, err := osvService.ImportCVE(cveID)
			if err != nil {
				slog.Error("could not import cve from osv", "err", err)
				return
			}

			slog.Info("successfully imported affected packages", "cveID", cve.CVE, "affectedPackages", len(affectedPackages))
		},
	}

	return importCmd
}

func newImportCommand() *cobra.Command {
	importCmd := &cobra.Command{
		Use:   "import",
		Short: "Will import the vulnerability database",
		Args:  cobra.MaximumNArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			core.LoadConfig() // nolint
			database, err := core.DatabaseFactory()
			if err != nil {
				slog.Error("could not connect to database", "error", err)
				return
			}
			migrateDB(database)

			cveRepository := repositories.NewCVERepository(database)
			cweRepository := repositories.NewCWERepository(database)
			exploitsRepository := repositories.NewExploitRepository(database)
			affectedComponentsRepository := repositories.NewAffectedComponentRepository(database)
			configService := config.NewService(database)
			v := vulndb.NewImportService(cveRepository, cweRepository, exploitsRepository, affectedComponentsRepository, configService)

			var mode string // determines how we import
			if len(args) > 0 {
				mode = args[0]
			}
			// import incremental updates using the difference between two databases states
			if mode == "inc" {
				err := v.ImportFromDiff()
				if err != nil {
					slog.Error("error when trying to import with diff files", "err", err)
					return
				}
			} else { // import the full table
				if mode == "diff" { // additionally create a diff table to be used by the export command
					os.Setenv("MAKE_DIFF_TABLES", "true")
				}

				tag := "latest"
				if len(args) == 1 {
					tag = args[0]
				} else {
					tag = args[1]
				}

				err = v.Import(database, tag)
				if err != nil {
					slog.Error("could not import vulndb", "err", err)
					return
				}
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
			// check if after flag is set
			after, _ := cmd.Flags().GetString("after")
			startIndex, _ := cmd.Flags().GetInt("startIndex")

			core.LoadConfig() // nolint

			db, err := core.DatabaseFactory()
			if err != nil {
				slog.Error("could not connect to database", "err", err)
				return
			}

			migrateDB(db)

			databasesToSync, _ := cmd.Flags().GetStringArray("databases")

			cveRepository := repositories.NewCVERepository(db)
			cweRepository := repositories.NewCWERepository(db)
			affectedCmpRepository := repositories.NewAffectedComponentRepository(db)
			nvdService := vulndb.NewNVDService(cveRepository)
			mitreService := vulndb.NewMitreService(cweRepository)
			epssService := vulndb.NewEPSSService(nvdService, cveRepository)
			osvService := vulndb.NewOSVService(affectedCmpRepository)
			// cvelistService := vulndb.NewCVEListService(cveRepository)
			debianSecurityTracker := vulndb.NewDebianSecurityTracker(affectedCmpRepository)

			expoitDBService := vulndb.NewExploitDBService(nvdService, repositories.NewExploitRepository(db))

			githubExploitDBService := vulndb.NewGithubExploitDBService(repositories.NewExploitRepository(db))

			if emptyOrContains(databasesToSync, "cwe") {
				now := time.Now()
				slog.Info("starting cwe database sync")
				if err := mitreService.Mirror(); err != nil {
					slog.Error("could not mirror cwe database", "err", err)
				}
				slog.Info("finished cwe database sync", "duration", time.Since(now))
			}

			if emptyOrContains(databasesToSync, "nvd") {
				slog.Info("starting nvd database sync")
				now := time.Now()
				if after != "" {
					// we do a partial sync
					// try to parse the date
					afterDate, err := time.Parse("2006-01-02", after)
					if err != nil {
						slog.Error("could not parse after date", "err", err, "provided", after, "expectedFormat", "2006-01-02")
					}
					err = nvdService.FetchAfter(afterDate)
					if err != nil {
						slog.Error("could not fetch after date", "err", err)
					}
				} else {
					if startIndex != 0 {
						err = nvdService.FetchAfterIndex(startIndex)
						if err != nil {
							slog.Error("could not fetch after index", "err", err)
						}
					} else {
						err = nvdService.Sync()
						if err != nil {
							slog.Error("could not do initial sync", "err", err)
						}
					}
				}
				slog.Info("finished nvd database sync", "duration", time.Since(now))
			}

			/*if emptyOrContains(databasesToSync, "cvelist") {
				slog.Info("starting cvelist database sync")
				now := time.Now()

				if err := cvelistService.Mirror(); err != nil {
					slog.Error("could not mirror cvelist database", "err", err)
				}
				slog.Info("finished cvelist database sync", "duration", time.Since(now))
			}*/

			if emptyOrContains(databasesToSync, "epss") {
				slog.Info("starting epss database sync")
				now := time.Now()

				if err := epssService.Mirror(); err != nil {
					slog.Error("could not sync epss database", "err", err)
				}
				slog.Info("finished epss database sync", "duration", time.Since(now))
			}

			if emptyOrContains(databasesToSync, "osv") {
				slog.Info("starting osv database sync")
				now := time.Now()
				if err := osvService.Mirror(); err != nil {
					slog.Error("could not sync osv database", "err", err)
				}
				slog.Info("finished osv database sync", "duration", time.Since(now))
			}

			if emptyOrContains(databasesToSync, "exploitdb") {
				slog.Info("starting exploitdb database sync")
				now := time.Now()
				if err := expoitDBService.Mirror(); err != nil {
					slog.Error("could not sync exploitdb database", "err", err)
				}
				slog.Info("finished exploitdb database sync", "duration", time.Since(now))
			}

			if emptyOrContains(databasesToSync, "github-poc") {
				slog.Info("starting github-poc database sync")
				now := time.Now()
				if err := githubExploitDBService.Mirror(); err != nil {
					slog.Error("could not sync github-poc database", "err", err)
				}
				slog.Info("finished github-poc database sync", "duration", time.Since(now))
			}

			if emptyOrContains(databasesToSync, "dsa") {
				slog.Info("starting dsa database sync")
				now := time.Now()
				if err := debianSecurityTracker.Mirror(); err != nil {
					slog.Error("could not sync dsa database", "err", err)
				}
				slog.Info("finished dsa database sync", "duration", time.Since(now))
			}
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
			core.LoadConfig() // nolint
			os.RemoveAll("diffs-tmp/")
			err := vulndb.Export()
			if err != nil {
				return
			}
		},
	}
	return &exportCmd
}
