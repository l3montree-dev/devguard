package commands

import (
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/vulndb"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
	"github.com/spf13/cobra"
)

func NewVulndbCommand() *cobra.Command {
	vulndbCmd := cobra.Command{
		Use:   "vulndb",
		Short: "Vulnerability Database",
	}

	vulndbCmd.AddCommand(newImportCVECommand())
	vulndbCmd.AddCommand(newSyncCommand())
	vulndbCmd.AddCommand(newImportCommand())
	return &vulndbCmd
}

func emptyOrContains(s []string, e string) bool {
	if len(s) == 0 {
		return true
	}
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func isValidCVE(cveId string) bool {
	// should either be just 2023-1234 or cve-2023-1234
	if len(cveId) == 0 {
		return false
	}

	r := regexp.MustCompile(`^CVE-\d{4}-\d{4,7}$`)
	if r.MatchString(cveId) {
		return true
	}

	r = regexp.MustCompile(`^\d{4}-\d{4,7}$`)
	return r.MatchString(cveId)
}

func newImportCVECommand() *cobra.Command {
	importCmd := &cobra.Command{
		Use:   "import-cve",
		Short: "Will import the vulnerability database",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			core.LoadConfig() // nolint
			database, err := core.DatabaseFactory()
			if err != nil {
				slog.Error("could not connect to database", "err", err)
				return
			}

			cveId := args[0]
			cveId = strings.TrimSpace(strings.ToUpper(cveId))
			// check if first argument is valid cve
			if !isValidCVE(cveId) {
				slog.Error("invalid cve id", "cve", cveId)
				return
			}

			cveRepository := repositories.NewCVERepository(database)
			nvdService := vulndb.NewNVDService(cveRepository)
			osvService := vulndb.NewOSVService(repositories.NewAffectedComponentRepository(database))

			cve, err := nvdService.ImportCVE(cveId)

			if err != nil {
				slog.Error("could not import cve", "err", err)
				return
			}
			slog.Info("successfully imported cve", "cveId", cve.CVE)

			// the cvelist does provide additional cpe matches.
			cvelistService := vulndb.NewCVEListService(cveRepository)
			cpeMatches, err := cvelistService.ImportCVE(cveId)
			if err != nil {
				slog.Error("could not import cve from cvelist", "err", err)
				return
			}

			slog.Info("successfully imported cpe matches", "cveId", cve.CVE, "cpeMatches", len(cpeMatches))

			// the osv database provides additional information about affected packages
			affectedPackages, err := osvService.ImportCVE(cveId)
			if err != nil {
				slog.Error("could not import cve from osv", "err", err)
				return
			}

			slog.Info("successfully imported affected packages", "cveId", cve.CVE, "affectedPackages", len(affectedPackages))
		},
	}

	return importCmd
}

func newImportCommand() *cobra.Command {
	importCmd := &cobra.Command{
		Use:   "import",
		Short: "Will import the vulnerability database",
		Args:  cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			core.LoadConfig() // nolint

			database, err := core.DatabaseFactory()
			if err != nil {
				slog.Error("could not connect to database", "err", err)
				return
			}

			cveRepository := repositories.NewCVERepository(database)
			cweRepository := repositories.NewCWERepository(database)
			exploitsRepository := repositories.NewExploitRepository(database)
			affectedComponentsRepository := repositories.NewAffectedComponentRepository(database)

			tag := "latest"
			if len(args) > 0 {
				tag = args[0]
			}
			v := vulndb.NewImportService(cveRepository, cweRepository, exploitsRepository, affectedComponentsRepository)
			err = v.Import(database, tag)
			if err != nil {
				slog.Error("could not import vulndb", "err", err)
				return
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

			database, err := core.DatabaseFactory()
			if err != nil {
				slog.Error("could not connect to database", "err", err)
				return
			}

			databasesToSync, _ := cmd.Flags().GetStringArray("databases")

			cveRepository := repositories.NewCVERepository(database)
			cweRepository := repositories.NewCWERepository(database)
			affectedCmpRepository := repositories.NewAffectedComponentRepository(database)
			nvdService := vulndb.NewNVDService(cveRepository)
			mitreService := vulndb.NewMitreService(cweRepository)
			epssService := vulndb.NewEPSSService(nvdService, cveRepository)
			osvService := vulndb.NewOSVService(affectedCmpRepository)
			// cvelistService := vulndb.NewCVEListService(cveRepository)
			debianSecurityTracker := vulndb.NewDebianSecurityTracker(affectedCmpRepository)

			expoitDBService := vulndb.NewExploitDBService(nvdService, repositories.NewExploitRepository(database))

			githubExploitDBService := vulndb.NewGithubExploitDBService(repositories.NewExploitRepository(database))

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
