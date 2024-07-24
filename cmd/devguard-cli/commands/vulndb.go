package commands

import (
	"log/slog"
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

	vulndbCmd.AddCommand(newRepairCommand())
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

func newRepairCommand() *cobra.Command {
	repairCmd := cobra.Command{
		Use:   "repair",
		Short: "Will repair the vulnerability database",
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

			databasesToRepair, _ := cmd.Flags().GetStringArray("databases")

			cveRepository := repositories.NewCVERepository(database)
			cweRepository := repositories.NewCWERepository(database)
			affectedCmpRepository := repositories.NewAffectedCmpRepository(database)
			nvdService := vulndb.NewNVDService(cveRepository)
			mitreService := vulndb.NewMitreService(cweRepository)
			epssService := vulndb.NewEPSSService(nvdService, cveRepository)
			osvService := vulndb.NewOSVService(affectedCmpRepository)
			cvelistService := vulndb.NewCVEListService(cveRepository)
			expoitDBService := vulndb.NewExploitDBService(nvdService, repositories.NewExploitRepository(database))

			githubExploitDBService := vulndb.NewGithubExploitDBService(repositories.NewExploitRepository(database))

			if emptyOrContains(databasesToRepair, "cwe") {
				now := time.Now()
				slog.Info("starting cwe database repair")
				if err := mitreService.Mirror(); err != nil {
					slog.Error("could not mirror cwe database", "err", err)
					return
				}
				slog.Info("finished cwe database repair", "duration", time.Since(now))
			}

			if emptyOrContains(databasesToRepair, "cvelist") {
				slog.Info("starting cvelist database repair")
				now := time.Now()

				if err := cvelistService.Mirror(); err != nil {
					slog.Error("could not mirror cvelist database", "err", err)
					return
				}
				slog.Info("finished cvelist database repair", "duration", time.Since(now))
			}

			if emptyOrContains(databasesToRepair, "nvd") {
				slog.Info("starting nvd database repair")
				now := time.Now()
				if after != "" {
					// we do a partial repair
					// try to parse the date
					afterDate, err := time.Parse("2006-01-02", after)
					if err != nil {
						slog.Error("could not parse after date", "err", err, "provided", after, "expectedFormat", "2006-01-02")
						return
					}
					err = nvdService.FetchAfter(afterDate)
					if err != nil {
						slog.Error("could not fetch after date", "err", err)
						return
					}
				} else {
					if startIndex != 0 {
						err = nvdService.FetchAfterIndex(startIndex)
						if err != nil {
							slog.Error("could not fetch after index", "err", err)
							return
						}
					} else {
						// just redo the intitial sync
						err = nvdService.InitialPopulation()
						if err != nil {
							slog.Error("could not do initial sync", "err", err)
							return
						}
					}
				}
				slog.Info("finished nvd database repair", "duration", time.Since(now))
			}

			if emptyOrContains(databasesToRepair, "epss") {
				slog.Info("starting epss database repair")
				now := time.Now()

				if err := epssService.Mirror(); err != nil {
					slog.Error("could not repair epss database", "err", err)
					return
				}
				slog.Info("finished epss database repair", "duration", time.Since(now))
			}

			if emptyOrContains(databasesToRepair, "osv") {
				slog.Info("starting osv database repair")
				now := time.Now()
				if err := osvService.Mirror(); err != nil {
					slog.Error("could not repair osv database", "err", err)
					return
				}
				slog.Info("finished osv database repair", "duration", time.Since(now))
			}

			if emptyOrContains(databasesToRepair, "exploitdb") {
				slog.Info("starting exploitdb database repair")
				now := time.Now()
				if err := expoitDBService.Mirror(); err != nil {
					slog.Error("could not repair exploitdb database", "err", err)
					return
				}
				slog.Info("finished exploitdb database repair", "duration", time.Since(now))
			}

			if emptyOrContains(databasesToRepair, "github-poc") {
				slog.Info("starting github-poc database repair")
				now := time.Now()
				if err := githubExploitDBService.Mirror(); err != nil {
					slog.Error("could not repair github-poc database", "err", err)
					return
				}
				slog.Info("finished github-poc database repair", "duration", time.Since(now))
			}
		},
	}
	repairCmd.Flags().String("after", "", "allows to only repair a subset of data. This is used to identify the 'last correct' date in the nvd database. The sync will only include cve modifications in the interval [after, now]. Format: 2006-01-02")
	repairCmd.Flags().Int("startIndex", 0, "provide a start index to fetch the data from. This is useful after an initial sync failed")
	repairCmd.Flags().StringArray("databases", []string{}, "provide a list of databases to repair. Possible values are: nvd, cvelist, exploitdb, github-poc, cwe, epss, osv")

	return &repairCmd
}
