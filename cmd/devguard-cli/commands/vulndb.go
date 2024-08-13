package commands

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/vulndb"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
	"github.com/spf13/cobra"
	"oras.land/oras-go/v2/content/file"

	oras "oras.land/oras-go/v2"
	"oras.land/oras-go/v2/registry/remote"
)

func NewVulndbCommand() *cobra.Command {
	vulndbCmd := cobra.Command{
		Use:   "vulndb",
		Short: "Vulnerability Database",
	}

	vulndbCmd.AddCommand(newRepairCommand())
	vulndbCmd.AddCommand(newImportCVECommand())
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
		Use:   "importcve",
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
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {

			// 0. Create a file store
			fs, err := file.New("/tmp/")
			if err != nil {
				panic(err)
			}
			defer fs.Close()

			// 1. Connect to a remote repository
			ctx := context.Background()
			reg := "ghcr.io/l3montree-dev/devguard"
			repo, err := remote.NewRepository(reg + "/vulndb")
			if err != nil {
				fmt.Println("could not connect to remote repository")
				panic(err)
			}

			// 2. Copy from the remote repository to the file store
			tag := args[0]
			manifestDescriptor, err := oras.Copy(ctx, repo, tag, fs, tag, oras.DefaultCopyOptions)
			if err != nil {
				panic(err)
			}
			fmt.Println("manifest descriptor:", manifestDescriptor)
			fmt.Println("File store:", fs)

			reader, err := fs.Fetch(ctx, manifestDescriptor)
			if err != nil {
				panic(err)
			}

			data, err := io.ReadAll(reader)
			if err != nil {
				panic(err)
			}

			fmt.Println(string(data))

		},
	}
	return importCmd
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
			fmt.Println(after, startIndex)

			core.LoadConfig() // nolint

			database, err := core.DatabaseFactory()
			if err != nil {
				slog.Error("could not connect to database", "err", err)
				return
			}

			databasesToRepair, _ := cmd.Flags().GetStringArray("databases")

			cveRepository := repositories.NewCVERepository(database)
			cweRepository := repositories.NewCWERepository(database)
			affectedCmpRepository := repositories.NewAffectedComponentRepository(database)
			nvdService := vulndb.NewNVDService(cveRepository)
			mitreService := vulndb.NewMitreService(cweRepository)
			epssService := vulndb.NewEPSSService(nvdService, cveRepository)
			osvService := vulndb.NewOSVService(affectedCmpRepository)
			cvelistService := vulndb.NewCVEListService(cveRepository)
			debianSecurityTracker := vulndb.NewDebianSecurityTracker(affectedCmpRepository)

			expoitDBService := vulndb.NewExploitDBService(nvdService, repositories.NewExploitRepository(database))

			githubExploitDBService := vulndb.NewGithubExploitDBService(repositories.NewExploitRepository(database))

			if emptyOrContains(databasesToRepair, "cwe") {
				now := time.Now()
				slog.Info("starting cwe database repair")
				if err := mitreService.Mirror(); err != nil {
					slog.Error("could not mirror cwe database", "err", err)
				}
				slog.Info("finished cwe database repair", "duration", time.Since(now))
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
						// just redo the intitial sync
						err = nvdService.InitialPopulation()
						if err != nil {
							slog.Error("could not do initial sync", "err", err)
						}
					}
				}
				slog.Info("finished nvd database repair", "duration", time.Since(now))
			}

			if emptyOrContains(databasesToRepair, "cvelist") {
				slog.Info("starting cvelist database repair")
				now := time.Now()

				if err := cvelistService.Mirror(); err != nil {
					slog.Error("could not mirror cvelist database", "err", err)
				}
				slog.Info("finished cvelist database repair", "duration", time.Since(now))
			}

			if emptyOrContains(databasesToRepair, "epss") {
				slog.Info("starting epss database repair")
				now := time.Now()

				if err := epssService.Mirror(); err != nil {
					slog.Error("could not repair epss database", "err", err)
				}
				slog.Info("finished epss database repair", "duration", time.Since(now))
			}

			if emptyOrContains(databasesToRepair, "osv") {
				slog.Info("starting osv database repair")
				now := time.Now()
				if err := osvService.Mirror(); err != nil {
					slog.Error("could not repair osv database", "err", err)
				}
				slog.Info("finished osv database repair", "duration", time.Since(now))
			}

			if emptyOrContains(databasesToRepair, "exploitdb") {
				slog.Info("starting exploitdb database repair")
				now := time.Now()
				if err := expoitDBService.Mirror(); err != nil {
					slog.Error("could not repair exploitdb database", "err", err)
				}
				slog.Info("finished exploitdb database repair", "duration", time.Since(now))
			}

			if emptyOrContains(databasesToRepair, "github-poc") {
				slog.Info("starting github-poc database repair")
				now := time.Now()
				if err := githubExploitDBService.Mirror(); err != nil {
					slog.Error("could not repair github-poc database", "err", err)
				}
				slog.Info("finished github-poc database repair", "duration", time.Since(now))
			}

			if emptyOrContains(databasesToRepair, "dsa") {
				slog.Info("starting dsa database repair")
				now := time.Now()
				if err := debianSecurityTracker.Mirror(); err != nil {
					slog.Error("could not repair dsa database", "err", err)
				}
				slog.Info("finished dsa database repair", "duration", time.Since(now))
			}

		},
	}
	repairCmd.Flags().String("after", "", "allows to only repair a subset of data. This is used to identify the 'last correct' date in the nvd database. The sync will only include cve modifications in the interval [after, now]. Format: 2006-01-02")
	repairCmd.Flags().Int("startIndex", 0, "provide a start index to fetch the data from. This is useful after an initial sync failed")
	repairCmd.Flags().StringArray("databases", []string{}, "provide a list of databases to repair. Possible values are: nvd, cvelist, exploitdb, github-poc, cwe, epss, osv, dsa")

	return &repairCmd
}
