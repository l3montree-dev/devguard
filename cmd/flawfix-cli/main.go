// Copyright (C) 2024 Tim Bastin, l3montree UG (haftungsbeschränkt)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

// Copyright (C) 2024 Tim Bastin, l3montree UG (haftungsbeschränkt)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"log/slog"
	"os"
	"time"

	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/l3montree-dev/flawfix/internal/core/vulndb"
	"github.com/l3montree-dev/flawfix/internal/database/repositories"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "flawfix-cli",
	Short: "Management cli",
	Long:  `The flawfix cli can be used to interact with a running flawfix instance.`,
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	vulndbCmd := cobra.Command{
		Use:   "vulndb",
		Short: "Vulnerability Database",
	}
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

			cveRepository := repositories.NewCVERepository(database)
			cweRepository := repositories.NewCWERepository(database)
			affectedCmpRepository := repositories.NewAffectedCmpRepository(database)
			nvdService := vulndb.NewNVDService(cveRepository)
			mitreService := vulndb.NewMitreService(cweRepository)
			epssService := vulndb.NewEPSSService(nvdService, cveRepository)
			osvService := vulndb.NewOSVService(affectedCmpRepository)

			now := time.Now()
			slog.Info("starting cwe database repair")
			if err := mitreService.Mirror(); err != nil {
				slog.Error("could not mirror cwe database", "err", err)
				return
			}
			slog.Info("finished cwe database repair", "duration", time.Since(now))

			slog.Info("starting cve database repair")
			now = time.Now()
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
			slog.Info("finished cve database repair", "duration", time.Since(now))
			slog.Info("starting epss database repair")
			now = time.Now()

			if err := epssService.Mirror(); err != nil {
				slog.Error("could not repair epss database", "err", err)
				return
			}
			slog.Info("finished epss database repair", "duration", time.Since(now))
			slog.Info("starting osv database repair")
			now = time.Now()
			if err := osvService.Mirror(); err != nil {
				slog.Error("could not repair osv database", "err", err)
				return
			}
			slog.Info("finished osv database repair", "duration", time.Since(now))
		},
	}
	repairCmd.Flags().String("after", "", "allows to only repair a subset of data. This is used to identify the 'last correct' date in the nvd database. The sync will only include cve modifications in the interval [after, now]. Format: 2006-01-02")
	repairCmd.Flags().Int("startIndex", 0, "provide a start index to fetch the data from. This is useful after an initial sync failed")

	vulndbCmd.AddCommand(&repairCmd)
	rootCmd.AddCommand(&vulndbCmd)
}

func main() {
	core.InitLogger()
	Execute()
}
