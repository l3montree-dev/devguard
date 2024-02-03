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

	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/l3montree-dev/flawfix/internal/core/vulndb"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "flawfix",
	Short: "Vulnerability management for devs.",
	Long:  `Flawfix is a tool to manage vulnerabilities in your software.`,
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	rootCmd.AddCommand(&cobra.Command{
		Use:   "import",
		Short: "Import a CVE.",
		Long:  `Import a CVE from the NVD. This command will fetch the CVE from the NVD and store it in the local database. The ID of the CVE must be passed as an argument. The ID is in the format CVE-YYYY-NNNN.`,
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			// check if a single argument was passed
			if len(args) != 1 {
				cmd.Help() // nolint: errcheck
				os.Exit(1)
			}
			err := core.LoadConfig()
			if err != nil {
				slog.Error("could not initialize config", "err", err)
				os.Exit(1)
			}

			core.InitLogger()

			db, err := core.DatabaseFactory()
			if err != nil {
				slog.Error("could not connect to database", "err", err)
				os.Exit(1)
			}

			cveRepository := vulndb.NewGormRepository(db)

			nvdService := vulndb.NewNVDService(nil, nil, cveRepository)

			slog.Info("importing CVE", "cve", args[0])
			cve, err := nvdService.ImportCVE(args[0])
			if err != nil {
				slog.Error("could not import CVE", "err", err)
				os.Exit(1)
			}
			slog.Info("successfully imported CVE", "cve", cve.CVE)
		},
	})
}

func main() {
	Execute()
}
