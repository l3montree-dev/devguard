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
	"github.com/l3montree-dev/flawfix/internal/core/flaw"
	"github.com/l3montree-dev/flawfix/internal/core/vulndb/scan"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "flawfix",
	Short: "Vulnerability management for devs.",
	Long:  `Flawfix is a tool to manage vulnerabilities and other flaws in your software.`,
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	rootCmd.PersistentFlags().String("assetId", "", "The id of the asset which is scanned")
	rootCmd.PersistentFlags().String("token", "", "The personal access token to authenticate the request")
	err := rootCmd.MarkPersistentFlagRequired("assetId")
	if err != nil {
		slog.Error("could not mark flag as required", "err", err)
		os.Exit(1)
	}
	err = rootCmd.MarkPersistentFlagRequired("token")
	if err != nil {
		slog.Error("could not mark flag as required", "err", err)
		os.Exit(1)
	}

	rootCmd.AddCommand(&cobra.Command{
		Use:   "sca [path to SBOM file]",
		Short: "Software composition analysis",
		Long:  `Scan a SBOM for vulnerabilities. This command will scan a SBOM for vulnerabilities and return a list of vulnerabilities found in the SBOM. The SBOM must be passed as an argument.`,
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

			cpeComparer := scan.NewCPEComparer(db)
			purlComparer := scan.NewPurlComparer(db)

			scanner := scan.NewSBOMScanner(cpeComparer, purlComparer)

			f, err := os.Open(args[0])
			if err != nil {
				slog.Error("could not open file", "err", err)
				os.Exit(1)
			}
			defer f.Close()
			vulns, err := scanner.Scan(f)
			if err != nil {
				slog.Error("could not scan file", "err", err)
				os.Exit(1)
			}

			// create flaws out of those vulnerabilities
			flaws := []flaw.Model{}
			for _, vuln := range vulns {
				flaw := flaw.Model{
					CVEID:     vuln.CVEID,
					ScannerID: "github.com/l3montree-dev/flawfix/cmd/sbom-scanner",
				}
				flaw.SetAdditionalData(map[string]any{
					"introducedVersion": vuln.GetIntroducedVersion(),
					"fixedVersion":      vuln.GetFixedVersion(),
					"packageName":       vuln.PackageName,
				})
				flaws = append(flaws, flaw)
			}
			// save the flaws in the database.
		},
	})
}

func main() {
	Execute()
}
