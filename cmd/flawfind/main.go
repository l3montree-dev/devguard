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
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/l3montree-dev/flawfix/internal/database/models"
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

func generateSBOM() (*os.File, error) {
	// generate random name
	filename := uuid.New().String() + ".json"

	// run the sbom generator
	cmd := exec.Command("cdxgen", "-o", filename)

	err := cmd.Run()

	if err != nil {
		return nil, err
	}

	// open the file and return the path
	return os.Open(filename)
}

func init() {
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	rootCmd.PersistentFlags().String("assetName", "", "The id of the asset which is scanned")
	rootCmd.PersistentFlags().String("token", "", "The personal access token to authenticate the request")
	err := rootCmd.MarkPersistentFlagRequired("assetName")
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
		Use:   "sca",
		Short: "Software composition analysis",
		Long:  `Scan a SBOM for vulnerabilities. This command will scan a SBOM for vulnerabilities and return a list of vulnerabilities found in the SBOM. The SBOM must be passed as an argument.`,
		Args:  cobra.ExactArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			core.InitLogger()
			token, err := cmd.Flags().GetString("token")
			if err != nil {
				slog.Error("could not get token", "err", err)
				return
			}
			assetName, err := cmd.Flags().GetString("assetName")
			if err != nil {
				slog.Error("could not get asset id", "err", err)
				return
			}
			err = core.LoadConfig()
			if err != nil {
				slog.Error("could not initialize config", "err", err)
				return
			}

			// read the sbom file and post it to the scan endpoint
			// get the flaws and print them to the console
			file, err := generateSBOM()
			if err != nil {
				slog.Error("could not open file", "err", err)
				return
			}
			defer func() {
				// remove the file after the scan
				err := os.Remove(file.Name())
				if err != nil {
					slog.Error("could not remove file", "err", err)
				}

			}()

			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()

			req, err := http.NewRequestWithContext(ctx, "POST", "http://localhost:8080/api/v1/scan", file)
			if err != nil {
				slog.Error("could not create request", "err", err)
				return
			}
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("X-Asset-Name", assetName)

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				slog.Error("could not send request", "err", err)
				return
			}

			if resp.StatusCode != http.StatusOK {
				slog.Error("could not scan file", "status", resp.Status)
				return
			}

			// read and parse the body - it should be an array of flaws
			// print the flaws to the console
			flaws := []models.Flaw{}

			err = json.NewDecoder(resp.Body).Decode(&flaws)
			if err != nil {
				slog.Error("could not parse response", "err", err)
				return
			}

			for _, f := range flaws {
				slog.Info("flaw found", "cve", f.CVEID, "package", f.GetAdditionalData()["packageName"], "severity", f.CVE.Severity)
			}
		},
	})
}

func main() {
	Execute()
}
