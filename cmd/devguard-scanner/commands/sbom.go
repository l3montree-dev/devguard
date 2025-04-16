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

package commands

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/l3montree-dev/devguard/internal/core/pat"
	"github.com/l3montree-dev/devguard/internal/core/vulndb/scan"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func sbomCmd(cmd *cobra.Command, args []string) error {
	// parse the config
	token, assetName, apiUrl, failOnRisk, webUI := parseConfig(cmd)

	filePath := args[0]
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return fmt.Errorf("file does not exist: %s", filePath)
	}

	// read the file
	file, err := os.ReadFile(filePath)
	// check for errors
	if err != nil {
		slog.Error("could not read file", "err", err)
		return err
	}

	ctx, cancel := context.WithTimeout(cmd.Context(), 60*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", apiUrl+"/api/v1/scan", bytes.NewReader(file))

	if err != nil {
		return err
	}

	err = pat.SignRequest(token, req)
	if err != nil {
		return err
	}

	scannerId, err := cmd.Flags().GetString("scanner-id")
	if err != nil {
		slog.Error("could not get scanner id", "err", err)
		return err
	}

	ref, err := cmd.Flags().GetString("ref")
	if err != nil {
		slog.Error("could not get ref", "err", err)
		return err
	}
	defaultRef, err := cmd.Flags().GetString("default-ref")
	if err != nil || defaultRef == "" {
		defaultRef = ref
	}

	// set the headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Asset-Name", assetName)
	req.Header.Set("X-Scanner", scannerId)
	req.Header.Set("X-Asset-Ref", ref)
	req.Header.Set("X-Asset-Default-Branch", defaultRef)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// read the body
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return errors.Wrap(err, "could not scan file")
		}

		return fmt.Errorf("could not scan file: %s %s", resp.Status, string(body))
	}

	// read and parse the body - it should be an array of dependencyVulns
	// print the dependencyVulns to the console
	var scanResponse scan.ScanResponse

	err = json.NewDecoder(resp.Body).Decode(&scanResponse)
	if err != nil {
		return errors.Wrap(err, "could not parse response")
	}

	printScaResults(scanResponse, failOnRisk, assetName, webUI)
	return nil
}

func NewSbomCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sbom",
		Short: "Usage: <sbom.json>. Scan a software bill of materials. Only CycloneDX SBOMs are supported.",
		Long:  `Scan a software bill of materials. Only CycloneDX SBOMs are supported. This command will scan the SBOM for vulnerabilities and return the results.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			err := sbomCmd(cmd, args)
			if err != nil {
				slog.Error("sbom scanning failed", "err", err)
				return err
			}
			return nil
		},
	}

	cmd.Flags().String("scanner-id", "github.com/l3montree-dev/devguard-scanner/cmd/sbom", "Name of the scanner. DevGuard will compare new and old results based on the scanner-id.")

	cmd.Flags().String("ref", "main", "The git reference to use. This can be a branch, tag, or commit hash. If not specified, main will be used")
	cmd.Flags().String("default-ref", "main", "The default git reference to use. This can be a branch, tag, or commit hash. If not specified, --ref will be used.")

	addScanFlags(cmd)
	return cmd
}
