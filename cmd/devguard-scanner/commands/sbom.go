// Copyright (C) 2024 Tim Bastin, l3montree GmbH
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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/l3montree-dev/devguard/cmd/devguard-scanner/config"
	"github.com/l3montree-dev/devguard/cmd/devguard-scanner/scanner"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func sbomCmd(cmd *cobra.Command, args []string) error {
	filePath := args[0]
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return fmt.Errorf("file does not exist: %s", filePath)
	}

	// read the file
	file, err := os.Open(filePath)
	// check for errors
	if err != nil {
		slog.Error("could not read file", "err", err)
		return err
	}

	// upload the bom to the scan endpoint
	resp, cancel, err := scanner.UploadBOM(file)
	defer cancel()

	if err != nil {
		// check for timeout
		if errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "context deadline exceeded") {
			slog.Error("request timed out after configured or default timeout - as scan commands and upload can take a while consider increasing using the --timeout flag", "timeout", time.Duration(config.RuntimeBaseConfig.Timeout)*time.Second)
		}
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
	var scanResponse dtos.ScanResponse

	err = json.NewDecoder(resp.Body).Decode(&scanResponse)
	if err != nil {
		return errors.Wrap(err, "could not parse response")
	}
	return scanner.PrintScaResults(scanResponse, config.RuntimeBaseConfig.FailOnRisk, config.RuntimeBaseConfig.FailOnCVSS, config.RuntimeBaseConfig.AssetName, config.RuntimeBaseConfig.WebUI)
}

func NewSbomCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "sbom <sbom.json>",
		Short:             "Scan a CycloneDX SBOM for vulnerabilities",
		DisableAutoGenTag: true,
		Long: `Scan a CycloneDX Software Bill of Materials (SBOM) and upload it to DevGuard for vulnerability analysis.

Only CycloneDX-formatted SBOMs are supported. The command signs the request using the configured token and returns scan results.`,
		Example: `  # Scan a CycloneDX SBOM
  devguard-scanner sbom my-bom.json

  # Scan with custom asset name
  devguard-scanner sbom my-bom.json --assetName my-app

  # Fail on high risk vulnerabilities
  devguard-scanner sbom my-bom.json --failOnRisk high`,
		Args: cobra.ExactArgs(1),
		RunE: sbomCmd,
	}

	scanner.AddDependencyVulnsScanFlags(cmd)
	return cmd
}
