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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/l3montree-dev/devguard/cmd/devguard-scanner/config"
	"github.com/l3montree-dev/devguard/cmd/devguard-scanner/scanner"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/dtos/sarif"

	"github.com/l3montree-dev/devguard/services"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func sarifCmd(cmd *cobra.Command, args []string) error {
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

	if config.RuntimeBaseConfig.OutputPath != "" {
		err = os.WriteFile(config.RuntimeBaseConfig.OutputPath, file, 0644)
		if err != nil {
			return errors.Wrap(err, "could not write sarif file to output path")
		}
		slog.Info("SARIF report saved", "path", config.RuntimeBaseConfig.OutputPath)
	}

	timeout := time.Duration(config.RuntimeBaseConfig.Timeout) * time.Second
	ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/api/v1/sarif-scan", config.RuntimeBaseConfig.APIURL), bytes.NewReader(file))

	if err != nil {
		return err
	}

	err = services.SignRequest(config.RuntimeBaseConfig.Token, req)
	if err != nil {
		return err
	}

	// set the headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Scanner", config.RuntimeBaseConfig.ScannerID)
	config.SetXAssetHeaders(req)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		// check for timeout
		if errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "context deadline exceeded") {
			slog.Error("request timed out after configured or default timeout - as scan commands and upload can take a while consider increasing using the --timeout flag", "timeout", timeout)
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
	var scanResponse dtos.FirstPartyScanResponse

	err = json.NewDecoder(resp.Body).Decode(&scanResponse)
	if err != nil {
		return errors.Wrap(err, "could not parse response")
	}

	return scanner.PrintFirstPartyScanResults(scanResponse, config.RuntimeBaseConfig.AssetName, config.RuntimeBaseConfig.WebUI, config.RuntimeBaseConfig.Ref, config.RuntimeBaseConfig.ScannerID)
}

func NewSarifCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "sarif <sarif.json>",
		Short:             "Scan a SARIF report and upload results to DevGuard",
		DisableAutoGenTag: true,
		Long: `Upload a SARIF-formatted static analysis report to DevGuard for processing and result comparison.

The command signs the request using the configured token and returns scan results.`,
		Example: `  # Upload a SARIF report
  devguard-scanner sarif results.sarif.json

  # Upload and save the processed report
  devguard-scanner sarif results.sarif.json --outputPath uploaded-results.sarif.json

  # Upload with custom scanner ID for result tracking
  devguard-scanner sarif results.sarif.json --scannerID custom-scanner-v1`,
		Args: cobra.ExactArgs(1),
		RunE: sarifCmd,
	}

	cmd.Flags().String("scannerID", "github.com/l3montree-dev/devguard/cmd/devguard-scanner/sarif", "Name of the scanner. DevGuard will compare new and old results based on the scannerID.")

	scanner.AddFirstPartyVulnsScanFlags(cmd)
	return cmd
}

func expandAndObfuscateSnippet(sarifScan *sarif.SarifSchema210Json, path string) {

	// expand the snippet
	for ru, run := range sarifScan.Runs {
		for re, result := range run.Results {
			for lo, location := range result.Locations {
				startLine := location.PhysicalLocation.Region.StartLine
				endLine := location.PhysicalLocation.Region.EndLine
				original := location.PhysicalLocation.Region.Snippet.Text

				var fileContent []byte
				var err error
				// read the file from git - if there is a partial fingerprint which looks like a commit sha
				// this is a bit of a hack, but we need to read the file from git to expand the snippet
				if sarifScan.Runs[ru].Results[re].PartialFingerprints != nil && len(sarifScan.Runs[ru].Results[re].PartialFingerprints["commitSha"]) > 0 {
					fileContent, err = utils.ReadFileFromGitRef(path, sarifScan.Runs[ru].Results[re].PartialFingerprints["commitSha"], utils.OrDefault(location.PhysicalLocation.ArtifactLocation.URI, ""))
					if err != nil {
						slog.Error("could not read file", "err", err)
						continue
					}
				} else {
					// read the file from the filesystem
					fileContent, err = os.ReadFile(utils.OrDefault(location.PhysicalLocation.ArtifactLocation.URI, ""))
					if err != nil {
						slog.Error("could not read file", "err", err)
						continue
					}
				}
				// expand the snippet
				expandedSnippet, err := expandSnippet(fileContent, utils.OrDefault(startLine, 0), utils.OrDefault(endLine, 0), utils.OrDefault(original, ""))
				if err != nil {
					continue
				}

				// obfuscate the snippet
				obfuscateSnippet := scanner.ObfuscateString(expandedSnippet)

				// set the snippet
				sarifScan.Runs[ru].Results[re].Locations[lo].PhysicalLocation.Region.Snippet.Text = &obfuscateSnippet

			}
		}
	}

}

func expandSnippet(fileContent []byte, startLine, endLine int, original string) (string, error) {
	startLine--
	endLine--

	lines := strings.Split(string(fileContent), "\n")

	if startLine < 0 || endLine > len(lines) {
		return original, fmt.Errorf("start line or end line is out of range")
	}

	if startLine > endLine {
		return original, fmt.Errorf("start line after end line")
	}

	//original is the string with the secret, but without the beginning of the line, so we reconstruct it
	// slice the original string where *** are
	secretStringBegin := strings.Split(original, "***")

	//find the first occurrence of the secret in the line
	startColumn := strings.Index(lines[startLine], secretStringBegin[0])
	secretLineBegin := ""
	if startColumn != -1 {
		secretLineBegin = lines[startLine][:startColumn]
	}

	expandedSnippet := ""

	startLineN := int(math.Max(0, float64(startLine)-5))
	endLineN := int(math.Min(float64(len(lines)), float64(endLine)+6))
	// keep the endLine in bounds, even if tools do report an endline which does not even exist (files has 63 lines, tools report endline is 64)
	endLine = int(math.Min(float64(endLine)+1, float64(len(lines))))

	// replace start and endline to make sure any previous tranformations will be applied#
	start := lines[startLineN:startLine]
	end := lines[endLine:endLineN]

	startStr := ""
	endStr := ""
	if len(start) > 0 {
		startStr = strings.Join(start, "\n")
		expandedSnippet = startStr + "\n"
	}

	marker := "+++"
	expandedSnippet += marker + "\n" + secretLineBegin + original + "\n" + marker

	if len(end) > 0 {
		endStr = strings.Join(end, "\n")
		expandedSnippet += "\n" + endStr
	}

	return expandedSnippet, nil
}

func sarifCommandFactory(scannerID string) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		sarifResult, err := executeCodeScan(scannerID, config.RuntimeBaseConfig.Path, config.RuntimeBaseConfig.OutputPath)
		if err != nil {
			return errors.Wrap(err, "could not open file")
		}
		slog.Info("Completed code scan", "scannerID", scannerID)

		timeout := time.Duration(config.RuntimeBaseConfig.Timeout) * time.Second
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		// expand snippet and obfuscate it
		expandAndObfuscateSnippet(sarifResult, config.RuntimeBaseConfig.Path)

		// marshal the result
		b, err := json.Marshal(sarifResult)
		if err != nil {
			return errors.Wrap(err, "could not marshal sarif result")
		}

		if config.RuntimeBaseConfig.OutputPath != "" {
			err = os.WriteFile(config.RuntimeBaseConfig.OutputPath, b, 0644)
			if err != nil {
				return errors.Wrap(err, "could not write sarif file to output path")
			}
			slog.Info("SARIF report saved", "path", config.RuntimeBaseConfig.OutputPath)
		}

		slog.Info("Uploading SARIF report", "scannerID", scannerID)

		req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/api/v1/sarif-scan/", config.RuntimeBaseConfig.APIURL), bytes.NewReader(b))
		if err != nil {
			return errors.Wrap(err, "could not create request")
		}

		err = services.SignRequest(config.RuntimeBaseConfig.Token, req)
		if err != nil {
			return errors.Wrap(err, "could not sign request")
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Scanner", "github.com/l3montree-dev/devguard/cmd/devguard-scanner/"+scannerID)
		config.SetXAssetHeaders(req)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			// check for timeout
			if errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "context deadline exceeded") {
				slog.Error("request timed out after configured or default timeout - as scan commands and upload can take a while consider increasing using the --timeout flag", "timeout", timeout)
			}
			return errors.Wrap(err, "could not send request")
		}

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
		var scanResponse dtos.FirstPartyScanResponse

		err = json.NewDecoder(resp.Body).Decode(&scanResponse)
		if err != nil {
			return errors.Wrap(err, "could not parse response")
		}

		return scanner.PrintFirstPartyScanResults(scanResponse, config.RuntimeBaseConfig.AssetName, config.RuntimeBaseConfig.WebUI, config.RuntimeBaseConfig.Ref, scannerID)
	}
}

func executeCodeScan(scannerID, path, outputPath string) (*sarif.SarifSchema210Json, error) {
	switch scannerID {
	case "secret-scanning":
		return secretScan(path, outputPath)
	case "sast":
		return sastScan(path, outputPath)
	case "iac":
		return iacScan(path, outputPath)
	default:
		return nil, fmt.Errorf("unknown scanner: %s", scannerID)
	}
}
