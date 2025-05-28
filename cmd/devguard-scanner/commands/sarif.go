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
	"math"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/l3montree-dev/devguard/cmd/devguard-scanner/config"
	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/l3montree-dev/devguard/internal/core/pat"
	"github.com/l3montree-dev/devguard/internal/core/vuln"
	"github.com/l3montree-dev/devguard/internal/core/vulndb/scan"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
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

	ctx, cancel := context.WithTimeout(cmd.Context(), 60*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/api/v1/sarif-scan", config.RuntimeBaseConfig.ApiUrl), bytes.NewReader(file))

	if err != nil {
		return err
	}

	err = pat.SignRequest(config.RuntimeBaseConfig.Token, req)
	if err != nil {
		return err
	}

	// set the headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Scanner", config.RuntimeBaseConfig.ScannerID)
	config.SetXAssetHeaders(req)

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
	var scanResponse scan.FirstPartyScanResponse

	err = json.NewDecoder(resp.Body).Decode(&scanResponse)
	if err != nil {
		return errors.Wrap(err, "could not parse response")
	}

	return printFirstPartyScanResults(scanResponse, config.RuntimeBaseConfig.AssetName, config.RuntimeBaseConfig.WebUI, config.RuntimeBaseConfig.Ref, config.RuntimeBaseConfig.ScannerID)
}

func NewSarifCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sarif",
		Short: "Usage: <sarif.json>. Scan a static application security test result file.",
		Long:  `Usage: <sarif.json>. Scan a static application security test result file. This will upload the file to DevGuard and return the results.`,
		Args:  cobra.ExactArgs(1),
		RunE:  sarifCmd,
	}

	cmd.Flags().String("scannerId", "github.com/l3montree-dev/devguard-scanner/cmd/sarif", "Name of the scanner. DevGuard will compare new and old results based on the scannerId.")

	addScanFlags(cmd)
	return cmd
}

func expandAndObfuscateSnippet(sarifScan *common.SarifResult, path string) {

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
				if len(sarifScan.Runs[ru].Results[re].PartialFingerprints.CommitSha) > 0 {
					fileContent, err = utils.ReadFileFromGitRef(path, sarifScan.Runs[ru].Results[re].PartialFingerprints.CommitSha, location.PhysicalLocation.ArtifactLocation.Uri)
					if err != nil {
						slog.Error("could not read file", "err", err)
						continue
					}
				} else {
					// read the file from the filesystem
					fileContent, err = os.ReadFile(location.PhysicalLocation.ArtifactLocation.Uri)
					if err != nil {
						slog.Error("could not read file", "err", err)
						continue
					}
				}
				// expand the snippet
				expandedSnippet, err := expandSnippet(fileContent, startLine, endLine, original)
				if err != nil {
					continue
				}

				// obfuscate the snippet
				obfuscateSnippet := obfuscateString(expandedSnippet)

				// set the snippet
				sarifScan.Runs[ru].Results[re].Locations[lo].PhysicalLocation.Region.Snippet.Text = obfuscateSnippet

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

	expandedSnippet += "+++\n" + secretLineBegin + original + "\n+++"

	if len(end) > 0 {
		endStr = strings.Join(end, "\n")
		expandedSnippet += "\n" + endStr
	}

	return expandedSnippet, nil
}

func obfuscateString(str string) string {

	// create regex to split string at whitespace and new line chars
	reg := regexp.MustCompile(`[\n]+`)
	// split the string into words
	els := reg.Split(str, -1)

	for i, el := range els {
		words := strings.Fields(el)
		// split at whitespace
		for i, word := range words {
			// 5 is a magic number!
			entropy := utils.ShannonEntropy(word)
			if entropy > 4 {
				words[i] = word[:1+len(word)/2] + strings.Repeat("*", len(word)/2)
			}
		}

		// join the words back together
		els[i] = strings.Join(words, " ")
	}

	return strings.Join(els, "\n")
}

// add obfuscation function for snippet
func obfuscateSecret(sarifScan *common.SarifResult) {
	// obfuscate the snippet
	for ru, run := range sarifScan.Runs {
		for re, result := range run.Results {
			for lo, location := range result.Locations {
				snippet := location.PhysicalLocation.Region.Snippet.Text
				snippetMax := 20
				if len(snippet) < snippetMax {
					snippetMax = len(snippet) / 2
				}
				snippet = snippet[:snippetMax] + strings.Repeat("*", len(snippet)-snippetMax)
				// set the snippet
				sarifScan.Runs[ru].Results[re].Locations[lo].PhysicalLocation.Region.Snippet.Text = snippet
			}
		}
	}
}

func printFirstPartyScanResults(scanResponse scan.FirstPartyScanResponse, assetName string, webUI string, assetVersionName string, scannerID string) error {

	if len(scanResponse.FirstPartyVulns) == 0 {
		return nil
	}

	// get all "open" vulns
	openVulns := utils.Filter(scanResponse.FirstPartyVulns, func(v vuln.FirstPartyVulnDTO) bool {
		return v.State == models.VulnStateOpen
	})

	switch scannerID {
	case "secret-scanning":
		printSecretScanResults(openVulns, webUI, assetName, assetVersionName)
	default:
		printSastScanResults(openVulns, webUI, assetName, assetVersionName)
	}

	if len(openVulns) > 0 {
		return fmt.Errorf("found %d unhandled vulnerabilities", len(openVulns))
	}

	return nil
}

func sarifCommandFactory(scannerID string) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		sarifResult, err := executeCodeScan(scannerID, config.RuntimeBaseConfig.Path)
		if err != nil {
			return errors.Wrap(err, "could not open file")
		}

		// expand snippet and obfuscate it
		expandAndObfuscateSnippet(sarifResult, config.RuntimeBaseConfig.Path)

		// marshal the result
		b, err := json.Marshal(sarifResult)
		if err != nil {
			return errors.Wrap(err, "could not marshal sarif result")
		}

		req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/api/v1/sarif-scan/", config.RuntimeBaseConfig.ApiUrl), bytes.NewReader(b))
		if err != nil {
			return errors.Wrap(err, "could not create request")
		}

		err = pat.SignRequest(config.RuntimeBaseConfig.Token, req)
		if err != nil {
			return errors.Wrap(err, "could not sign request")
		}

		if err != nil {
			printGitHelp(err)
			return errors.Wrap(err, "could not get version info")
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Asset-Name", config.RuntimeBaseConfig.AssetName)
		req.Header.Set("X-Scanner", "github.com/l3montree-dev/devguard/cmd/devguard-scanner/"+scannerID)
		req.Header.Set("X-Asset-Ref", config.RuntimeBaseConfig.Ref)
		if config.RuntimeBaseConfig.DefaultBranch != nil {
			req.Header.Set("X-Asset-Default-Branch", *config.RuntimeBaseConfig.DefaultBranch)
		}

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return errors.Wrap(err, "could not send request")
		}

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("could not scan file: %s", resp.Status)
		}

		// read and parse the body - it should be an array of dependencyVulns
		// print the dependencyVulns to the console
		var scanResponse scan.FirstPartyScanResponse

		err = json.NewDecoder(resp.Body).Decode(&scanResponse)
		if err != nil {
			return errors.Wrap(err, "could not parse response")
		}

		return printFirstPartyScanResults(scanResponse, config.RuntimeBaseConfig.AssetName, config.RuntimeBaseConfig.WebUI, config.RuntimeBaseConfig.Ref, scannerID)
	}
}

func executeCodeScan(scannerID, path string) (*common.SarifResult, error) {
	switch scannerID {
	case "secret-scanning":
		return secretScan(path)
	case "sast":
		return sastScan(path)
	case "iac":
		return iacScan(path)
	default:
		return nil, fmt.Errorf("unknown scanner: %s", scannerID)
	}
}
