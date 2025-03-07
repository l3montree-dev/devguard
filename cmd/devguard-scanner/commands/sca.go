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
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/dependencyVuln"
	"github.com/l3montree-dev/devguard/internal/core/pat"
	"github.com/l3montree-dev/devguard/internal/core/vulndb/scan"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/package-url/packageurl-go"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func maybeGetFileName(path string) (string, bool) {
	l, err := os.Stat(path)
	if err != nil {
		return "", false
	}

	if l.IsDir() {
		return path, true
	}
	return filepath.Base(path), false
}

func generateSBOM(path string) (*os.File, error) {
	// generate random name
	filename := uuid.New().String() + ".json"

	// check if we are scanning a dir or a single file
	maybeFilename, isDir := maybeGetFileName(path)
	// var cdxgenCmd *exec.Cmd
	var trivyCmd *exec.Cmd
	if isDir {
		slog.Info("scanning directory", "dir", path)
		// scanning a dir
		// cdxgenCmd = exec.Command("cdxgen", "-o", filename)
		trivyCmd = exec.Command("trivy", "fs", ".", "--format", "cyclonedx", "--output", filename)
	} else {
		slog.Info("scanning single file", "file", maybeFilename)
		// scanning a single file
		// cdxgenCmd = exec.Command("cdxgen", maybeFilename, "-o", filename)
		trivyCmd = exec.Command("trivy", "image", "--input", filepath.Base(path), "--format", "cyclonedx", "--output", filename) // nolint:all // 	There is no security issue right here. This runs on the client. You are free to attack yourself.
	}

	stderr := &bytes.Buffer{}
	// get the output
	trivyCmd.Stderr = stderr

	// cdxgenCmd.Dir = getDirFromPath(path)
	trivyCmd.Dir = getDirFromPath(path)

	// run the commands
	/*err := cdxgenCmd.Run()
	if err != nil {
		return nil, err
	}*/

	err := trivyCmd.Run()
	if err != nil {
		return nil, errors.Wrap(err, stderr.String())
	}

	// open the file and return the path
	return os.Open(filepath.Join(getDirFromPath(path), filename))
}

// containsRune checks if a string contains a specific rune
func containsRune(s string, r rune) bool {
	for _, char := range s {
		if char == r {
			return true
		}
	}
	return false
}

// IsValidPath checks if a string is a valid file path
func isValidPath(path string) (bool, error) {
	// Check for null bytes
	if !utf8.ValidString(path) || len(path) == 0 {
		return false, fmt.Errorf("path contains null bytes")
	}

	// Check for invalid characters
	invalidChars := `<>:"\|?*`
	for _, char := range invalidChars {
		if containsRune(path, char) {
			return false, fmt.Errorf("invalid character '%c' in path", char)
		}
	}

	// Check if the path length is within the acceptable limit
	if len(path) > 260 {
		return false, fmt.Errorf("path length exceeds 260 characters")
	}

	// Check if the path is either absolute or relative
	absPath, err := filepath.Abs(path)
	if err != nil {
		return false, err
	}

	// Check if the path exists
	_, err = os.Stat(absPath)

	if os.IsNotExist(err) {
		return false, errors.Wrap(err, "path does not exist: %s"+absPath)
	}

	return true, nil
}

func sanitizeApiUrl(apiUrl string) string {
	// check if the url has a trailing slash
	apiUrl = strings.TrimSuffix(apiUrl, "/")

	// check if the url has a protocol
	if !strings.HasPrefix(apiUrl, "http://") && !strings.HasPrefix(apiUrl, "https://") {
		apiUrl = "https://" + apiUrl
	}

	return apiUrl
}

func parseConfig(cmd *cobra.Command) (string, string, string, string, string) {
	token, err := cmd.PersistentFlags().GetString("token")
	if err != nil {
		slog.Error("could not get token", "err", err)
		return "", "", "", "", ""
	}
	assetName, err := cmd.PersistentFlags().GetString("assetName")
	if err != nil {
		slog.Error("could not get asset id", "err", err)
		return "", "", "", "", ""
	}
	apiUrl, err := cmd.PersistentFlags().GetString("apiUrl")
	if err != nil {
		slog.Error("could not get api url", "err", err)
		return "", "", "", "", ""
	}
	apiUrl = sanitizeApiUrl(apiUrl)

	failOnRisk, err := cmd.Flags().GetString("fail-on-risk")
	if err != nil {
		slog.Error("could not get fail-on-risk", "err", err)
		return "", "", "", "", ""
	}

	webUI, err := cmd.Flags().GetString("webUI")
	if err != nil {
		slog.Error("could not get webUI", "err", err)
		return "", "", "", "", ""
	}

	return token, assetName, apiUrl, failOnRisk, webUI
}

// Function to dynamically change the format of the table row depending on the input parameters
func flawToTableRow(pURL packageurl.PackageURL, f flaw.FlawDTO, clickableLink string) table.Row {
	if pURL.Namespace == "" { //Remove the second slash if the second parameter is empty to avoid double slashes
		return table.Row{fmt.Sprintf("pkg:%s/%s", pURL.Type, pURL.Name), utils.SafeDereference(f.CVEID), utils.OrDefault(f.RawRiskAssessment, 0), strings.TrimPrefix(pURL.Version, "v"), utils.SafeDereference(f.ComponentFixedVersion), f.State, clickableLink}
	} else {
		return table.Row{fmt.Sprintf("pkg:%s/%s/%s", pURL.Type, pURL.Namespace, pURL.Name), utils.SafeDereference(f.CVEID), utils.OrDefault(f.RawRiskAssessment, 0), strings.TrimPrefix(pURL.Version, "v"), utils.SafeDereference(f.ComponentFixedVersion), f.State, clickableLink}
	}
}

func printGitHelp(err error) {
	// do a detailed explaination on how to version the software using git tags
	slog.Error("could not get semver version", "err", err)
	slog.Info(`1. What is SemVer:
Semantic Versioning (SemVer) uses a version number format: MAJOR.MINOR.PATCH
- MAJOR: Incompatible API changes
- MINOR: Backward-compatible new features
- PATCH: Backward-compatible bug fixes

2. How to do it:
- Initial tag:
git tag -a 1.0.0 -m "Initial release"
git push origin 1.0.0

- New versions:
- Breaking changes:
git tag -a 2.0.0 -m "Breaking changes"
git push origin 2.0.0

- New features:
git tag -a 1.1.0 -m "New features"
git push origin 1.1.0

- Bug fixes:
git tag -a 1.0.1 -m "Bug fixes"
git push origin 1.0.1
`)
}

// can be reused for container scanning as well.
func printScaResults(scanResponse scan.ScanResponse, failOnRisk, assetName, webUI string, doRiskManagement bool) {
	slog.Info("Scan completed successfully", "dependencyVulnAmount", len(scanResponse.DependencyVulns), "openedByThisScan", scanResponse.AmountOpened, "closedByThisScan", scanResponse.AmountClosed)

	if len(scanResponse.DependencyVulns) == 0 {
		return
	}

	// order the flaws by their risk
	slices.SortFunc(scanResponse.DependencyVulns, func(a, b dependencyVuln.DependencyVulnDTO) int {
		return int(utils.OrDefault(a.RawRiskAssessment, 0)*100) - int(utils.OrDefault(b.RawRiskAssessment, 0)*100)
	})

	// get the max risk of open!!! dependencyVulns
	openRisks := utils.Map(utils.Filter(scanResponse.DependencyVulns, func(f dependencyVuln.DependencyVulnDTO) bool {
		return f.State == "open"
	}), func(f dependencyVuln.DependencyVulnDTO) float64 {
		return utils.OrDefault(f.RawRiskAssessment, 0)
	})

	maxRisk := 0.
	for _, risk := range openRisks {
		if risk > maxRisk {
			maxRisk = risk
		}
	}

	tw := table.NewWriter()
	tw.AppendHeader(table.Row{"Library", "Vulnerability", "Risk", "Installed", "Fixed", "Status", "URL"})
	tw.AppendRows(utils.Map(
		scanResponse.DependencyVulns,
		func(f dependencyVuln.DependencyVulnDTO) table.Row {
			clickableLink := ""
			if doRiskManagement {
				//TODO: change flaws
				clickableLink = fmt.Sprintf("%s/%s/flaws/%s", webUI, assetName, f.ID)
			} else {
				clickableLink = "Risk Management is disabled"
			}

			// extract package name and version from purl
			// purl format: pkg:package-type/namespace/name@version?qualifiers#subpath
			pURL, err := packageurl.FromString(*f.ComponentPurl)
			if err != nil {
				slog.Error("could not parse purl", "err", err)
			}

			return flawToTableRow(pURL, f, clickableLink)
		},
	))

	fmt.Println(tw.Render())

	switch failOnRisk {
	case "low":
		if maxRisk > 0.1 {
			return
		}
	case "medium":
		if maxRisk >= 4 {
			return
		}

	case "high":
		if maxRisk >= 7 {
			return
		}

	case "critical":
		if maxRisk >= 9 {
			return
		}
	}
}

func addDefaultFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().String("assetName", "", "The id of the asset which is scanned")
	cmd.PersistentFlags().String("token", "", "The personal access token to authenticate the request")
	cmd.PersistentFlags().String("apiUrl", "https://api.devguard.dev", "The url of the API to send the scan request to")
}

func addScanFlags(cmd *cobra.Command) {
	addDefaultFlags(cmd)
	err := cmd.MarkPersistentFlagRequired("assetName")
	if err != nil {
		slog.Error("could not mark flag as required", "err", err)
		return
	}
	err = cmd.MarkPersistentFlagRequired("token")
	if err != nil {
		slog.Error("could not mark flag as required", "err", err)
		return
	}

	cmd.Flags().Bool("riskManagement", true, "Enable risk management (stores the detected vulnerabilities in devguard)")

	cmd.Flags().String("path", ".", "The path to the project to scan. Defaults to the current directory.")
	cmd.Flags().String("fail-on-risk", "critical", "The risk level to fail the scan on. Can be 'low', 'medium', 'high' or 'critical'. Defaults to 'critical'.")
	cmd.Flags().String("webUI", "https://main.devguard.org", "The url of the web UI to show the scan results in. Defaults to 'https://app.devguard.dev'.")

}

func getDirFromPath(path string) string {
	fi, err := os.Stat(path)
	if err != nil {
		return path
	}
	switch mode := fi.Mode(); {
	case mode.IsDir():
		return path
	case mode.IsRegular():
		return filepath.Dir(path)
	}
	return path
}

func scaCommandFactory(scanner string) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		core.InitLogger()
		token, assetName, apiUrl, failOnRisk, webUI := parseConfig(cmd)
		if token == "" {
			slog.Error("token seems to be empty. If you provide the token via an environment variable like --token=$DEVGUARD_TOKEN, check, if the environment variable is set or if there are any spelling mistakes", "token", token)
			return fmt.Errorf("token seems to be empty")
		}

		core.LoadConfig() // nolint:errcheck // just swallow the error: https://github.com/l3montree-dev/devguard/issues/188

		path, err := cmd.Flags().GetString("path")
		if err != nil {
			return errors.Wrap(err, "could not get path")
		}

		if isValid, err := isValidPath(path); !isValid && err != nil {
			return errors.Wrap(err, "invalid path")
		}

		// read the sbom file and post it to the scan endpoint
		// get the dependencyVulns and print them to the console
		file, err := generateSBOM(path)
		if err != nil {
			return errors.Wrap(err, "could not open file")
		}
		defer os.Remove(file.Name())

		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		// check if we should do risk management
		doRiskManagement, err := cmd.Flags().GetBool("riskManagement")
		if err != nil {
			return errors.Wrap(err, "could not get risk management flag")
		}

		req, err := http.NewRequestWithContext(ctx, "POST", apiUrl+"/api/v1/scan", file)
		if err != nil {
			return errors.Wrap(err, "could not create request")
		}

		err = pat.SignRequest(token, req)
		if err != nil {
			return errors.Wrap(err, "could not sign request")
		}

		err = utils.SetGitVersionHeader(path, req)

		if err != nil {
			printGitHelp(err)
			return errors.Wrap(err, "could not get version info")
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Risk-Management", strconv.FormatBool(doRiskManagement))
		req.Header.Set("X-Asset-Name", assetName)
		req.Header.Set("X-Scanner", "github.com/l3montree-dev/devguard/cmd/devguard-scanner"+"/"+scanner)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return errors.Wrap(err, "could not send request")
		}

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("could not scan file: %s", resp.Status)
		}

		// read and parse the body - it should be an array of dependencyVulns
		// print the dependencyVulns to the console
		var scanResponse scan.ScanResponse

		err = json.NewDecoder(resp.Body).Decode(&scanResponse)
		if err != nil {
			return errors.Wrap(err, "could not parse response")
		}

		printScaResults(scanResponse, failOnRisk, assetName, webUI, doRiskManagement)
		return nil
	}
}

func NewSCACommand() *cobra.Command {
	scaCommand := &cobra.Command{
		Use:   "sca",
		Short: "Start a Software composition analysis",
		Long:  `Scan an application for vulnerabilities. This command will generate a sbom, upload it to devguard and scan it for vulnerabilities.`,
		// Args:  cobra.ExactArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			err := scaCommandFactory("sca")(cmd, args)
			if err != nil {
				slog.Error("software composition analysis failed", "err", err)
				panic(err.Error())
			}
		},
	}

	addScanFlags(scaCommand)
	return scaCommand
}
