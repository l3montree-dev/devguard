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
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/flaw"
	"github.com/l3montree-dev/devguard/internal/core/pat"
	"github.com/l3montree-dev/devguard/internal/core/vulndb/scan"
	"github.com/l3montree-dev/devguard/internal/utils"
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
		trivyCmd = exec.Command("trivy", "fs", path, "--format", "cyclonedx", "--output", filename)
	} else {
		slog.Info("scanning single file", "file", maybeFilename)
		// scanning a single file
		// cdxgenCmd = exec.Command("cdxgen", maybeFilename, "-o", filename)
		trivyCmd = exec.Command("trivy", "image", "--input", path, "--format", "cyclonedx", "--output", filename)
	}

	// cdxgenCmd.Dir = getDirFromPath(path)
	trivyCmd.Dir = getDirFromPath(path)

	// run the commands
	/*err := cdxgenCmd.Run()
	if err != nil {
		return nil, err
	}*/

	err := trivyCmd.Run()
	if err != nil {
		return nil, err
	}
	// trivy generates the cyclonedx spec in version 1.6, while cdxgen generates version 1.5
	jsonData, err := os.ReadFile(filepath.Join(getDirFromPath(path), filename))
	if err != nil {
		return nil, err
	}
	// unmashal the json data
	var data map[string]interface{}
	err = json.Unmarshal(jsonData, &data)
	if err != nil {
		return nil, err
	}
	// change the spec version to 1.5
	data["specVersion"] = "1.5"
	// marshal the data back to json
	newJsonData, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	// write the data back to the file
	err = os.WriteFile(filepath.Join(getDirFromPath(path), filename), newJsonData, 0600)
	if err != nil {
		return nil, err
	}
	// merge the two files
	// mergeCommand := exec.Command("cyclonedx", "merge", "--hierarchical", "--name", "devguard", "--version", "v1.0.0", "--input-files", filename, filename+".1", "--input-format", "json", "--output-format", "json", "--output-file", strings.Replace(filename, ".json", "", 1)+".merged.json")
	/*mergeCommand.Dir = getDirFromPath(path)

	err = mergeCommand.Run()
	if err != nil {
		return nil, err
	}

	// remove the files

	err = os.Remove(filename)
	if err != nil {
		return nil, err
	}

	err = os.Remove(filename + ".1")
	if err != nil {
		return nil, err
	}*/

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
	if _, err := os.Stat(absPath); os.IsNotExist(err) {
		return false, fmt.Errorf("path does not exist")
	}

	return true, nil
}

func getCurrentVersion(path string) (string, int, error) {
	// mark the path as safe git directory
	slog.Debug("marking path as safe", "path", getDirFromPath(path))
	cmd := exec.Command("git", "config", "--global", "--add", "safe.directory", "*") // nolint:all
	var out bytes.Buffer
	var errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	err := cmd.Run()
	if err != nil {
		slog.Info("could not mark path as safe", "err", err, "path", getDirFromPath(path), "msg", errOut.String())
		return "", 0, err
	}

	// reset the buffer
	out.Reset()
	errOut.Reset()

	cmd = exec.Command("git", "tag", "--sort=-v:refname")

	cmd.Stdout = &out
	cmd.Stderr = &errOut
	cmd.Dir = getDirFromPath(path)
	err = cmd.Run()
	if err != nil {
		slog.Info("could not run git tag", "err", err, "path", getDirFromPath(path), "msg", errOut.String())
		return "", 0, err
	}

	// Filter using regex
	tagList := out.String()
	tags := strings.Split(tagList, "\n")
	semverRegex := regexp.MustCompile(`^v?[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$`)
	var latestTag string
	for _, tag := range tags {
		if semverRegex.MatchString(tag) {
			latestTag = tag
			break
		}
	}

	// Check and print the latest semver tag
	if latestTag == "" {
		return "", 0, fmt.Errorf("no semver tag found")
	} else {
		cmd = exec.Command("git", "rev-list", "--count", latestTag+"..HEAD") // nolint:all:Latest Tag is already checked against a semver regex.
		var commitOut bytes.Buffer
		errOut = bytes.Buffer{}
		cmd.Stdout = &commitOut
		cmd.Stderr = &errOut
		cmd.Dir = getDirFromPath(path)
		err = cmd.Run()
		if err != nil {
			slog.Error(
				"could not run git rev-list --count", "err", err, "path", getDirFromPath(path), "msg", errOut.String(),
			)
			log.Fatal(err)
		}

		commitCount := strings.TrimSpace(commitOut.String())
		commitCountInt, err := strconv.Atoi(commitCount)
		if err != nil {
			return "", 0, err
		}

		return latestTag, commitCountInt, nil
	}
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
		os.Exit(1)
	}
	assetName, err := cmd.PersistentFlags().GetString("assetName")
	if err != nil {
		slog.Error("could not get asset id", "err", err)
		os.Exit(1)
	}
	apiUrl, err := cmd.PersistentFlags().GetString("apiUrl")
	if err != nil {
		slog.Error("could not get api url", "err", err)
		os.Exit(1)
	}
	apiUrl = sanitizeApiUrl(apiUrl)

	failOnRisk, err := cmd.Flags().GetString("fail-on-risk")
	if err != nil {
		slog.Error("could not get fail-on-risk", "err", err)
		os.Exit(1)
	}

	webUI, err := cmd.Flags().GetString("webUI")
	if err != nil {
		slog.Error("could not get webUI", "err", err)
		os.Exit(1)
	}

	return token, assetName, apiUrl, failOnRisk, webUI
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
git tag -a v1.0.0 -m "Initial release"
git push origin v1.0.0

- New versions:
- Breaking changes:
git tag -a v2.0.0 -m "Breaking changes"
git push origin v2.0.0

- New features:
git tag -a v1.1.0 -m "New features"
git push origin v1.1.0

- Bug fixes:
git tag -a v1.0.1 -m "Bug fixes"
git push origin v1.0.1
`)
}

// can be reused for container scanning as well.
func printScaResults(scanResponse scan.ScanResponse, failOnRisk, assetName, webUI string, doRiskManagement bool) {
	slog.Info("Scan completed successfully", "flawAmount", len(scanResponse.Flaws), "openedByThisScan", scanResponse.AmountOpened, "closedByThisScan", scanResponse.AmountClosed)

	if len(scanResponse.Flaws) == 0 {
		return
	}

	// order the flaws by their risk
	slices.SortFunc(scanResponse.Flaws, func(a, b flaw.FlawDTO) int {
		return int(*(a.RawRiskAssessment)*100) - int(*b.RawRiskAssessment*100)
	})

	// get the max risk of open!!! flaws
	openRisks := utils.Map(utils.Filter(scanResponse.Flaws, func(f flaw.FlawDTO) bool {
		return f.State == "open"
	}), func(f flaw.FlawDTO) float64 {
		return *f.RawRiskAssessment
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
		scanResponse.Flaws,
		func(f flaw.FlawDTO) table.Row {
			clickableLink := ""
			if doRiskManagement {
				clickableLink = fmt.Sprintf("%s/%s/flaws/%s", webUI, assetName, f.ID)
			} else {
				clickableLink = "Risk Management is disabled"
			}
			return table.Row{f.ArbitraryJsonData["packageName"].(string), f.CVEID, *f.RawRiskAssessment, f.ArbitraryJsonData["installedVersion"], f.ArbitraryJsonData["fixedVersion"], f.State, clickableLink}
		},
	))

	fmt.Println(tw.Render())

	switch failOnRisk {
	case "low":
		if maxRisk > 0.1 {
			os.Exit(1)
		}
	case "medium":
		if maxRisk >= 4 {
			os.Exit(1)
		}

	case "high":
		if maxRisk >= 7 {
			os.Exit(1)
		}

	case "critical":
		if maxRisk >= 9 {
			os.Exit(1)
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
		os.Exit(1)
	}
	err = cmd.MarkPersistentFlagRequired("token")
	if err != nil {
		slog.Error("could not mark flag as required", "err", err)
		os.Exit(1)
	}

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

func scaCommandFactory(scanType string) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		core.InitLogger()
		token, assetName, apiUrl, failOnRisk, webUI := parseConfig(cmd)
		if token == "" {
			slog.Error("token seems to be empty. If you provide the token via an environment variable like --token=$DEVGUARD_TOKEN, check, if the environment variable is set or if there are any spelling mistakes", "token", token)
			os.Exit(1)
		}

		core.LoadConfig() // nolint:errcheck // just swallow the error: https://github.com/l3montree-dev/devguard/issues/188

		path, err := cmd.Flags().GetString("path")
		if err != nil {
			return errors.Wrap(err, "could not get path")
		}

		if isValid, err := isValidPath(path); !isValid && err != nil {
			return errors.Wrap(err, "invalid path")
		}

		// we use the commit count, to check if we should create a new version - or if its dirty.
		// v1.0.0 - . . . . . . . . . . - v1.0.1
		// all commits after v1.0.0 are part of v1.0.1
		// if there are no commits after the tag, we are on a clean tag
		version, commitAfterTag, err := getCurrentVersion(path)
		if err != nil {
			printGitHelp(err)
		}

		if commitAfterTag != 0 {
			version = version + "-" + strconv.Itoa(commitAfterTag)
		}

		slog.Info("starting scan", "version", version, "asset", assetName)
		// read the sbom file and post it to the scan endpoint
		// get the flaws and print them to the console
		file, err := generateSBOM(path)

		if err != nil {
			return errors.Wrap(err, "could not open file")
		}

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

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Risk-Management", strconv.FormatBool(doRiskManagement))
		req.Header.Set("X-Asset-Name", assetName)
		req.Header.Set("X-Asset-Version", version)
		req.Header.Set("X-Scan-Type", scanType)
		req.Header.Set("X-Scanner", "github.com/l3montree-dev/devguard/cmd/devguard-scanner"+"/"+scanType)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return errors.Wrap(err, "could not send request")
		}

		err = os.Remove(file.Name())
		if err != nil {
			return errors.Wrap(err, "could not remove file")
		}

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("could not scan file: %s", resp.Status)
		}

		// read and parse the body - it should be an array of flaws
		// print the flaws to the console
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
				os.Exit(1)
			}
		},
	}

	scaCommand.Flags().Bool("riskManagement", true, "Enable risk management (stores the detected vulnerabilities in devguard)")

	addScanFlags(scaCommand)
	return scaCommand
}