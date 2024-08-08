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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"time"

	"github.com/google/uuid"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/flaw"
	"github.com/l3montree-dev/devguard/internal/core/pat"
	"github.com/l3montree-dev/devguard/internal/core/vulndb/scan"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "devguard-scanner",
	Short: "Vulnerability management for devs.",
	Long:  `Devguard-Scanner is a tool to identify vulnerabilities and flaws in a software. It communicates the result to a devguard instance.`,
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

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
	cmd := exec.Command("git", "tag", "--sort=-v:refname")
	var out bytes.Buffer
	var errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	cmd.Dir = getDirFromPath(path)
	err := cmd.Run()
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

func parseConfig(cmd *cobra.Command) (string, string, string, string, string) {
	token, err := cmd.Flags().GetString("token")
	if err != nil {
		slog.Error("could not get token", "err", err)
		os.Exit(1)
	}
	assetName, err := cmd.Flags().GetString("assetName")
	if err != nil {
		slog.Error("could not get asset id", "err", err)
		os.Exit(1)
	}
	apiUrl, err := cmd.Flags().GetString("apiUrl")
	if err != nil {
		slog.Error("could not get api url", "err", err)
		os.Exit(1)
	}
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
func printScaResults(scanResponse scan.ScanResponse, failOnRisk, assetName, webUI string) {
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
			clickableLink := fmt.Sprintf("\033]8;;%s/%s/flaws/%s\033\\View in Web UI\033]8;;\033\\", webUI, assetName, f.ID)
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

func addScanFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().String("assetName", "", "The id of the asset which is scanned")
	cmd.PersistentFlags().String("token", "", "The personal access token to authenticate the request")
	cmd.PersistentFlags().String("apiUrl", "https://api.devguard.dev", "The url of the API to send the scan request to")

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
	cmd.Flags().String("webUI", "http://localhost:3000", "The url of the web UI to show the scan results in. Defaults to 'https://app.devguard.dev'.")
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

func scaCommandFactory(scanType string) func(cmd *cobra.Command, args []string) {
	return func(cmd *cobra.Command, args []string) {
		core.InitLogger()
		token, assetName, apiUrl, failOnRisk, webUI := parseConfig(cmd)

		err := core.LoadConfig()
		if err != nil {
			slog.Warn("could not initialize config", "err", err)
		}

		path, err := cmd.Flags().GetString("path")
		if err != nil {
			slog.Error("could not get path", "err", err)
			os.Exit(1)
		}

		if isValid, err := isValidPath(path); !isValid && err != nil {
			slog.Error("invalid path", "err", err)
			os.Exit(1)
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
			slog.Error("could not open file", "err", err)
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		req, err := http.NewRequestWithContext(ctx, "POST", apiUrl+"/api/v1/scan", file)
		if err != nil {
			slog.Error("could not create request", "err", err)
			return
		}

		err = pat.SignRequest(token, req)
		if err != nil {
			slog.Error("could not sign request", "err", err)
			return
		}

		req.Header.Set("X-Asset-Name", assetName)
		req.Header.Set("X-Asset-Version", version)
		req.Header.Set("X-Scan-Type", scanType)
		req.Header.Set("X-Scanner", "github.com/l3montree-dev/devguard/cmd/devguard-scanner"+"/"+scanType)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			slog.Error("could not send request", "err", err)
			return
		}

		err = os.Remove(file.Name())
		if err != nil {
			slog.Error("could not remove file", "err", err)
		}

		if resp.StatusCode != http.StatusOK {
			slog.Error("could not scan file", "status", resp.Status)
			return
		}

		// read and parse the body - it should be an array of flaws
		// print the flaws to the console
		var scanResponse scan.ScanResponse

		err = json.NewDecoder(resp.Body).Decode(&scanResponse)
		if err != nil {
			slog.Error("could not parse response", "err", err)
			return
		}
		printScaResults(scanResponse, failOnRisk, assetName, webUI)
	}
}

func init() {
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	healthCheckCommand := &cobra.Command{
		Use:   "health",
		Short: "Check the health of the scanner",
		Long:  `Check if all dependencies are installed for the scanner to function`,
		Args:  cobra.ExactArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			// execute cdxgen and git help commands. If they throw an error, print it to the console
			// if they don't, print a success message

			for _, command := range []string{"trivy", "git"} {
				cmd := exec.Command(command, "--help")
				// get the output
				var out bytes.Buffer
				cmd.Stdout = &out

				err := cmd.Run()
				if err != nil {
					slog.Error("could not execute command", "command", command, "err", err)
					return
				}
				// read the output
				slog.Info("command executed successfully", "command", command)
			}
		},
	}

	rootCmd.AddCommand(healthCheckCommand)

	scaCommand := &cobra.Command{
		Use:   "sca",
		Short: "Software composition analysis",
		Long:  `Scan an application for vulnerabilities. This command will generate a sbom, upload it to devguard and scan it for vulnerabilities.`,
		// Args:  cobra.ExactArgs(0),
		Run: scaCommandFactory("sca"),
	}

	containerScanningCommand := &cobra.Command{
		Use:   "container-scanning",
		Short: "Software composition analysis of a container image",
		Long:  `Scan a SBOM for vulnerabilities. This command will scan a SBOM for vulnerabilities and return a list of vulnerabilities found in the SBOM. The SBOM must be passed as an argument.`,
		// Args:  cobra.ExactArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			// check if the path has a .tar ending
			path, err := cmd.Flags().GetString("path")
			if err != nil {
				slog.Error("could not get path", "err", err)
				os.Exit(1)
			}
			if !strings.HasSuffix(path, ".tar") {
				slog.Error("invalid path", "err", fmt.Errorf("path must be a tar file"))
				os.Exit(1)
			}

			scaCommandFactory("container-scanning")(cmd, args)
		},
	}

	addScanFlags(scaCommand)
	addScanFlags(containerScanningCommand)

	rootCmd.AddCommand(scaCommand)
	rootCmd.AddCommand(containerScanningCommand)
}

func main() {
	Execute()
}
