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
	"strconv"
	"strings"
	"unicode/utf8"

	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/pat"
	"github.com/l3montree-dev/devguard/internal/core/vulndb/scan"
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

func generateSBOM(path string) (*os.File, error) {
	// generate random name
	filename := uuid.New().String() + ".json"

	// run the sbom generator
	cmd := exec.Command("cdxgen", "-o", filename)
	cmd.Dir = path

	err := cmd.Run()

	if err != nil {
		return nil, err
	}

	// open the file and return the path
	return os.Open(filepath.Join(path, filename))
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
	cmd.Stdout = &out
	cmd.Dir = path
	err := cmd.Run()
	if err != nil {
		log.Fatal(err)
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
		cmd.Stdout = &commitOut
		cmd.Dir = path
		err = cmd.Run()
		if err != nil {
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

func init() {
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	rootCmd.PersistentFlags().String("assetName", "", "The id of the asset which is scanned")
	rootCmd.PersistentFlags().String("token", "", "The personal access token to authenticate the request")
	rootCmd.PersistentFlags().String("apiUrl", "https://api.devguard.dev", "The url of the API to send the scan request to")

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

	scaCommand := &cobra.Command{
		Use:   "sca",
		Short: "Software composition analysis",
		Long:  `Scan a SBOM for vulnerabilities. This command will scan a SBOM for vulnerabilities and return a list of vulnerabilities found in the SBOM. The SBOM must be passed as an argument.`,
		// Args:  cobra.ExactArgs(0),
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
			apiUrl, err := cmd.Flags().GetString("apiUrl")
			if err != nil {
				slog.Error("could not get api url", "err", err)
				return
			}

			err = core.LoadConfig()
			if err != nil {
				slog.Warn("could not initialize config", "err", err)
			}

			path, err := cmd.Flags().GetString("path")
			if err != nil {
				slog.Error("could not get path", "err", err)
				return
			}

			if isValid, err := isValidPath(path); !isValid && err != nil {
				slog.Error("invalid path", "err", err)
				return
			}

			// we use the commit count, to check if we should create a new version - or if its dirty.
			// v1.0.0 - . . . . . . . . . . - v1.0.1
			// all commits after v1.0.0 are part of v1.0.1
			// if there are no commits after the tag, we are on a clean tag
			version, commitAfterTag, err := getCurrentVersion(path)
			if err != nil {
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
			defer func() {
				// remove the file after the scan
				err := os.Remove(file.Name())
				if err != nil {
					slog.Error("could not remove file", "err", err)
				}

			}()

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
			var scanResponse scan.ScanResponse

			err = json.NewDecoder(resp.Body).Decode(&scanResponse)
			if err != nil {
				slog.Error("could not parse response", "err", err)
				return
			}
			slog.Info("Scan completed successfully", "flawAmount", len(scanResponse.Flaws), "openedByThisScan", scanResponse.AmountOpened, "closedByThisScan", scanResponse.AmountClosed)

			if len(scanResponse.Flaws) == 0 {
				return
			}

			for _, f := range scanResponse.Flaws {
				slog.Info("flaw found", "cve", f.CVEID, "package", f.ArbitraryJsonData["packageName"], "severity", f.CVE.Severity, "introduced", f.ArbitraryJsonData["introducedVersion"], "fixed", f.ArbitraryJsonData["fixedVersion"])
			}
		},
	}
	scaCommand.Flags().String("path", ".", "The path to the project to scan. Defaults to the current directory.")

	rootCmd.AddCommand(scaCommand)
}

func main() {
	Execute()
}
