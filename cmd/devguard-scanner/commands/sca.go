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
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/l3montree-dev/devguard/cmd/devguard-scanner/config"
	"github.com/l3montree-dev/devguard/internal/core/pat"
	"github.com/l3montree-dev/devguard/internal/core/vuln"
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

// we need to run go mod tidy before running trivy
// this is because trivy needs dependencies before it can scan a go project
// https://trivy.dev/latest/docs/coverage/language/golang/
func prepareTrivyCommand(path string) {
	trivyCmd := exec.Command("go", "mod", "tidy")
	trivyCmd.Dir = getDirFromPath(path)
	stderr := &bytes.Buffer{}
	trivyCmd.Stderr = stderr
	err := trivyCmd.Run()
	if err != nil {
		return
	}
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

		prepareTrivyCommand(path)

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

// Function to dynamically change the format of the table row depending on the input parameters
func dependencyVulnToTableRow(pURL packageurl.PackageURL, v vuln.DependencyVulnDTO) table.Row {
	if pURL.Namespace == "" { //Remove the second slash if the second parameter is empty to avoid double slashes
		return table.Row{fmt.Sprintf("pkg:%s/%s", pURL.Type, pURL.Name), utils.SafeDereference(v.CVEID), utils.OrDefault(v.RawRiskAssessment, 0), strings.TrimPrefix(pURL.Version, "v"), utils.SafeDereference(v.ComponentFixedVersion), v.State}
	} else {
		return table.Row{fmt.Sprintf("pkg:%s/%s/%s", pURL.Type, pURL.Namespace, pURL.Name), utils.SafeDereference(v.CVEID), utils.OrDefault(v.RawRiskAssessment, 0), strings.TrimPrefix(pURL.Version, "v"), utils.SafeDereference(v.ComponentFixedVersion), v.State}
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
func printScaResults(scanResponse scan.ScanResponse, failOnRisk, assetName, webUI string) error {
	slog.Info("Scan completed successfully", "dependencyVulnAmount", len(scanResponse.DependencyVulns), "openedByThisScan", scanResponse.AmountOpened, "closedByThisScan", scanResponse.AmountClosed)

	if len(scanResponse.DependencyVulns) == 0 {
		return nil
	}

	// order the vulns by their risk
	slices.SortFunc(scanResponse.DependencyVulns, func(a, b vuln.DependencyVulnDTO) int {
		return int(utils.OrDefault(a.RawRiskAssessment, 0)*100) - int(utils.OrDefault(b.RawRiskAssessment, 0)*100)
	})

	// get the max risk of open!!! dependencyVulns
	openRisks := utils.Map(utils.Filter(scanResponse.DependencyVulns, func(f vuln.DependencyVulnDTO) bool {
		return f.State == "open"
	}), func(f vuln.DependencyVulnDTO) float64 {
		return utils.OrDefault(f.RawRiskAssessment, 0)
	})

	maxRisk := 0.
	for _, risk := range openRisks {
		if risk > maxRisk {
			maxRisk = risk
		}
	}

	tw := table.NewWriter()
	//tw.SetAllowedRowLength(155)
	tw.AppendHeader(table.Row{"Library", "Vulnerability", "Risk", "Installed", "Fixed", "Status"})
	tw.AppendRows(utils.Map(
		scanResponse.DependencyVulns,
		func(v vuln.DependencyVulnDTO) table.Row {
			// extract package name and version from purl
			// purl format: pkg:package-type/namespace/name@version?qualifiers#subpath
			pURL, err := packageurl.FromString(*v.ComponentPurl)
			if err != nil {
				slog.Error("could not parse purl", "err", err)
			}

			return dependencyVulnToTableRow(pURL, v)
		},
	))

	fmt.Println(tw.Render())
	if len(scanResponse.DependencyVulns) > 0 {
		clickableLink := fmt.Sprintf("%s/%s/refs/%s/dependency-risks/", webUI, assetName, scanResponse.DependencyVulns[0].AssetVersionName)
		fmt.Printf("See all dependency risks at:\n%s\n", clickableLink)
	}

	switch failOnRisk {
	case "low":
		if maxRisk > 0.1 {
			return fmt.Errorf("max risk exceeds threshold %f", maxRisk)
		}
	case "medium":
		if maxRisk >= 4 {
			return fmt.Errorf("max risk exceeds threshold %f", maxRisk)
		}

	case "high":
		if maxRisk >= 7 {
			return fmt.Errorf("max risk exceeds threshold %f", maxRisk)
		}

	case "critical":
		if maxRisk >= 9 {
			return fmt.Errorf("max risk exceeds threshold %f", maxRisk)
		}
	}

	return nil
}

func addDefaultFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().String("assetName", "", "The id of the asset which is scanned")
	cmd.PersistentFlags().String("token", "", "The personal access token to authenticate the request")
	cmd.PersistentFlags().String("apiUrl", "https://api.devguard.dev", "The url of the API to send the scan request to")
}

func addAssetRefFlags(cmd *cobra.Command) {
	cmd.Flags().String("ref", "", "The git reference to use. This can be a branch, tag, or commit hash. If not specified, it will first check for a git repository in the current directory. If not found, it will just use main.")
	cmd.Flags().String("defaultRef", "", "The default git reference to use. This can be a branch, tag, or commit hash. If not specified, it will check, if the current directory is a git repo. If it isn't, --ref will be used.")
}

func addScanFlags(cmd *cobra.Command) {
	addDefaultFlags(cmd)
	addAssetRefFlags(cmd)

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

	cmd.Flags().String("path", ".", "The path to the project to scan. Defaults to the current directory.")
	cmd.Flags().String("failOnRisk", "critical", "The risk level to fail the scan on. Can be 'low', 'medium', 'high' or 'critical'. Defaults to 'critical'.")
	cmd.Flags().String("webUI", "https://main.devguard.org", "The url of the web UI to show the scan results in. Defaults to 'https://main.devguard.org'.")

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

func scaCommandFactory(scannerID string) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		// read the sbom file and post it to the scan endpoint
		// get the dependencyVulns and print them to the console
		file, err := generateSBOM(config.RuntimeBaseConfig.Path)
		if err != nil {
			return errors.Wrap(err, "could not open file")
		}
		defer os.Remove(file.Name())

		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/api/v1/scan", config.RuntimeBaseConfig.ApiUrl), file)
		if err != nil {
			return errors.Wrap(err, "could not create request")
		}

		err = pat.SignRequest(config.RuntimeBaseConfig.Token, req)
		if err != nil {
			return errors.Wrap(err, "could not sign request")
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Scanner", "github.com/l3montree-dev/devguard/cmd/devguard-scanner/"+scannerID)
		config.SetXAssetHeaders(req)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return errors.Wrap(err, "could not send request")
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

		return printScaResults(scanResponse, config.RuntimeBaseConfig.FailOnRisk, config.RuntimeBaseConfig.AssetName, config.RuntimeBaseConfig.WebUI)
	}
}

func NewSCACommand() *cobra.Command {
	scaCommand := &cobra.Command{
		Use:   "sca",
		Short: "Start a Software composition analysis",
		Long:  `Scan an application for vulnerabilities. This command will generate a sbom, upload it to devguard and scan it for vulnerabilities.`,
		// Args:  cobra.ExactArgs(0),
		RunE: scaCommandFactory("sca"),
	}

	addScanFlags(scaCommand)
	return scaCommand
}
