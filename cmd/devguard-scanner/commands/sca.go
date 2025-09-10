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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
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

type AttestationFileLine struct {
	PayloadType string `json:"payloadType"`
	Payload     string `json:"payload"` // base64 encoded AttestationPayload
}

// extract filename from path or return directory if path points to a directory
// second return argument is true if it's a directory and false is it's a file
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
func prepareTrivyCommand(workdir string) {
	trivyCmd := exec.Command("go", "mod", "tidy")
	trivyCmd.Dir = workdir
	stderr := &bytes.Buffer{}
	trivyCmd.Stderr = stderr
	err := trivyCmd.Run()
	if err != nil {
		return
	}
}

func generateSBOM(ctx context.Context, pathOrImage string, isImage bool) ([]byte, error) {
	// generate random name
	filename := uuid.New().String() + ".json"

	// check if we are scanning a dir or a single file
	maybeFilename, isDir := maybeGetFileName(pathOrImage)

	// if we are supposed to load an image just use the current workdir
	// because where else would we switch to. For all other cases look at
	// the Path variables that's passed in via the config
	var workDir string
	if isImage {
		workDir = "./"
	} else {
		workDir = getDirFromPath(pathOrImage)
	}
	sbomFile := filepath.Join(workDir, filename)

	var trivyCmd *exec.Cmd
	if isImage {
		image := pathOrImage
		// login in to docker registry first before we try to run trivy
		err := maybeLoginIntoOciRegistry(ctx)
		if err != nil {
			return nil, err
		}

		slog.Info("scanning oci image", "image", image)
		trivyCmd = exec.Command("trivy", "image", image, "--format", "cyclonedx", "--output", sbomFile)
	} else if isDir {
		slog.Info("scanning directory", "dir", workDir)
		prepareTrivyCommand(workDir)
		// scanning a dir
		trivyCmd = exec.Command("trivy", "fs", ".", "--format", "cyclonedx", "--output", sbomFile)
		// set working directory because the trivy command scans the local directory
		trivyCmd.Dir = workDir
	} else {
		slog.Info("scanning single file", "file", maybeFilename)
		// scanning a single file
		// cdxgenCmd = exec.Command("cdxgen", maybeFilename, "-o", filename)
		trivyCmd = exec.Command("trivy", "image", "--input", filepath.Base(pathOrImage), "--format", "cyclonedx", "--output", sbomFile) // nolint:all // 	There is no security issue right here. This runs on the client. You are free to attack yourself.
	}

	stderr := &bytes.Buffer{}
	// get the output
	trivyCmd.Stderr = stderr

	err := trivyCmd.Run()
	if err != nil {
		return nil, errors.Wrap(err, stderr.String())
	}
	file, err := os.Open(sbomFile)
	if err != nil {
		return nil, errors.Wrap(err, "could not open file")
	}
	// open the file and return the path
	content, err := io.ReadAll(file)
	if err != nil {
		return nil, errors.Wrap(err, "could not read file")
	}

	// delete the file after reading it
	defer os.Remove(sbomFile)
	return content, nil
}

// Function to dynamically change the format of the table row depending on the input parameters
func dependencyVulnToTableRow(pURL packageurl.PackageURL, v vuln.DependencyVulnDTO) table.Row {
	var cvss float32 = 0.0
	if v.CVE != nil {
		cvss = v.CVE.CVSS
	}

	if pURL.Namespace == "" { //Remove the second slash if the second parameter is empty to avoid double slashes
		return table.Row{fmt.Sprintf("pkg:%s/%s", pURL.Type, pURL.Name), utils.SafeDereference(v.CVEID), utils.OrDefault(v.RawRiskAssessment, 0), cvss, strings.TrimPrefix(pURL.Version, "v"), utils.SafeDereference(v.ComponentFixedVersion), v.State}
	} else {
		return table.Row{fmt.Sprintf("pkg:%s/%s/%s", pURL.Type, pURL.Namespace, pURL.Name), utils.SafeDereference(v.CVEID), utils.OrDefault(v.RawRiskAssessment, 0), cvss, strings.TrimPrefix(pURL.Version, "v"), utils.SafeDereference(v.ComponentFixedVersion), v.State}
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
func printScaResults(scanResponse scan.ScanResponse, failOnRisk, failOnCVSS, assetName, webUI string) error {
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

	openCVSS := utils.Map(utils.Filter(scanResponse.DependencyVulns, func(f vuln.DependencyVulnDTO) bool {
		return f.State == "open" && f.CVE != nil
	}), func(f vuln.DependencyVulnDTO) float32 {
		return f.CVE.CVSS
	})

	maxRisk := 0.
	for _, risk := range openRisks {
		if risk > maxRisk {
			maxRisk = risk
		}
	}

	var maxCVSS float32
	for _, v := range openCVSS {
		if v > maxCVSS {
			maxCVSS = v
		}
	}

	tw := table.NewWriter()
	//tw.SetAllowedRowLength(155)
	tw.AppendHeader(table.Row{"Library", "Vulnerability", "Risk", "CVSS", "Installed", "Fixed", "Status"})
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
			return fmt.Errorf("max risk exceeds threshold %.2f", maxRisk)
		}
	case "medium":
		if maxRisk >= 4 {
			return fmt.Errorf("max risk exceeds threshold %.2f", maxRisk)
		}

	case "high":
		if maxRisk >= 7 {
			return fmt.Errorf("max risk exceeds threshold %.2f", maxRisk)
		}

	case "critical":
		if maxRisk >= 9 {
			return fmt.Errorf("max risk exceeds threshold %.2f", maxRisk)
		}
	}

	switch failOnCVSS {
	case "low":
		if maxCVSS > 0.1 {
			return fmt.Errorf("max CVSS exceeds threshold %.2f", maxCVSS)
		}
	case "medium":
		if maxCVSS >= 4 {
			return fmt.Errorf("max CVSS exceeds threshold %.2f", maxCVSS)
		}
	case "high":
		if maxCVSS >= 7 {
			return fmt.Errorf("max CVSS exceeds threshold %.2f", maxCVSS)
		}
	case "critical":
		if maxCVSS >= 9 {
			return fmt.Errorf("max CVSS exceeds threshold %.2f", maxCVSS)
		}
	}

	return nil
}

func addDefaultFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().String("assetName", "", "The id of the asset which is scanned")
	cmd.PersistentFlags().String("token", "", "The personal access token to authenticate the request")
	cmd.PersistentFlags().String("apiUrl", "https://api.devguard.org", "The url of the API to send the scan request to")
}

func addAssetRefFlags(cmd *cobra.Command) {
	cmd.Flags().String("ref", "", "The git reference to use. This can be a branch, tag, or commit hash. If not specified, it will first check for a git repository in the current directory. If not found, it will just use main.")
	cmd.Flags().String("defaultRef", "", "The default git reference to use. This can be a branch, tag, or commit hash. If not specified, it will check, if the current directory is a git repo. If it isn't, --ref will be used.")
	cmd.Flags().Bool("isTag", false, "If the current git reference is a tag. If not specified, it will check if the current directory is a git repo. If it isn't, it will be set to false.")
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
	cmd.Flags().String("image", "", "The oci image to scan.")
	cmd.Flags().String("failOnRisk", "critical", "The risk level to fail the scan on. Can be 'low', 'medium', 'high' or 'critical'. Defaults to 'critical'.")
	cmd.Flags().String("failOnCVSS", "critical", "The risk level to fail the scan on. Can be 'low', 'medium', 'high' or 'critical'. Defaults to 'critical'.")
	cmd.Flags().String("webUI", "https://app.devguard.org", "The url of the web UI to show the scan results in. Defaults to 'https://app.devguard.org'.")
	cmd.Flags().String("artifactName", "", "The name of the artifact which was scanned. If not specified, it will default to the empty artifact name ''.")

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

func getAttestations(image string) ([]map[string]any, error) {
	// cosign download attestation image
	cosignCmd := exec.Command("cosign", "download", "attestation", image)

	stderrBuf := &bytes.Buffer{}
	stdoutBuf := &bytes.Buffer{}

	// get the output
	cosignCmd.Stderr = stderrBuf
	cosignCmd.Stdout = stdoutBuf

	err := cosignCmd.Run()
	if err != nil {
		return nil, errors.Wrap(err, stderrBuf.String())
	}

	stdoutStr := stdoutBuf.String()
	jsonLines := strings.Split(stdoutStr, "\n")
	if len(jsonLines) > 0 {
		// remove last element (empty line)
		jsonLines = jsonLines[:len(jsonLines)-1]
	}

	attestations := []map[string]any{}
	// go through each line (attestation) of the .jsonlines file
	for _, jsonLine := range jsonLines {
		var line AttestationFileLine
		err = json.Unmarshal([]byte(jsonLine), &line)
		if err != nil {
			return nil, err
		}

		// Extract base64 encoded payload
		data, err := base64.StdEncoding.DecodeString(line.Payload)
		if err != nil {
			log.Fatal("error:", err)
		}

		// Parse payload as attestation
		var attestation map[string]any
		err = json.Unmarshal([]byte(data), &attestation)
		if err != nil {
			return nil, err
		}

		attestations = append(attestations, attestation)
	}

	return attestations, nil
}

func scanExternalImage() error {
	// download and extract release attestation BOMs first
	attestations, err := getAttestations(config.RuntimeBaseConfig.Image)
	if err != nil && !strings.Contains(err.Error(), "found no attestations") {
		return err
	}

	ctx := context.Background()

	// generate SBOM using Trivy
	file, err := generateSBOM(ctx, config.RuntimeBaseConfig.Image, true)
	if err != nil {
		return err
	}

	// load sbom that was generated in the line above
	bom, err := bomFromBytes(file)
	if err != nil {
		return err
	}

	var vex *cyclonedx.BOM

	// check if there is any release attestation - if so, add the purl to the sbom
	for _, attestation := range attestations {
		if strings.HasPrefix(attestation["predicateType"].(string), "https://cyclonedx.org/vex") {
			predicate, ok := attestation["predicate"].(map[string]any)
			if !ok {
				panic("could not parse predicate")
			}

			// marshal the predicate back to json
			predicateBytes, err := json.Marshal(predicate)
			if err != nil {
				panic(err)
			}
			vex, err = bomFromBytes(predicateBytes)
			if err != nil {
				panic(err)
			}
		} else if attestation["predicateType"] == "https://in-toto.io/attestation/release/v0.1" {
			predicate, ok := attestation["predicate"].(map[string]any)
			if !ok {
				panic("could not parse predicate")
			}
			purl, ok := predicate["purl"].(string)
			if !ok || purl == "" {
				panic("could not parse purl")
			}

			// try to parse a version from the purl
			parsedPurl, err := packageurl.FromString(purl)
			if err != nil {
				slog.Warn("could not parse purl", "purl", purl, "err", err)
				continue
			}

			bom.Components = utils.Ptr(append(*bom.Components, cyclonedx.Component{
				Type:       cyclonedx.ComponentTypeApplication,
				Name:       purl,
				BOMRef:     purl,
				PackageURL: purl,
				Version:    parsedPurl.Version,
			}))

			// get the root and mark a dependency on the purl
			rootRef := bom.Metadata.Component.BOMRef
			// find the root ref in the dependencies and add a dependency to the purl
			index := slices.IndexFunc(*bom.Dependencies, func(d cyclonedx.Dependency) bool {
				return d.Ref == rootRef
			})
			if index == -1 {
				continue
			}
			dependencies := *(*bom.Dependencies)[index].Dependencies
			if dependencies == nil {
				dependencies = []string{}
			}
			// only add if not already present
			if slices.Contains(dependencies, purl) {
				continue
			}

			dependencies = append(dependencies, purl)
			(*bom.Dependencies)[index].Dependencies = &dependencies
		}
	}

	buff := &bytes.Buffer{}
	// marshal the bom back to json
	err = cyclonedx.NewBOMEncoder(buff, cyclonedx.BOMFileFormatJSON).Encode(bom)
	if err != nil {
		return err
	}

	// upload the bom to the scan endpoint
	resp, cancel, err := uploadBOM(buff)

	if err != nil {
		return errors.Wrap(err, "could not send request")
	}
	defer cancel()
	defer resp.Body.Close()

	// check if we can upload a vex as well
	if vex != nil {
		vexBuff := &bytes.Buffer{}
		// marshal the bom back to json
		err = cyclonedx.NewBOMEncoder(vexBuff, cyclonedx.BOMFileFormatJSON).Encode(vex)
		if err != nil {
			return err
		}

		// upload the vex
		vexResp, err := uploadVEX(vexBuff)
		if err != nil {
			slog.Error("could not upload vex", "err", err)
		} else {
			defer vexResp.Body.Close()
			if vexResp.StatusCode != http.StatusOK {
				slog.Error("could not upload vex", "status", vexResp.Status)
			} else {
				slog.Info("uploaded vex successfully")
			}
		}
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
	var scanResponse scan.ScanResponse
	err = json.NewDecoder(resp.Body).Decode(&scanResponse)
	if err != nil {
		return errors.Wrap(err, "could not parse response")
	}

	err = printScaResults(scanResponse, config.RuntimeBaseConfig.FailOnRisk, config.RuntimeBaseConfig.FailOnCVSS, config.RuntimeBaseConfig.AssetName, config.RuntimeBaseConfig.WebUI)
	if err != nil {
		return err
	}
	return nil
}

func uploadVEX(vex io.Reader) (*http.Response, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/api/v1/vex", config.RuntimeBaseConfig.APIURL), vex)
	if err != nil {
		return nil, errors.Wrap(err, "could not create request")
	}

	err = pat.SignRequest(config.RuntimeBaseConfig.Token, req)
	if err != nil {
		return nil, errors.Wrap(err, "could not sign request")
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Scanner", config.RuntimeBaseConfig.ScannerID)
	req.Header.Set("X-Artifact-Name", config.RuntimeBaseConfig.ArtifactName)
	config.SetXAssetHeaders(req)

	return http.DefaultClient.Do(req)
}

func uploadBOM(bom io.Reader) (*http.Response, context.CancelFunc, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)

	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/api/v1/scan", config.RuntimeBaseConfig.APIURL), bom)
	if err != nil {
		return nil, cancel, errors.Wrap(err, "could not create request")
	}

	err = pat.SignRequest(config.RuntimeBaseConfig.Token, req)
	if err != nil {
		return nil, cancel, errors.Wrap(err, "could not sign request")
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Scanner", config.RuntimeBaseConfig.ScannerID)
	req.Header.Set("X-Artifact-Name", config.RuntimeBaseConfig.ArtifactName)
	config.SetXAssetHeaders(req)

	resp, err := http.DefaultClient.Do(req)
	return resp, cancel, err
}

func scaCommand(cmd *cobra.Command, args []string) error {

	ctx := cmd.Context()

	// in case it's a docker image we need to scan the image and try to download attestations
	if config.RuntimeBaseConfig.Image != "" {
		return scanExternalImage()
	}

	// read the sbom file and post it to the scan endpoint
	// get the dependencyVulns and print them to the console
	file, err := generateSBOM(ctx, config.RuntimeBaseConfig.Path, false)
	if err != nil {
		return errors.Wrap(err, "could not open file")
	}

	resp, cancel, err := uploadBOM(bytes.NewBuffer(file))
	if err != nil {
		return errors.Wrap(err, "could not send request")
	}
	defer cancel()
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

	return printScaResults(scanResponse, config.RuntimeBaseConfig.FailOnRisk, config.RuntimeBaseConfig.FailOnCVSS, config.RuntimeBaseConfig.AssetName, config.RuntimeBaseConfig.WebUI)
}

func NewSCACommand() *cobra.Command {
	scaCommand := &cobra.Command{
		Use:   "sca",
		Short: "Start a Software composition analysis",
		Long:  `Scan an application for vulnerabilities. This command will generate a sbom, upload it to devguard and scan it for vulnerabilities.`,
		// Args:  cobra.ExactArgs(0),
		RunE: scaCommand,
	}

	addScanFlags(scaCommand)
	return scaCommand
}
