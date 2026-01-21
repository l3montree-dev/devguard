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
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/cmd/devguard-scanner/config"
	"github.com/l3montree-dev/devguard/cmd/devguard-scanner/scanner"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/package-url/packageurl-go"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

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
		workDir = utils.GetDirFromPath(pathOrImage)
	}
	sbomFile := filepath.Join(workDir, filename)

	var trivyCmd *exec.Cmd
	if isImage {
		image := pathOrImage
		// login in to docker registry first before we try to run trivy
		err := scanner.MaybeLoginIntoOciRegistry(ctx)
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
		trivyCmd = exec.Command("trivy", "image", "--input", pathOrImage, "--format", "cyclonedx", "--output", sbomFile) // nolint:all // 	There is no security issue right here. This runs on the client. You are free to attack yourself.
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

func scanExternalImage(ctx context.Context) error {
	var err error
	var attestations = []map[string]any{}
	if !config.RuntimeBaseConfig.IgnoreUpstreamAttestations {
		// download and extract release attestation BOMs first
		attestations, err = scanner.DiscoverAttestations(config.RuntimeBaseConfig.Image, "")
		if err != nil && !strings.Contains(err.Error(), "found no attestations") {
			return err
		}
	}

	// generate SBOM using Trivy
	file, err := generateSBOM(ctx, config.RuntimeBaseConfig.Image, true)
	if err != nil {
		return err
	}

	// load sbom that was generated in the line above
	bom, err := scanner.BomFromBytes(file)
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
			vex, err = scanner.BomFromBytes(predicateBytes)
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
	err = cyclonedx.NewBOMEncoder(buff, cyclonedx.BOMFileFormatJSON).SetEscapeHTML(false).Encode(bom)
	if err != nil {
		return err
	}

	// upload the bom to the scan endpoint
	resp, cancel, err := scanner.UploadBOM(buff)

	if err != nil {
		return errors.Wrap(err, "could not send request")
	}
	defer cancel()
	defer resp.Body.Close()

	// check if we can upload a vex as well
	if vex != nil {
		vexBuff := &bytes.Buffer{}
		// marshal the bom back to json
		err = cyclonedx.NewBOMEncoder(vexBuff, cyclonedx.BOMFileFormatJSON).SetEscapeHTML(false).Encode(vex)
		if err != nil {
			return err
		}

		config.RuntimeBaseConfig.Origin = "vex:" + config.RuntimeBaseConfig.Origin
		// upload the vex
		// but it is not from upstream - it is the image we are currently looking at.
		vexResp, err := scanner.UploadVEX(vexBuff)
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
	var scanResponse dtos.ScanResponse
	err = json.NewDecoder(resp.Body).Decode(&scanResponse)
	if err != nil {
		return errors.Wrap(err, "could not parse response")
	}

	err = scanner.PrintScaResults(scanResponse, config.RuntimeBaseConfig.FailOnRisk, config.RuntimeBaseConfig.FailOnCVSS, config.RuntimeBaseConfig.AssetName, config.RuntimeBaseConfig.WebUI)
	if err != nil {
		return err
	}
	return nil
}

func scanLocalFilePath(ctx context.Context) error {
	// check if sbom file or need to generate sbom
	var file []byte
	var err error
	if strings.HasSuffix(config.RuntimeBaseConfig.Path, ".json") {
		// read the sbom file and post it to the scan endpoint
		file, err = os.ReadFile(config.RuntimeBaseConfig.Path)
		if err != nil {
			return errors.Wrap(err, "could not read file")
		}
	} else {
		// generate SBOM using Trivy
		file, err = generateSBOM(ctx, config.RuntimeBaseConfig.Path, false)
		if err != nil {
			return errors.Wrap(err, "could not open file")
		}
	}

	resp, cancel, err := scanner.UploadBOM(bytes.NewBuffer(file))
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
	var scanResponse dtos.ScanResponse

	err = json.NewDecoder(resp.Body).Decode(&scanResponse)
	if err != nil {
		return errors.Wrap(err, "could not parse response")
	}

	return scanner.PrintScaResults(scanResponse, config.RuntimeBaseConfig.FailOnRisk, config.RuntimeBaseConfig.FailOnCVSS, config.RuntimeBaseConfig.AssetName, config.RuntimeBaseConfig.WebUI)
}

func scaCommand(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	if len(args) > 0 && args[0] != "" && strings.Contains(args[0], ":") {
		config.RuntimeBaseConfig.Image = args[0]
	} else if len(args) > 0 && args[0] != "" && strings.Contains(args[0], ".tar") {
		config.RuntimeBaseConfig.Path = args[0]
	}

	// in case it's a docker image we need to scan the image and try to download attestations
	if config.RuntimeBaseConfig.Image != "" {
		return scanExternalImage(ctx)
	} else if config.RuntimeBaseConfig.Path != "" {
		return scanLocalFilePath(ctx)
	}
	return fmt.Errorf("either --image or --path must be specified, or passed as an argument")
}

func NewSCACommand() *cobra.Command {
	scaCommand := &cobra.Command{
		Use:               "sca [image|path]",
		Short:             "Run Software Composition Analysis (SCA)",
		DisableAutoGenTag: true,
		Long: `Run a Software Composition Analysis (SCA) for a project or container image.

This command can accept either an OCI image reference (e.g. ghcr.io/org/image:tag) via
--image or as the first positional argument, or a local path/tar file via --path or as
the first positional argument. The command will generate or accept an SBOM, upload it to
DevGuard and return vulnerability results.`,
		Example: `  # Scan a container image
  devguard-scanner sca ghcr.io/org/image:tag

  # Scan a local project directory
  devguard-scanner sca ./path/to/project

  # Scan with custom asset name
  devguard-scanner sca --image ghcr.io/org/image:tag --assetName my-app

  # Scan and fail on high risk vulnerabilities
  devguard-scanner sca ./project --failOnRisk high`,
		RunE: scaCommand,
	}

	scanner.AddDependencyVulnsScanFlags(scaCommand)
	scaCommand.Flags().String("path", "", "Path to the project directory or tar file to scan. If empty, the first argument must be provided.")
	return scaCommand
}
