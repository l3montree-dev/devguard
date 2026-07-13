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
	"github.com/l3montree-dev/devguard/normalize"
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
	sbomFile := filepath.Join(os.TempDir(), filename)

	var trivyCmd *exec.Cmd

	var configFileArgs []string
	if config.RuntimeBaseConfig.ConfigFilePath != "" {
		configFileArgs = []string{"--config", config.RuntimeBaseConfig.ConfigFilePath}
	}

	if isImage {
		image := pathOrImage
		// login in to docker registry first before we try to run trivy
		err := scanner.MaybeLoginIntoOciRegistry(ctx)
		if err != nil {
			return nil, err
		}

		slog.Info("scanning oci image", "image", image)
		args := []string{"image", image, "--format", "cyclonedx", "--output", sbomFile}
		args = append(args, configFileArgs...)
		args = append(args, config.RuntimeExtraArgs...)

		trivyCmd = exec.Command("trivy", args...) // nolint:all // 	There is no security issue right here. This runs on the client. You are free to attack yourself.
	} else if isDir {
		slog.Info("scanning directory", "dir", workDir)
		prepareTrivyCommand(workDir)
		args := []string{"fs", ".", "--format", "cyclonedx", "--output", sbomFile}
		args = append(args, configFileArgs...)
		args = append(args, config.RuntimeExtraArgs...)
		// scanning a directory - we need to switch to the directory first because trivy needs to run in the context of the project to be able to find the dependencies
		trivyCmd = exec.Command("trivy", args...) // nolint:all // 	There is no security issue right here. This runs on the client. You are free to attack yourself.
		trivyCmd.Dir = workDir
	} else {
		slog.Info("scanning single file", "file", maybeFilename)
		args := []string{"image", "--input", pathOrImage, "--format", "cyclonedx", "--output", sbomFile}
		args = append(args, configFileArgs...)
		args = append(args, config.RuntimeExtraArgs...)

		// scanning a single file
		// cdxgenCmd = exec.Command("cdxgen", maybeFilename, "-o", filename)
		trivyCmd = exec.Command("trivy", args...) // nolint:all // 	There is no security issue right here. This runs on the client. You are free to attack yourself.
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

// discoverAndMergeSupplementarySBOMs runs discover to find supplementary SBOMs (a
// directory walk or an image filesystem search, depending on the caller) and, if any
// are found, merges them into bom's root component. A discovery failure is logged and
// treated as "none found" rather than failing the scan. After merging, any
// "application" type component not covered by a supplementary SBOM is logged as a
// warning.
func discoverAndMergeSupplementarySBOMs(bom *cyclonedx.BOM, discover func() ([]*cyclonedx.BOM, error)) error {
	extras, err := discover()
	if err != nil {
		slog.Warn("could not scan for supplementary SBOMs", "sbomPath", config.RuntimeBaseConfig.SBOMPath, "err", err)
		return nil
	}
	for _, extra := range extras {
		if extra.Metadata != nil && extra.Metadata.Component != nil {
			slog.Info("found supplementary SBOM", "path", extra.Metadata.Component.Name)
		}
	}
	// Must run before merging: components with no PackageURL get silently
	// dropped by the graph the merge builds (see
	// normalize.SBOMGraphFromCycloneDX), so this is the last point where the
	// component is still present in bom to warn about.
	warnAboutUnidentifiableComponents(bom, extras)
	if len(extras) > 0 {
		if err := mergeSupplementarySBOMs(bom, extras); err != nil {
			return errors.Wrap(err, "could not merge supplementary SBOMs")
		}
	}
	return nil
}

// warnAboutUnidentifiableComponents warns about "application" components with
// no purl, no supplementary SBOM, and no resolved dependency tree - these get
// dropped and reparented during merging, producing an incomplete SBOM.
func warnAboutUnidentifiableComponents(bom *cyclonedx.BOM, extras []*cyclonedx.BOM) {
	if bom.Components == nil {
		return
	}

	suppliedPaths := make(map[string]bool, len(extras))
	for _, extra := range extras {
		if extra.Metadata != nil && extra.Metadata.Component != nil {
			suppliedPaths[extra.Metadata.Component.Name] = true
		}
	}

	childrenByRef := dependencyChildrenByRef(bom.Dependencies)
	realDescendantCache := make(map[string]bool)

	var enriched, unresolved int
	for _, c := range *bom.Components {
		if c.Type != cyclonedx.ComponentTypeApplication {
			continue
		}
		if c.PackageURL != "" || hasVersionedDescendant(c.BOMRef, childrenByRef, realDescendantCache) {
			continue // trivy already resolved this one, no action needed
		}
		if suppliedPaths[c.Name] {
			enriched++
			continue
		}
		unresolved++
		slog.Warn("found an application component with no package identity (purl); it and everything it depends on will be dropped from the dependency graph and reparented to the nearest ancestor with a valid identity, producing an incomplete SBOM - provide a supplementary SBOM describing it (rooted at this exact path) under --sbomPath to fix this", "path", c.Name)
		printSupplementarySBOMExample(c.Name)
	}

	if enriched > 0 || unresolved > 0 {
		slog.Info("application component resolution", "enrichedBySupplementarySBOM", enriched, "unresolved", unresolved)
	}
}

// dependencyChildrenByRef indexes a dependency list by ref.
func dependencyChildrenByRef(deps *[]cyclonedx.Dependency) map[string][]string {
	childrenByRef := make(map[string][]string)
	if deps == nil {
		return childrenByRef
	}
	for _, d := range *deps {
		if d.Dependencies != nil {
			childrenByRef[d.Ref] = *d.Dependencies
		}
	}
	return childrenByRef
}

// hasVersionedDescendant reports whether ref has a versioned purl (pkg:...@version)
// anywhere in its dependency subtree, not just among its direct children - trivy
// often nests real deps under an intermediate unversioned node (e.g. go.mod ->
// unversioned main module -> real go.sum deps).
func hasVersionedDescendant(ref string, childrenByRef map[string][]string, cache map[string]bool) bool {
	return hasVersionedDescendantVisiting(ref, childrenByRef, cache, map[string]bool{ref: true})
}

func hasVersionedDescendantVisiting(ref string, childrenByRef map[string][]string, cache map[string]bool, visited map[string]bool) bool {
	if v, ok := cache[ref]; ok {
		return v
	}
	result := false
	for _, child := range childrenByRef[ref] {
		if visited[child] {
			continue
		}
		visited[child] = true
		if strings.HasPrefix(child, "pkg:") && strings.Contains(child, "@") {
			result = true
			break
		}
		if hasVersionedDescendantVisiting(child, childrenByRef, cache, visited) {
			result = true
			break
		}
	}
	cache[ref] = result
	return result
}

// printSupplementarySBOMExample prints a ready-to-use, copy-pasteable
// supplementary SBOM for the given in-image/in-project path, to stderr so it
// doesn't get mixed into piped SBOM/log output. The root component's
// bom-ref/name must exactly match path - that's what devguard-scanner's
// --sbomPath discovery matches on. "components"/"dependencies" are optional;
// this example includes one library child to show the shape.
func printSupplementarySBOMExample(path string) {
	example := struct {
		BOMFormat    string                 `json:"bomFormat"`
		SpecVersion  string                 `json:"specVersion"`
		Metadata     cyclonedx.Metadata     `json:"metadata"`
		Components   []cyclonedx.Component  `json:"components"`
		Dependencies []cyclonedx.Dependency `json:"dependencies"`
	}{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.7",
		Metadata: cyclonedx.Metadata{
			Component: &cyclonedx.Component{
				Type:   cyclonedx.ComponentTypeApplication,
				BOMRef: path,
				Name:   path,
			},
		},
		Components: []cyclonedx.Component{
			{
				Type:       cyclonedx.ComponentTypeLibrary,
				BOMRef:     "pkg:golang/example.org/some/module@v1.2.3",
				PackageURL: "pkg:golang/example.org/some/module@v1.2.3",
				Name:       "example.org/some/module",
				Version:    "v1.2.3",
			},
		},
		Dependencies: []cyclonedx.Dependency{
			{Ref: path, Dependencies: &[]string{"pkg:golang/example.org/some/module@v1.2.3"}},
		},
	}
	out, err := json.MarshalIndent(example, "", "  ")
	if err != nil {
		return
	}
	fmt.Fprintf(os.Stderr, "save this as a .json file under --sbomPath (default /sboms) to describe %q:\n%s\n", path, out)
}

// mergeSupplementarySBOMs enriches bom's dependency graph with each extra,
// via normalize.SBOMGraph.EnrichSBOM (see there for exact replace-vs-attach
// semantics). bom.Metadata.Component itself is left untouched; only
// Components/Dependencies are replaced with the enriched graph's exported
// view (via ToCycloneDX, reusing bom's own root identity through RootName) -
// the root's own entry in Dependencies (its declared children) is kept, but
// the root component itself is dropped from the returned Components slice,
// since it's already represented by Metadata.Component.
//
// Each extra can carry its own top-level ExternalReferences (e.g. a link to
// that specific binary's VEX document) - those are merged into bom's own
// top-level ExternalReferences, since that's the only place the backend
// looks for VEX URLs to auto-fetch (see controllers/scan_controller.go's
// bom.ExternalReferences scan).
func mergeSupplementarySBOMs(bom *cyclonedx.BOM, extras []*cyclonedx.BOM) error {
	rootRef := bom.Metadata.Component.BOMRef

	g, err := normalize.SBOMGraphFromCycloneDX(bom, "cli-scan", "cli-scan")
	if err != nil {
		return errors.Wrap(err, "could not build SBOM graph")
	}

	for _, extra := range extras {
		isNew, err := g.EnrichSBOM(extra, rootRef)
		if err != nil {
			return err
		}
		if isNew {
			slog.Info("enrichment attached a new node under the scan root", "path", extra.Metadata.Component.Name)
		} else {
			slog.Info("enrichment replaced an existing component's subtree", "path", extra.Metadata.Component.Name)
		}
		if extra.ExternalReferences != nil {
			mergeExternalReferences(bom, *extra.ExternalReferences)
		}
	}

	exported := g.ToCycloneDX(normalize.BOMMetadata{RootName: rootRef})
	filtered := make([]cyclonedx.Component, 0, len(*exported.Components))
	for _, c := range *exported.Components {
		if c.BOMRef == rootRef {
			continue
		}
		filtered = append(filtered, c)
	}

	bom.Components = &filtered
	bom.Dependencies = exported.Dependencies
	return nil
}

// mergeExternalReferences appends refs to bom's top-level ExternalReferences,
// skipping any (type, URL) pair already present.
func mergeExternalReferences(bom *cyclonedx.BOM, refs []cyclonedx.ExternalReference) {
	existing := map[cyclonedx.ExternalReference]bool{}
	if bom.ExternalReferences != nil {
		for _, ref := range *bom.ExternalReferences {
			existing[cyclonedx.ExternalReference{Type: ref.Type, URL: ref.URL}] = true
		}
	} else {
		bom.ExternalReferences = &[]cyclonedx.ExternalReference{}
	}
	for _, ref := range refs {
		key := cyclonedx.ExternalReference{Type: ref.Type, URL: ref.URL}
		if existing[key] {
			continue
		}
		existing[key] = true
		*bom.ExternalReferences = append(*bom.ExternalReferences, ref)
	}
}

// writeSBOMIfRequested saves the final SBOM to config.RuntimeBaseConfig.SBOMOutputPath,
// if set. It is a no-op otherwise.
func writeSBOMIfRequested(bom []byte) error {
	if config.RuntimeBaseConfig.SBOMOutputPath == "" {
		return nil
	}
	if err := os.WriteFile(config.RuntimeBaseConfig.SBOMOutputPath, bom, 0644); err != nil {
		return errors.Wrap(err, "could not write SBOM output file")
	}
	slog.Info("wrote SBOM to file", "path", config.RuntimeBaseConfig.SBOMOutputPath)
	return nil
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

	if err := discoverAndMergeSupplementarySBOMs(bom, func() ([]*cyclonedx.BOM, error) {
		img, err := scanner.LoadRemoteImage(ctx, config.RuntimeBaseConfig.Image)
		if err != nil {
			return nil, err
		}
		return scanner.DiscoverSupplementarySBOMsInImage(img, config.RuntimeBaseConfig.SBOMPath)
	}); err != nil {
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
				// slog.Warn("could not parse purl", "purl", purl, "err", err) // this log spams the output and is not useful for the user. We can ignore it.
				continue
			}

			bom.Components = new(append(*bom.Components, cyclonedx.Component{
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

	if err := writeSBOMIfRequested(buff.Bytes()); err != nil {
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

	return handleScanResponse(resp.Body)
}

// discoverSupplementarySBOMsForPath finds supplementary SBOMs for a local
// scan target: a directory (walked under sbomPath), or a single non-JSON
// file, which is assumed to be an OCI image tarball (its filesystem is
// searched for sbomPath).
func discoverSupplementarySBOMsForPath(pathOrTar, sbomPath string) ([]*cyclonedx.BOM, error) {
	_, isDir := maybeGetFileName(pathOrTar)
	if isDir {
		return scanner.DiscoverSupplementarySBOMsInDir(filepath.Join(pathOrTar, sbomPath))
	}

	img, cleanup, err := scanner.LoadImageFromTarball(pathOrTar)
	defer cleanup()
	if err != nil {
		return nil, err
	}
	return scanner.DiscoverSupplementarySBOMsInImage(img, sbomPath)
}

func scanLocalFilePath(ctx context.Context) error {
	// check if sbom file or need to generate sbom
	var file []byte
	var err error
	isJSON := strings.HasSuffix(config.RuntimeBaseConfig.Path, ".json")
	if isJSON {
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

	if !isJSON {
		bom, err := scanner.BomFromBytes(file)
		if err != nil {
			return err
		}

		if err := discoverAndMergeSupplementarySBOMs(bom, func() ([]*cyclonedx.BOM, error) {
			return discoverSupplementarySBOMsForPath(config.RuntimeBaseConfig.Path, config.RuntimeBaseConfig.SBOMPath)
		}); err != nil {
			return err
		}

		buff := &bytes.Buffer{}
		if err := cyclonedx.NewBOMEncoder(buff, cyclonedx.BOMFileFormatJSON).SetEscapeHTML(false).Encode(bom); err != nil {
			return err
		}
		file = buff.Bytes()
	}

	if err := writeSBOMIfRequested(file); err != nil {
		return err
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

	return handleScanResponse(resp.Body)
}

func handleScanResponse(body io.Reader) error {
	// Read the body once so we can use it for both output modes.
	bodyBytes, err := io.ReadAll(body)
	if err != nil {
		return errors.Wrap(err, "could not read scan response")
	}

	output := strings.ToLower(config.RuntimeBaseConfig.Output)
	if output == "cyclonedx" {
		_, err := os.Stdout.Write(bodyBytes)
		return err
	}

	var bom cyclonedx.BOM
	if err := cyclonedx.NewBOMDecoder(bytes.NewReader(bodyBytes), cyclonedx.BOMFileFormatJSON).Decode(&bom); err != nil {
		return errors.Wrap(err, "could not parse CycloneDX VEX response")
	}
	return scanner.PrintCycloneDXVexResults(bom, config.RuntimeBaseConfig.FailOnRisk, config.RuntimeBaseConfig.FailOnCVSS, config.RuntimeBaseConfig.AssetName, config.RuntimeBaseConfig.WebUI, config.RuntimeBaseConfig.Ref)
}

func scaCommand(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	args, config.RuntimeExtraArgs = splitPassthroughArgs(cmd, args)
	if len(args) > 0 && args[0] != "" && strings.Contains(args[0], ":") {
		config.RuntimeBaseConfig.Image = args[0]
	} else if len(args) > 0 && args[0] != "" {
		config.RuntimeBaseConfig.Path = args[0]
	}

	if config.RuntimeBaseConfig.AssetName != "" && config.RuntimeBaseConfig.Token != "" {
		// download any config file if exists
		configFilePath, err := config.GetAndWriteConfigFile(ctx, "trivy.yaml", config.RuntimeBaseConfig.AssetName)
		if err != nil {
			slog.Warn("could not get config file, using default trivy config", "file", "trivy.yaml", "err", err)
		} else {
			// set the config file path in the runtime config so that it can be used by the scanner commands
			config.RuntimeBaseConfig.ConfigFilePath = configFilePath
		}
	}

	// in case it's a docker image we need to scan the image and try to download attestations
	if config.RuntimeBaseConfig.Image != "" {
		return scanExternalImage(ctx)
	} else if config.RuntimeBaseConfig.Path != "" {
		return scanLocalFilePath(ctx)
	}
	// default to scan current directory
	config.RuntimeBaseConfig.Path = "."
	return scanLocalFilePath(ctx)
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
DevGuard and return vulnerability results.

Any flags after a "--" separator are forwarded verbatim to the underlying trivy invocation.
See the trivy CLI reference for available flags: https://trivy.dev/docs/latest/guide/references/configuration/cli/trivy/`,
		Example: `  # Scan a container image
  devguard-scanner sca ghcr.io/org/image:tag

  # Scan a local project directory
  devguard-scanner sca ./path/to/project

  # Scan with custom asset name
  devguard-scanner sca --image ghcr.io/org/image:tag --assetName my-app --token YOUR_TOKEN

  # Scan and fail on high risk vulnerabilities
  devguard-scanner sca ./project --failOnRisk high

  # Forward extra flags to trivy
  devguard-scanner sca ./project -- --skip-dirs vendor --timeout 10m`,
		RunE: scaCommand,
	}

	scanner.AddDependencyVulnsScanFlags(scaCommand)
	scaCommand.Flags().String("path", "", "Path to the project directory or tar file to scan. If empty, the first argument must be provided.")
	scanner.AddSupplementarySBOMFlags(scaCommand)
	return scaCommand
}
