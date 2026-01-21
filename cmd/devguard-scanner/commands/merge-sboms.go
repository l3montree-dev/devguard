/*
Copyright The ORAS Authors.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package commands

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/spf13/cobra"
)

type MergeSBOMsConfigFile struct {
	Purl  string   `json:"purl"`
	SBOMs []string `json:"sboms"`
}

func NewMergeSBOMSCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "merge-sboms <config file>",
		Short:             "Merge multiple SBOMs into one SBOM",
		DisableAutoGenTag: true,
		Long: `Merge multiple CycloneDX SBOMs into a single SBOM.

The command expects a JSON configuration file with the target purl and a list
of SBOM file paths to merge. The merged SBOM is written to stdout in pretty JSON.

Example config file:
  { "purl": "pkg:foo/bar@1.2.3", "sboms": ["a.json", "b.json"] }`,
		Example: `  # Merge SBOMs using config file
  devguard-scanner merge-sboms config.json

  # Redirect output to file
  devguard-scanner merge-sboms config.json > merged-sbom.json`,
		RunE: runMergeSBOMs,
	}

	return cmd
}

func runMergeSBOMs(cmd *cobra.Command, args []string) error {
	filePath := args[0]
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return err
	}

	slog.Info("Merging SBOMs from config file", "filePath", filePath)
	// read the json file and parse it
	fileContent, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}
	var config MergeSBOMsConfigFile
	if err := json.Unmarshal(fileContent, &config); err != nil {
		return err
	}

	return mergeSBOMs(cmd.Context(), config.Purl, config.SBOMs)
}

func mergeSBOMs(ctx context.Context, purl string, sboms []string) error {
	// read all cyclonedx sboms
	result := cyclonedx.NewBOM()
	// we can already set the metadata
	result.Metadata = &cyclonedx.Metadata{
		Component: &cyclonedx.Component{
			Type:       cyclonedx.ComponentTypeApplication,
			BOMRef:     purl,
			PackageURL: purl,
			Name:       purl,
		},
	}
	result.Components = &[]cyclonedx.Component{}
	result.Dependencies = &[]cyclonedx.Dependency{}

	rootDependencies := cyclonedx.Dependency{
		Ref:          purl,
		Dependencies: &[]string{},
	}
	for _, sbom := range sboms {
		slog.Info("Reading SBOM", "path", sbom)
		c, err := os.Open(sbom)
		if err != nil {
			return err
		}

		var bom cyclonedx.BOM
		if err := cyclonedx.NewBOMDecoder(c, cyclonedx.BOMFileFormatJSON).Decode(&bom); err != nil {
			return err
		}

		if bom.Metadata == nil || bom.Metadata.Component == nil {
			slog.Warn("SBOM has no metadata or component, skipping", "path", sbom)
			continue
		}

		if bom.Components != nil {
			merged := append(*result.Components, *bom.Components...)
			result.Components = &merged
		}
		// add a dependency from the main purl to the sbom purl, if the BOMRef is non-empty
		if bom.Metadata.Component.BOMRef != "" {
			*rootDependencies.Dependencies = append(*rootDependencies.Dependencies, bom.Metadata.Component.BOMRef)
		}

		if bom.Dependencies != nil {
			*result.Dependencies = append(*result.Dependencies, *bom.Dependencies...)
		}
	}

	*result.Dependencies = append(*result.Dependencies, rootDependencies)
	// print the sbom to stdout
	encoder := cyclonedx.NewBOMEncoder(os.Stdout, cyclonedx.BOMFileFormatJSON)
	encoder.SetPretty(true)
	encoder.SetEscapeHTML(false)
	err := encoder.Encode(result)
	if err != nil {
		return err
	}
	return nil
}
