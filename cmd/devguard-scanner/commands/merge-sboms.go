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
		Use:   "merge-sboms <config file>",
		Short: "Merge multiple SBOMs into one SBOM",
		Long:  `Merge multiple SBOMs into one SBOM`,
		RunE:  runMergeSBOMs,
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
	json.Unmarshal(fileContent, &config)

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

		merged := append(*result.Components, *bom.Components...)
		result.Components = &merged
		// add a dependency from the main purl to the sbom purl
		*rootDependencies.Dependencies = append(*rootDependencies.Dependencies, bom.Metadata.Component.BOMRef)

		*result.Dependencies = append(*result.Dependencies, *bom.Dependencies...)
	}

	*result.Dependencies = append(*result.Dependencies, rootDependencies)
	// print the sbom to stdout
	encoder := cyclonedx.NewBOMEncoder(os.Stdout, cyclonedx.BOMFileFormatJSON)
	encoder.SetPretty(true)
	err := encoder.Encode(result)
	if err != nil {
		return err
	}
	return nil
}
