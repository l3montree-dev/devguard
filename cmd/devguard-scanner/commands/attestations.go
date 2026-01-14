// Copyright (C) 2025 l3montree GmbH
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
	"encoding/json"
	"fmt"
	"log/slog"
	"os"

	"github.com/l3montree-dev/devguard/cmd/devguard-scanner/config"
	"github.com/l3montree-dev/devguard/cmd/devguard-scanner/scanner"

	"github.com/spf13/cobra"
)

func attestationsCmd(cmd *cobra.Command, args []string) error {
	image := args[0]

	if err := scanner.MaybeLoginIntoOciRegistry(cmd.Context()); err != nil {
		return err
	}

	policyPath, _ := cmd.Flags().GetString("policy")

	attestations, err := scanner.DiscoverAttestations(image, "")
	if err != nil {
		return err
	}

	// If no policy was supplied, just print the attestations.
	if policyPath == "" {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(attestations)
	}

	sarifResult, err := scanner.EvaluatePolicyAgainstAttestations(image, policyPath, attestations)
	if err != nil {
		return err
	}

	output, _ := json.MarshalIndent(sarifResult, "", "  ")

	if config.RuntimeBaseConfig.OutputPath != "" {
		if err := os.WriteFile(config.RuntimeBaseConfig.OutputPath, output, 0o644); err != nil {
			return fmt.Errorf("could not write sarif report: %w", err)
		}
		slog.Info("SARIF report saved", "path", config.RuntimeBaseConfig.OutputPath)
	}

	_, err = os.Stdout.Write(output)
	return err
}

func NewAttestationCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "attestations <oci@SHA>",
		Short:             "Discover attestations for an image and optionally evaluate a rego policy",
		DisableAutoGenTag: true,
		Long: `Retrieve and validate security attestations for container images used in Helm charts or other deployment workflows.

It automates what is normally a manual, time-consuming process of verifying that each image is properly hardened and accompanied by essential metadata such as SBOM, VEX, and SARIF.`,
		Example: `  # Discover attestations for an image
  devguard-scanner attestations ghcr.io/org/image:tag

  # Evaluate against a rego policy
  devguard-scanner attestations ghcr.io/org/image:tag --policy path/to/file.rego

  # Save policy evaluation results as SARIF
  devguard-scanner attestations ghcr.io/org/image:tag --policy path/to/file.rego --outputPath report.sarif.json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return attestationsCmd(cmd, args)
		},
	}

	scanner.AddDefaultFlags(cmd)
	scanner.AddAssetRefFlags(cmd)
	cmd.Flags().StringP("policy", "p", "", "check the images attestations against policy")
	cmd.Flags().String("outputPath", "", "Path to save the generated SARIF report. If not provided, the report is only printed.")

	// allow username, password and registry to be provided as well as flags

	return cmd
}
