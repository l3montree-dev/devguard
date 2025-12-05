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

	if policyPath == "" {
		output, err := json.MarshalIndent(attestations, "", "  ")
		if err != nil {
			return fmt.Errorf("could not marshal attestations: %w", err)
		}

		if config.RuntimeBaseConfig.OutputPath != "" {
			if err := os.WriteFile(config.RuntimeBaseConfig.OutputPath, output, 0o644); err != nil {
				return fmt.Errorf("could not write attestation report: %w", err)
			}
			slog.Info("Attestation report saved", "path", config.RuntimeBaseConfig.OutputPath)
		}

		_, err = os.Stdout.Write(output)
		return err
	}

	return fmt.Errorf("test")
}

func NewAttestationCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "attestations <oci@SHA>",
		Short: "Discover attestations for an image and optionally evaluate a Rego policy",
		Long: `Discover and inspect security attestations (e.g. SBOM, VEX, SARIF) attached to an OCI image.

Without --policy the command prints all discovered attestations as JSON. With --policy (implemented in following steps)
attestations can be evaluated against a local Rego policy.

Examples:
	devguard-scanner attestations ghcr.io/org/image:tag
	devguard-scanner attestations ghcr.io/org/image:tag --outputPath attestations.json
`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return attestationsCmd(cmd, args)
		},
	}

	scanner.AddDefaultFlags(cmd)
	scanner.AddAssetRefFlags(cmd)
	cmd.Flags().StringP("policy", "p", "", "Optional path to a Rego policy file to evaluate against discovered attestations (coming in a later step).")
	cmd.Flags().String("outputPath", "", "Path to save the discovered attestations JSON. If not provided, the result is only printed.")

	return cmd
}
