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
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/cmd/devguard-scanner/config"
	"github.com/l3montree-dev/devguard/cmd/devguard-scanner/scanner"
	"github.com/l3montree-dev/devguard/compliance"
	"github.com/l3montree-dev/devguard/utils"

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
	// check if policyPath is an url - if so, download it first
	if strings.HasPrefix(policyPath, "http://") || strings.HasPrefix(policyPath, "https://") {
		req, err := http.NewRequestWithContext(cmd.Context(), "GET", policyPath, nil)
		if err != nil {
			return fmt.Errorf("could not create request to download policy: %w", err)
		}
		content, err := utils.EgressClient.Do(req)
		if err != nil {
			return fmt.Errorf("could not download policy: %w", err)
		}
		defer content.Body.Close()
		if content.StatusCode != http.StatusOK {
			return fmt.Errorf("could not download policy: received status code %d", content.StatusCode)
		}
		body, err := io.ReadAll(content.Body)
		if err != nil {
			return fmt.Errorf("could not read policy content: %w", err)
		}
		policyPath = os.TempDir() + "/" + uuid.New().String() + ".rego"
		if err := os.WriteFile(policyPath, body, 0o644); err != nil {
			return fmt.Errorf("could not write policy to temp file: %w", err)
		}
		defer os.Remove(policyPath)
	}

	sarifResult, evals, err := scanner.EvaluatePolicyAgainstAttestations(image, policyPath, attestations)
	if err != nil {
		return err
	}

	var output []byte
	type evalOutput struct {
		Violations          []string       `json:"violations"`
		Compliant           *bool          `json:"compliant"`
		RawEvaluationResult map[string]any `json:"rawEvaluationResult"`
	}
	switch config.RuntimeBaseConfig.Format {
	case "plain":

		b, err := json.MarshalIndent(utils.Map(evals, func(e compliance.PolicyEvaluation) evalOutput {
			return evalOutput{
				Violations:          e.Violations,
				Compliant:           e.Compliant,
				RawEvaluationResult: e.RawEvaluationResult,
			}
		}), "", "  ")
		if err != nil {
			return fmt.Errorf("could not marshal evaluations: %w", err)
		}
		output = b
	case "sarif":
		b, err := json.MarshalIndent(sarifResult, "", "  ")
		if err != nil {
			return fmt.Errorf("could not marshal SARIF result: %w", err)
		}
		output = b
	}

	if config.RuntimeBaseConfig.OutputPath != "" {
		if err := os.WriteFile(config.RuntimeBaseConfig.OutputPath, output, 0o644); err != nil {
			return fmt.Errorf("could not write sarif report: %w", err)
		}
		slog.Info("SARIF report saved", "path", config.RuntimeBaseConfig.OutputPath)
	}

	_, err = os.Stdout.Write(append(output, '\n'))
	// check if some eval was wrong - if so, exit 1
	for _, eval := range evals {
		if eval.Compliant != nil && !*eval.Compliant {
			os.Exit(1)
		}
	}
	return err
}

func NewAttestationCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "attestations <oci@SHA>",
		Short:             "Discover attestations for an image and optionally evaluate a rego policy",
		DisableAutoGenTag: true,
		Long: `Retrieve all attestations (metadata documents) attached to a container image and optionally evaluate them against a Rego policy.

Attestations are documents attached to the image during its build pipeline — for example an SBOM,
a VEX document (vulnerability exceptions), or SARIF security scan results. Each attestation has a
predicate type (a URI) that identifies its kind. The policy receives all discovered attestations
and can match against specific predicate types to check that required metadata is present.

Example Rego policy that requires an SBOM and a VEX document:

  package devguard

  import future.keywords.if
  import future.keywords.in

  deny[msg] if {
    not has_attestation("https://cyclonedx.org/bom")
    msg := "Image is missing a CycloneDX SBOM attestation"
  }

  deny[msg] if {
    not has_attestation("https://cyclonedx.org/vex")
    msg := "Image is missing a VEX document"
  }

  has_attestation(predicate_type) if {
    some att in input.attestations
    att.predicateType == predicate_type
  }

The command exits with code 1 if any deny rule fires — making it suitable as a deployment gate.`,
		Example: `  # List all attestations attached to an image
  devguard-scanner attestations ghcr.io/org/image:tag

  # Evaluate against a Rego policy (exits 1 if policy fails)
  devguard-scanner attestations ghcr.io/org/image:tag --policy policy.rego

  # Save evaluation results as SARIF for upload to DevGuard
  devguard-scanner attestations ghcr.io/org/image:tag --policy policy.rego --format sarif --outputPath report.sarif.json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return attestationsCmd(cmd, args)
		},
		Annotations: map[string]string{
			"title":           "DevGuard-Scanner attestations — Discover and evaluate image attestations",
			"description":     "Discover all attestations attached to a container image and optionally evaluate them against a Rego policy with devguard-scanner attestations.",
			"keyword_primary": "devguard-scanner attestations",
		},
	}

	scanner.AddDefaultFlags(cmd)
	scanner.AddAssetRefFlags(cmd)
	cmd.Flags().StringP("policy", "p", "", "check the images attestations against policy")
	cmd.Flags().String("outputPath", "", "Path to save the generated report. If not provided, the report is only printed.")
	cmd.Flags().String("format", "plain", "Format of the report to generate (plain, sarif). Default is plain")

	// allow username, password and registry to be provided as well as flags
	return cmd
}
