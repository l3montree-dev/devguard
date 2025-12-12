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
package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/l3montree-dev/devguard/compliance"
	"github.com/l3montree-dev/devguard/dtos/sarif"
	"github.com/l3montree-dev/devguard/utils"
)

func EvaluatePolicyAgainstAttestations(image string, policyPath string, attestations []map[string]any) (*sarif.SarifSchema210Json, error) {
	policyContent, err := os.ReadFile(policyPath)
	if err != nil {
		return nil, fmt.Errorf("could not read policy file: %w", err)
	}

	policy, err := compliance.NewPolicy(filepath.Base(policyPath), string(policyContent))
	if err != nil {
		return nil, fmt.Errorf("could not parse policy: %w", err)
	}

	model := compliance.ConvertPolicyFsToModel(*policy)

	filtered := attestations
	if policy.PredicateType != "" {
		filtered = []map[string]any{}
		for _, attestation := range attestations {
			if predicateType, ok := attestation["predicateType"].(string); ok && predicateType == policy.PredicateType {
				filtered = append(filtered, attestation)
			}
		}
		if len(filtered) == 0 {
			return nil, fmt.Errorf("no attestations found for predicate type %s", policy.PredicateType)
		}
	}

	var evaluations []compliance.PolicyEvaluation
	for _, attestation := range filtered {
		raw, err := json.Marshal(attestation)
		if err != nil {
			return nil, fmt.Errorf("could not marshal attestation: %w", err)
		}

		input, err := utils.ExtractAttestationPayload(string(raw))
		if err != nil {
			return nil, fmt.Errorf("could not extract attestation payload: %w", err)
		}

		evaluations = append(evaluations, compliance.Eval(model, input))
	}

	sarif := buildSarifFromPolicy(image, *policy, evaluations)
	return &sarif, nil
}

func buildSarifFromPolicy(image string, policy compliance.PolicyFS, evaluations []compliance.PolicyEvaluation) sarif.SarifSchema210Json {
	ruleID := policy.Filename
	ruleName := policy.Title

	var helpURI *string
	if len(policy.RelatedResources) > 0 {
		helpURI = &policy.RelatedResources[0]
	}

	rule := sarif.ReportingDescriptor{
		ID:   ruleID,
		Name: &ruleName,
		ShortDescription: &sarif.MultiformatMessageString{
			Text: policy.Title,
		},
		FullDescription: &sarif.MultiformatMessageString{
			Text: policy.Description,
		},
		Help: &sarif.MultiformatMessageString{
			Text: policy.Description,
		},
		HelpURI: helpURI,
		Properties: &sarif.PropertyBag{
			Tags: policy.Tags,
			AdditionalProperties: map[string]any{
				"priority":             policy.Priority,
				"relatedResources":     policy.RelatedResources,
				"complianceFrameworks": policy.ComplianceFrameworks,
				"predicateType":        policy.PredicateType,
			},
		},
	}

	location := func(message string) sarif.Location {
		uri := fmt.Sprintf("oci://%s", image)

		return sarif.Location{
			PhysicalLocation: sarif.PhysicalLocation{
				ArtifactLocation: sarif.ArtifactLocation{
					URI: &uri,
				},
			},
			Message: sarif.Message{
				Text: message,
			},
		}
	}

	var results []sarif.Result
	for _, evaluation := range evaluations {
		if evaluation.Compliant != nil && *evaluation.Compliant {
			// create a pass result
			results = append(results, sarif.Result{
				Kind:   sarif.ResultKindPass,
				RuleID: &ruleID,
				Message: sarif.Message{
					Text: "Policy compliant",
				},
				Locations: []sarif.Location{
					location("The attestation is compliant with the policy."),
				},
				Properties: &sarif.PropertyBag{
					Tags: policy.Tags,
					AdditionalProperties: map[string]any{
						"precision": "high",
					},
				},
			})
			continue
		}
		for _, violation := range evaluation.Violations {
			results = append(results, sarif.Result{
				Kind:   sarif.ResultKindFail,
				RuleID: &ruleID,
				Message: sarif.Message{
					Text: violation,
				},
				Locations: []sarif.Location{
					location(violation),
				},
				Properties: &sarif.PropertyBag{
					Tags: policy.Tags,
					AdditionalProperties: map[string]any{
						"precision": "high",
					},
				},
			})
		}
	}

	driver := sarif.ToolComponent{
		Name:  "devguard-attestations",
		Rules: []sarif.ReportingDescriptor{rule},
	}

	return sarif.SarifSchema210Json{
		Version: sarif.SarifSchema210JsonVersionA210,
		Schema:  utils.Ptr("https://json.schemastore.org/sarif-2.1.0.json"),
		Runs: []sarif.Run{
			{
				Tool: sarif.Tool{
					Driver: driver,
				},
				Results: results,
			},
		},
	}
}
