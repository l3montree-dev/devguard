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

func EvaluatePolicyAgainstAttestations(srcPath string, policyPath string, attestations []map[string]any) (*sarif.SarifSchema210Json, []compliance.PolicyEvaluation, error) {

	content, err := os.ReadFile(policyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("could not read policy file: %w", err)
	}

	policy, err := compliance.PolicyFSFromContent(filepath.Base(policyPath), string(content))
	if err != nil {
		return nil, nil, fmt.Errorf("could not parse policy: %w", err)
	}

	evaluations := make([]compliance.PolicyEvaluation, 0)

foundMatch:

	for _, attestation := range attestations {
		predicateType, _ := attestation["predicateType"].(string)
		if predicateType != policy.PredicateType {
			continue
		}
		raw, err := json.Marshal(attestation)
		if err != nil {
			return nil, nil, fmt.Errorf("could not marshal attestation: %w", err)
		}
		input, err := utils.ExtractAttestationPayload(string(raw))
		if err != nil {
			return nil, nil, fmt.Errorf("could not extract attestation payload: %w", err)
		}
		eval := compliance.Eval(policy, input)
		evaluations = append(evaluations, eval)
		continue foundMatch
	}
	eval := compliance.Eval(policy, nil)
	evaluations = append(evaluations, eval)

	sarifResult := compliance.BuildSarifFromPolicies(srcPath, evaluations)
	return &sarifResult, evaluations, nil
}
