// Copyright (C) 2025 l3montree UG (haftungsbeschraenkt)
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

package compliance

import (
	"strings"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/l3montree-dev/devguard/internal/database/models"
)

type service struct {
	policies []Policy
}

func NewService() *service {
	return &service{
		policies: getPolicies(),
	}
}

func (s *service) EvalPolicies(attestations []models.Attestation) ([]common.PolicyEvaluation, error) {

	results := make([]common.PolicyEvaluation, 0, len(s.policies))

	for _, policy := range s.policies {
		// check if we find an attestation that matches
		for _, attestation := range attestations {
			if attestation.AttestationName != policy.AttestationName {
				continue
			}
			res := policy.Eval(attestation.Content)
			// this matches - lets add it
			results = append(results, res)

		}
		// we did not find any attestation that matches - lets add the policy with a nil result
		results = append(results, policy.Eval(nil))
	}

	return results, nil
}

func ViolationsFromEvals(assetVersionName string, assetID uuid.UUID, evals []common.PolicyEvaluation) []models.PolicyViolation {
	violations := make([]models.PolicyViolation, 0, len(evals))
	for _, eval := range evals {
		if eval.Compliant != nil && !*eval.Compliant {
			for _, v := range eval.Violations {
				// create a new policy violation model
				violation := models.PolicyViolation{
					Message:          v,
					PolicyID:         strings.TrimSuffix(eval.Filename, ".rego"),
					State:            models.VulnStateOpen, // default to open state
					AssetID:          assetID,
					AssetVersionName: assetVersionName,
				}

				violations = append(violations, violation)
			}
		}
	}

	return violations
}
