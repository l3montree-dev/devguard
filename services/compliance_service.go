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
package services

import (
	"context"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/compliance"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos/sarif"
	"github.com/l3montree-dev/devguard/shared"
)

type ComplianceService struct {
	attestationRepository shared.AttestationRepository
}

func NewComplianceService(attestationRepository shared.AttestationRepository) *ComplianceService {
	return &ComplianceService{
		attestationRepository: attestationRepository,
	}
}

func (s *ComplianceService) EvaluateArtifactAttestations(ctx context.Context, projectID uuid.UUID, assetVersion models.AssetVersion, artifact models.Artifact) (sarif.SarifSchema210Json, error) {
	attestations, err := s.attestationRepository.GetByArtifactAndAssetVersionAndAssetID(ctx, nil, artifact.ArtifactName, assetVersion.Name, assetVersion.AssetID)
	if err != nil {
		return sarif.SarifSchema210Json{}, err
	}

	policies, err := compliance.GetPoliciesFromFS("attestation-compliance-policies/policies")
	if err != nil {
		return sarif.SarifSchema210Json{}, err
	}

	evals := make([]compliance.PolicyEvaluation, 0, len(policies))
foundMatch:
	for _, policy := range policies {
		for _, attestation := range attestations {
			if attestation.PredicateType != policy.PredicateType {
				continue
			}
			eval := compliance.Eval(policy, attestation.Content)
			evals = append(evals, eval)
			continue foundMatch
		}
		evals = append(evals, compliance.Eval(policy, nil))
	}

	return compliance.BuildSarifFromPoliciesEvaluations("", evals), nil
}
