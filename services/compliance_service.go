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
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/l3montree-dev/devguard/utils"
)

type ComplianceService struct {
	attestationRepository shared.AttestationRepository
	policyRepository      shared.PolicyRepository
}

func NewComplianceService(attestationRepository shared.AttestationRepository, policyRepository shared.PolicyRepository) *ComplianceService {
	return &ComplianceService{
		attestationRepository: attestationRepository,
		policyRepository:      policyRepository,
	}
}

func (s *ComplianceService) ArtifactCompliance(ctx context.Context, projectID uuid.UUID, assetVersion models.AssetVersion, artifact models.Artifact) ([]dtos.PolicyEvaluationDTO, error) {
	attestations, err := s.attestationRepository.GetByArtifactAndAssetVersionAndAssetID(ctx, nil, artifact.ArtifactName, assetVersion.Name, assetVersion.AssetID)
	if err != nil {
		return nil, err
	}

	policies, err := s.policyRepository.FindCommunityManagedPolicies(ctx, nil)
	if err != nil {
		return nil, err
	}

	evals := make([]compliance.PolicyEvaluation, 0, len(policies))
foundMatch:
	for _, policy := range policies {
		for _, attestation := range attestations {
			if attestation.PredicateType != policy.PredicateType {
				continue
			}
			eval := compliance.Eval(policy, attestation.Content)
			eval.AttestationUpdatedAt = &attestation.UpdatedAt
			evals = append(evals, eval)
			continue foundMatch
		}
		evals = append(evals, compliance.Eval(policy, nil))
	}

	return utils.Map(evals, transformer.PolicyEvaluationToDTO), nil
}
