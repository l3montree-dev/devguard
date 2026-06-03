// Copyright (C) 2026 l3montree GmbH
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
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/shared"
)

type AttestationService struct {
	attestationRepository shared.AttestationRepository
}

var _ shared.AttestationService = (*AttestationService)(nil)

func NewAttestationService(attestationRepository shared.AttestationRepository) *AttestationService {
	return &AttestationService{
		attestationRepository: attestationRepository,
	}
}

func (s *AttestationService) GetByAssetID(ctx context.Context, tx shared.DB, assetID uuid.UUID) ([]models.Attestation, error) {
	return s.attestationRepository.GetByAssetID(ctx, tx, assetID)
}

func (s *AttestationService) GetByAssetVersionAndAssetID(ctx context.Context, tx shared.DB, assetID uuid.UUID, assetVersion string) ([]models.Attestation, error) {
	return s.attestationRepository.GetByAssetVersionAndAssetID(ctx, tx, assetID, assetVersion)
}

func (s *AttestationService) GetByArtifactAndAssetVersionAndAssetID(ctx context.Context, tx shared.DB, artifactName string, assetVersion string, assetID uuid.UUID) ([]models.Attestation, error) {
	return s.attestationRepository.GetByArtifactAndAssetVersionAndAssetID(ctx, tx, artifactName, assetVersion, assetID)
}

func (s *AttestationService) Create(ctx context.Context, tx shared.DB, attestation *models.Attestation) error {
	return s.attestationRepository.Create(ctx, tx, attestation)
}
