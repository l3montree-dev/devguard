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

package repositories

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
)

type policyViolationRepository struct {
	db core.DB
}

func NewPolicyViolationRepository(db core.DB) *policyViolationRepository {
	if err := db.AutoMigrate(&models.PolicyViolation{}); err != nil {
		panic(err)
	}
	return &policyViolationRepository{
		db: db,
	}
}

func (p *policyViolationRepository) Save(policyViolation *models.PolicyViolation) error {
	return p.db.Save(policyViolation).Error
}

func (p *policyViolationRepository) GetByAssetVersion(assetVersionName string, assetID uuid.UUID) ([]models.PolicyViolation, error) {
	var policyViolations []models.PolicyViolation
	err := p.db.Where("asset_version_name = ? AND asset_id = ?", assetVersionName, assetID).Find(&policyViolations).Error
	if err != nil {
		return nil, err
	}
	return policyViolations, nil
}

func (p *policyViolationRepository) GetByPolicyIdAndAttestationName(policyID string, attestationName string, assetVersionName string, assetID uuid.UUID) ([]models.PolicyViolation, error) {
	var policyViolations []models.PolicyViolation
	err := p.db.Where("attestation_name ? ? policy_id = ? AND asset_version_name = ? AND asset_id = ?", attestationName, policyID, assetVersionName, assetID).Find(&policyViolations).Error
	if err != nil {
		return nil, err
	}
	return policyViolations, nil
}
