// Copyright 2026 l3montree GmbH.
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package repositories

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/shared"
	"gorm.io/gorm"
)

type externalReferenceRepository struct {
	*GormRepository[uuid.UUID, models.ExternalReference]
}

var _ shared.ExternalReferenceRepository = (*externalReferenceRepository)(nil)

func NewExternalReferenceRepository(db *gorm.DB) shared.ExternalReferenceRepository {
	return &externalReferenceRepository{
		GormRepository: newGormRepository[uuid.UUID, models.ExternalReference](db),
	}
}

func (r *externalReferenceRepository) FindByAssetID(db *gorm.DB, assetID uuid.UUID) ([]models.ExternalReference, error) {
	var refs []models.ExternalReference
	err := r.GetDB(db).Where("asset_id = ?", assetID).Find(&refs).Error
	return refs, err
}

func (r *externalReferenceRepository) FindByAssetVersion(db *gorm.DB, assetID uuid.UUID, assetVersionName string) ([]models.ExternalReference, error) {
	var refs []models.ExternalReference
	err := r.GetDB(db).Where("asset_id = ? AND asset_version_name = ?", assetID, assetVersionName).Find(&refs).Error
	return refs, err
}

func (r *externalReferenceRepository) DeleteByAssetVersion(db *gorm.DB, assetID uuid.UUID, assetVersionName string) error {
	return r.GetDB(db).Where("asset_id = ? AND asset_version_name = ?", assetID, assetVersionName).Delete(&models.ExternalReference{}).Error
}
