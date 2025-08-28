// Copyright 2025 l3montree GmbH.
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package repositories

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
)

type artifactRepository struct {
	common.Repository[string, models.Artifact, core.DB]
	db core.DB
}

func NewArtifactRepository(db core.DB) *artifactRepository {
	return &artifactRepository{
		db:         db,
		Repository: newGormRepository[string, models.Artifact](db),
	}
}

func (r *artifactRepository) GetByAssetIDAndAssetVersionName(assetID uuid.UUID, assetVersionName string) ([]models.Artifact, error) {
	var artifacts []models.Artifact
	err := r.db.Where("asset_id = ? AND asset_version_name = ?", assetID, assetVersionName).Find(&artifacts).Error
	if err != nil {
		return nil, err
	}

	return artifacts, nil
}

func (r *artifactRepository) ReadArtifact(name string, assetVersionName string, assetID uuid.UUID) (models.Artifact, error) {
	var artifact models.Artifact
	err := r.db.Where("artifact_name = ? AND asset_version_name = ? AND asset_id = ?", name, assetVersionName, assetID).First(&artifact).Error
	return artifact, err
}
