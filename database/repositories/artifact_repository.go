// Copyright 2025 l3montree GmbH.
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package repositories

import (
	"context"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/utils"
	"gorm.io/gorm"
)

type artifactRepository struct {
	utils.Repository[string, models.Artifact, *gorm.DB]
	db *gorm.DB
}

func NewArtifactRepository(db *gorm.DB) *artifactRepository {
	return &artifactRepository{
		db:         db,
		Repository: newGormRepository[string, models.Artifact](db),
	}
}

func (r *artifactRepository) GetByAssetIDAndAssetVersionName(ctx context.Context, tx *gorm.DB, assetID uuid.UUID, assetVersionName string) ([]models.Artifact, error) {
	var artifacts []models.Artifact
	err := r.GetDB(ctx, tx).Where("asset_id = ? AND asset_version_name = ?", assetID, assetVersionName).Find(&artifacts).Error
	if err != nil {
		return nil, err
	}

	return artifacts, nil
}

func (r *artifactRepository) GetByAssetVersions(ctx context.Context, tx *gorm.DB, assetID uuid.UUID, assetVersionNames []string) ([]models.Artifact, error) {
	var artifacts []models.Artifact

	err := r.GetDB(ctx, tx).Where("asset_id = ? AND asset_version_name IN ?", assetID, assetVersionNames).Find(&artifacts).Error

	if err != nil {
		return nil, err
	}

	return artifacts, nil
}

func (r *artifactRepository) ReadArtifact(ctx context.Context, tx *gorm.DB, name string, assetVersionName string, assetID uuid.UUID) (models.Artifact, error) {
	var artifact models.Artifact
	err := r.GetDB(ctx, tx).Where("artifact_name = ? AND asset_version_name = ? AND asset_id = ?", name, assetVersionName, assetID).First(&artifact).Error
	return artifact, err
}

func (r *artifactRepository) DeleteArtifact(ctx context.Context, tx *gorm.DB, assetID uuid.UUID, assetVersionName string, artifactName string) error {
	return r.GetDB(ctx, tx).Where("artifact_name = ? AND asset_version_name = ? AND asset_id = ?", artifactName, assetVersionName, assetID).Delete(&models.Artifact{}).Error
}

func (r *artifactRepository) GetAllArtifactAffectedByDependencyVuln(ctx context.Context, tx *gorm.DB, vulnID uuid.UUID) ([]models.Artifact, error) {
	var artifacts []models.Artifact
	err := r.Repository.GetDB(ctx, tx).Raw(`SELECT a.* FROM artifact_dependency_vulns adv 
		LEFT JOIN artifacts a ON adv.artifact_artifact_name = a.artifact_name 
		AND adv.artifact_asset_version_name = a.asset_version_name
		AND adv.artifact_asset_id = a.asset_id
		WHERE adv.dependency_vuln_id = ?;`, vulnID).Find(&artifacts).Error
	if err != nil {
		return nil, err
	}
	return artifacts, nil
}
