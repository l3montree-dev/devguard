// Copyright 2025 l3montree GmbH.
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package repositories

import (
	"context"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/lib/pq"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type artifactRepository struct {
	utils.Repository[uuid.UUID, models.Artifact, *gorm.DB]
	db *gorm.DB
}

func NewArtifactRepository(db *gorm.DB) *artifactRepository {
	return &artifactRepository{
		db:         db,
		Repository: newGormRepository[uuid.UUID, models.Artifact](db),
	}
}

func (r *artifactRepository) GetByAssetID(ctx context.Context, tx *gorm.DB, assetID uuid.UUID) ([]models.Artifact, error) {
	var artifacts []models.Artifact
	err := r.GetDB(ctx, tx).Where("asset_id = ?", assetID).Find(&artifacts).Error
	if err != nil {
		return nil, err
	}

	return artifacts, nil
}

func (r *artifactRepository) GetByAssetIDs(ctx context.Context, tx *gorm.DB, assetIDs []uuid.UUID) ([]models.Artifact, error) {
	var artifacts []models.Artifact
	err := r.GetDB(ctx, tx).Where("asset_id = ANY (?)", pq.Array(assetIDs)).Find(&artifacts).Error
	if err != nil {
		return nil, err
	}

	return artifacts, nil
}

func (r *artifactRepository) GetByAssetVersionID(ctx context.Context, tx *gorm.DB, assetVersionID uuid.UUID) ([]models.Artifact, error) {
	var artifacts []models.Artifact
	err := r.GetDB(ctx, tx).Where("asset_version_id = ?", assetVersionID).Find(&artifacts).Error
	if err != nil {
		return nil, err
	}

	return artifacts, nil
}

func (r *artifactRepository) GetByAssetVersionIDs(ctx context.Context, tx *gorm.DB, assetVersionIDs []uuid.UUID) ([]models.Artifact, error) {
	var artifacts []models.Artifact

	err := r.GetDB(ctx, tx).Where("asset_version_id = ANY (?)", pq.Array(assetVersionIDs)).Find(&artifacts).Error

	if err != nil {
		return nil, err
	}

	return artifacts, nil
}

// FindOrCreate inserts the artifact if it does not exist yet and fills in the stored row either way
func (r *artifactRepository) FindOrCreate(ctx context.Context, tx *gorm.DB, artifact *models.Artifact) error {
	db := r.GetDB(ctx, tx)
	if err := db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "artifact_name"}, {Name: "asset_version_id"}},
		DoNothing: true,
	}).Create(artifact).Error; err != nil {
		return err
	}
	if artifact.ID != uuid.Nil {
		return nil
	}
	// on conflict nothing is returned, so the existing row needs to be read
	return db.Where("artifact_name = ? AND asset_version_id = ?", artifact.ArtifactName, artifact.AssetVersionID).First(artifact).Error
}

func (r *artifactRepository) ReadArtifact(ctx context.Context, tx *gorm.DB, name string, assetVersionID uuid.UUID) (models.Artifact, error) {
	var artifact models.Artifact
	err := r.GetDB(ctx, tx).Where("artifact_name = ? AND asset_version_id = ?", name, assetVersionID).First(&artifact).Error
	return artifact, err
}

func (r *artifactRepository) DeleteArtifact(ctx context.Context, tx *gorm.DB, assetVersionID uuid.UUID, artifactName string) error {
	return r.GetDB(ctx, tx).Where("artifact_name = ? AND asset_version_id = ?", artifactName, assetVersionID).Delete(&models.Artifact{}).Error
}

func (r *artifactRepository) GetAllArtifactAffectedByDependencyVuln(ctx context.Context, tx *gorm.DB, vulnID uuid.UUID) ([]models.Artifact, error) {
	var artifacts []models.Artifact
	err := r.Repository.GetDB(ctx, tx).Raw(`SELECT a.* FROM artifact_dependency_vulns adv 
		LEFT JOIN artifacts a ON adv.artifact_id = a.id
		WHERE adv.dependency_vuln_id = ?;`, vulnID).Find(&artifacts).Error
	if err != nil {
		return nil, err
	}
	return artifacts, nil
}
