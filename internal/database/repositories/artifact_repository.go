// Copyright 2025 l3montree GmbH.
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package repositories

import (
	"log/slog"

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

func (r *artifactRepository) DeleteArtifact(artifactName string, assetVersionName string, assetID uuid.UUID) error {
	err := r.db.Where("artifact_name = ? AND asset_version_name = ? AND asset_id = ?", artifactName, assetVersionName, assetID).Delete(&models.Artifact{}).Error
	if err != nil {
		return err
	}

	go func() {
		sql := `
DELETE FROM dependency_vulns dv
WHERE NOT EXISTS (SELECT 1 FROM artifact_dependency_vulns);

DELETE FROM license_risks lr
WHERE NOT EXISTS (SELECT 1 FROM artifact_license_risks);

DELETE FROM component_dependencies cd
WHERE NOT EXISTS (SELECT 1 FROM artifact_component_dependencies);

DELETE FROM vuln_events ve
WHERE NOT EXISTS (
    SELECT 1 FROM dependency_vulns
    UNION
    SELECT 1 FROM first_party_vulnerabilities
);
`
		err = r.db.Exec(sql).Error
		if err != nil {
			slog.Error("Failed to clean up orphaned records after deleting artifact", "err", err)
		}
	}() //nolint:errcheck

	return err
}
