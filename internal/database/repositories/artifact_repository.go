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

func (r *artifactRepository) DeleteArtifact(assetID uuid.UUID, assetVersionName string, artifactName string) error {
	err := r.db.Where("artifact_name = ? AND asset_version_name = ? AND asset_id = ?", artifactName, assetVersionName, assetID).Delete(&models.Artifact{}).Error
	if err != nil {
		return err
	}

	go func() {
		sql := CleanUpRecordsSQL
		err = r.db.Exec(sql).Error
		if err != nil {
			slog.Error("Failed to clean up orphaned records after deleting artifact", "err", err)
		}
	}() //nolint:errcheck

	return err
}

var CleanUpRecordsSQL = `
DELETE FROM dependency_vulns dv
WHERE NOT EXISTS (SELECT artifact_dependency_vulns.dependency_vuln_id FROM artifact_dependency_vulns WHERE artifact_dependency_vulns.dependency_vuln_id = dv.id);

DELETE FROM license_risks lr
WHERE NOT EXISTS (SELECT artifact_license_risks.license_risk_id FROM artifact_license_risks WHERE artifact_license_risks.license_risk_id = lr.id);

DELETE FROM component_dependencies cd
WHERE NOT EXISTS (SELECT artifact_component_dependencies.component_dependency_id FROM artifact_component_dependencies WHERE artifact_component_dependencies.component_dependency_id = cd.id);

DELETE FROM vuln_events ve
WHERE NOT EXISTS (
    SELECT dependency_vulns.id FROM dependency_vulns WHERE dependency_vulns.id = ve.vuln_id
	UNION
	SELECT first_party_vulnerabilities.id FROM first_party_vulnerabilities WHERE first_party_vulnerabilities.id = ve.vuln_id
);
`
