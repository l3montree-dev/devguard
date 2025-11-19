// Copyright 2025 l3montree GmbH.
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package repositories

import (
	"log/slog"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/utils"
	"gorm.io/gorm"
)

type artifactRepository struct {
	utils.Repository[string, models.Artifact, *gorm.DB]
	utils.FireAndForgetSynchronizer
	db *gorm.DB
}

func NewArtifactRepository(db *gorm.DB, synchronizer utils.FireAndForgetSynchronizer) *artifactRepository {
	return &artifactRepository{
		db:                        db,
		Repository:                newGormRepository[string, models.Artifact](db),
		FireAndForgetSynchronizer: synchronizer,
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

func (r *artifactRepository) GetByAssetVersions(assetID uuid.UUID, assetVersionNames []string) ([]models.Artifact, error) {
	var artifacts []models.Artifact

	err := r.db.Where("asset_id = ? AND asset_version_name IN ?", assetID, assetVersionNames).Find(&artifacts).Error

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

	r.FireAndForget(func() {
		sql := CleanupOrphanedRecordsSQL
		err = r.db.Exec(sql).Error
		if err != nil {
			slog.Error("Failed to clean up orphaned records after deleting artifact", "err", err)
		}
	})

	return err
}

func (r *artifactRepository) GetAllArtifactAffectedByDependencyVuln(tx *gorm.DB, vulnID string) ([]models.Artifact, error) {
	var artifacts []models.Artifact
	err := r.Repository.GetDB(tx).Raw(`SELECT a.* FROM artifact_dependency_vulns adv 
		LEFT JOIN artifacts a ON adv.artifact_artifact_name = a.artifact_name 
		AND adv.artifact_asset_version_name = a.asset_version_name
		AND adv.artifact_asset_id = a.asset_id
		WHERE adv.dependency_vuln_id = ?;`, vulnID).Find(&artifacts).Error
	if err != nil {
		return nil, err
	}
	return artifacts, nil
}

var CleanupOrphanedRecordsSQL = `
DELETE FROM dependency_vulns dv
WHERE NOT EXISTS (SELECT artifact_dependency_vulns.dependency_vuln_id FROM artifact_dependency_vulns WHERE artifact_dependency_vulns.dependency_vuln_id = dv.id);

DELETE FROM license_risks lr
WHERE NOT EXISTS (SELECT artifact_license_risks.license_risk_id FROM artifact_license_risks WHERE artifact_license_risks.license_risk_id = lr.id);

DELETE FROM component_dependencies cd
WHERE NOT EXISTS (SELECT artifact_component_dependencies.component_dependency_id FROM artifact_component_dependencies WHERE artifact_component_dependencies.component_dependency_id = cd.id);

DELETE FROM vuln_events ve WHERE ve.vuln_type = 'dependencyVuln' AND NOT EXISTS (
    SELECT dependency_vulns.id FROM dependency_vulns WHERE dependency_vulns.id = ve.vuln_id
);

DELETE FROM vuln_events ve WHERE ve.vuln_type = 'firstPartyVuln' AND NOT EXISTS(
	SELECT first_party_vulnerabilities.id FROM first_party_vulnerabilities WHERE first_party_vulnerabilities.id = ve.vuln_id
);

DELETE FROM vuln_events ve WHERE ve.vuln_type = 'licenseRisk' AND NOT EXISTS(
	SELECT license_risks.id FROM license_risks WHERE license_risks.id = ve.vuln_id
);
`
