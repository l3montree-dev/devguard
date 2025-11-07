package repositories

import (
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
)

type artifactRiskHistoryRepository struct {
	db core.DB
	common.Repository[uint, models.ArtifactRiskHistory, core.DB]
}

func NewArtifactRiskHistoryRepository(db core.DB) *artifactRiskHistoryRepository {
	return &artifactRiskHistoryRepository{
		db:         db,
		Repository: newGormRepository[uint, models.ArtifactRiskHistory](db),
	}
}

func (r *artifactRiskHistoryRepository) GetRiskHistory(artifactName *string, assetVersionName string, assetID uuid.UUID, start, end time.Time) ([]models.ArtifactRiskHistory, error) {
	var assetRisk = []models.ArtifactRiskHistory{}
	db := r.GetDB(r.db)

	// base query
	db = db.Where("asset_version_name = ? AND asset_id = ?", assetVersionName, assetID)

	// optional artifact filter
	if artifactName != nil {
		db = db.Where("artifact_name = ?", *artifactName)
	}

	if err := db.Where("day >= ? AND day <= ?", start, end).Order("day ASC").Find(&assetRisk).Error; err != nil {
		return nil, err
	}

	return assetRisk, nil
}

func (r *artifactRiskHistoryRepository) UpdateRiskAggregation(assetRisk *models.ArtifactRiskHistory) error {
	return r.Repository.GetDB(r.db).Save(assetRisk).Error
}

func (r *artifactRiskHistoryRepository) GetRiskHistoryByRelease(releaseID uuid.UUID, start, end time.Time) ([]models.ArtifactRiskHistory, error) {
	var assetRisk = []models.ArtifactRiskHistory{}

	// Use a recursive CTE to collect the release tree (the release and all child releases)
	// then join release_items to artifact_risk_history to get all matching artifact histories.
	db := r.GetDB(r.db)

	query := `
		WITH RECURSIVE release_tree AS (
			SELECT id
			FROM releases
			WHERE id = ?
			UNION ALL
			SELECT ri.child_release_id
			FROM release_items ri
			JOIN release_tree rt ON ri.release_id = rt.id
			WHERE ri.child_release_id IS NOT NULL
		),
		unique_release_items AS (
			SELECT DISTINCT asset_id, asset_version_name, artifact_name
			FROM release_items
			WHERE release_id IN (SELECT id FROM release_tree)
		)
		SELECT DISTINCT arh.artifact_name, arh.asset_version_name, arh.asset_id, arh.day, arh.sum_open_risk, arh.avg_open_risk, arh.max_open_risk, arh.min_open_risk,
		       arh.sum_closed_risk, arh.avg_closed_risk, arh.max_closed_risk, arh.min_closed_risk,
		       arh.open_dependency_vulns, arh.fixed_dependency_vulns,
		       arh.low, arh.medium, arh.high, arh.critical,
		       arh.low_cvss, arh.medium_cvss, arh.high_cvss, arh.critical_cvss
		FROM artifact_risk_history arh
		JOIN unique_release_items uri
		ON arh.asset_id = uri.asset_id
		AND arh.asset_version_name = uri.asset_version_name
		AND arh.artifact_name = uri.artifact_name
		AND arh.day >= ? AND arh.day <= ?
		ORDER BY arh.day ASC
	`

	if err := db.Raw(query, releaseID, start, end).Scan(&assetRisk).Error; err != nil {
		return nil, err
	}

	return assetRisk, nil
}
