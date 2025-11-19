package repositories

import (
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/utils"
	"gorm.io/gorm"
)

type assetRiskHistoryRepository struct {
	db *gorm.DB
	utils.Repository[uint, models.ArtifactRiskHistory, *gorm.DB]
}

func NewAssetRiskHistoryRepository(db *gorm.DB) *assetRiskHistoryRepository {
	return &assetRiskHistoryRepository{
		db:         db,
		Repository: newGormRepository[uint, models.ArtifactRiskHistory](db),
	}
}

func (r *assetRiskHistoryRepository) GetRiskHistory(assetVersionName string, assetID uuid.UUID, start, end time.Time) ([]models.ArtifactRiskHistory, error) {
	var assetRisk = []models.ArtifactRiskHistory{}
	// get all assetRisk of the asset
	if err := r.Repository.GetDB(r.db).Where("asset_version_name = ? AND asset_id = ?", assetVersionName, assetID).Where(
		"day >= ? AND day <= ?", start, end,
	).Order("day ASC").Find(&assetRisk).Error; err != nil {
		return nil, err
	}

	return assetRisk, nil
}

func (r *assetRiskHistoryRepository) UpdateRiskAggregation(assetRisk *models.ArtifactRiskHistory) error {
	return r.Repository.GetDB(r.db).Save(assetRisk).Error
}

func (r *assetRiskHistoryRepository) GetRiskHistoryByProject(projectID uuid.UUID, day time.Time) ([]models.ArtifactRiskHistory, error) {
	var assetRisk = []models.ArtifactRiskHistory{}

	projectAndChildProjectsQuery := r.Repository.GetDB(r.db).Raw(`
		WITH RECURSIVE project_tree AS (
			SELECT id, parent_id
			FROM projects
			WHERE id = ?
			UNION
			SELECT p.id, p.parent_id
			FROM projects p
			JOIN project_tree pt ON p.parent_id = pt.id
		)
		SELECT id
		FROM project_tree
	`, projectID)

	// get all assetRisk of the project
	db := r.GetDB(r.db)

	subQueryAssets := db.Table("assets").
		Select("id::uuid").
		Where("project_id IN (?)", projectAndChildProjectsQuery)

	if err := db.
		Where("asset_id IN (?)", subQueryAssets).
		Where("day = ?", day).
		Order("day ASC").
		Find(&assetRisk).
		Error; err != nil {
		return nil, err
	}

	return assetRisk, nil
}

func (r *assetRiskHistoryRepository) GetRiskHistoryByRelease(releaseID uuid.UUID, start, end time.Time) ([]models.ArtifactRiskHistory, error) {
	var assetRisk = []models.ArtifactRiskHistory{}

	// Use a recursive CTE to collect the release tree (the release and all child releases)
	// then join release_items to asset_risk_history to get all matching artifact histories.
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
		)
		SELECT DISTINCT arh.asset_version_name, arh.asset_id, arh.day, arh.sum_open_risk, arh.avg_open_risk, arh.max_open_risk, arh.min_open_risk,
			   arh.sum_closed_risk, arh.avg_closed_risk, arh.max_closed_risk, arh.min_closed_risk,
			   arh.open_dependency_vulns, arh.fixed_dependency_vulns,
			   arh.low, arh.medium, arh.high, arh.critical,
			   arh.low_cvss, arh.medium_cvss, arh.high_cvss, arh.critical_cvss
		FROM asset_risk_history arh
		JOIN release_items ri ON arh.asset_version_name = ri.asset_version_name AND arh.asset_id = ri.asset_id
		WHERE ri.release_id IN (SELECT id FROM release_tree)
		  AND arh.day >= ? AND arh.day <= ?
		ORDER BY arh.day ASC
	`

	if err := db.Raw(query, releaseID, start, end).Preload("Asset").Scan(&assetRisk).Error; err != nil {
		return nil, err
	}

	return assetRisk, nil
}
