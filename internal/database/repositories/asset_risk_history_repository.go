package repositories

import (
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
)

type assetRiskHistoryRepository struct {
	db core.DB
	common.Repository[uint, models.AssetRiskHistory, core.DB]
}

func NewAssetRiskHistoryRepository(db core.DB) *assetRiskHistoryRepository {
	if os.Getenv("DISABLE_AUTOMIGRATE") != "true" {
		if err := db.AutoMigrate(&models.AssetRiskHistory{}); err != nil {
			panic(err)
		}
	}

	return &assetRiskHistoryRepository{
		db:         db,
		Repository: newGormRepository[uint, models.AssetRiskHistory](db),
	}
}

func (r *assetRiskHistoryRepository) GetRiskHistory(assetVersionName string, assetID uuid.UUID, start, end time.Time) ([]models.AssetRiskHistory, error) {
	var assetRisk []models.AssetRiskHistory = []models.AssetRiskHistory{}
	// get all assetRisk of the asset
	if err := r.Repository.GetDB(r.db).Where("asset_version_name = ? AND asset_id = ?", assetVersionName, assetID).Where(
		"day >= ? AND day <= ?", start, end,
	).Order("day ASC").Find(&assetRisk).Error; err != nil {
		return nil, err
	}

	return assetRisk, nil
}

func (r *assetRiskHistoryRepository) UpdateRiskAggregation(assetRisk *models.AssetRiskHistory) error {
	return r.Repository.GetDB(r.db).Save(assetRisk).Error
}

func (r *assetRiskHistoryRepository) GetRiskHistoryByProject(projectId uuid.UUID, day time.Time) ([]models.AssetRiskHistory, error) {
	var assetRisk []models.AssetRiskHistory = []models.AssetRiskHistory{}

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
	`, projectId)

	// get all assetRisk of the project
	db := r.Repository.GetDB(r.db)

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
