package repositories

import (
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database"
	"github.com/l3montree-dev/devguard/internal/database/models"
)

type assetRiskHistoryRepository struct {
	db database.DB
	Repository[uint, models.AssetRiskHistory, core.DB]
}

func NewAssetRiskHistoryRepository(db core.DB) *assetRiskHistoryRepository {
	if err := db.AutoMigrate(&models.AssetRiskHistory{}); err != nil {
		panic(err)
	}
	return &assetRiskHistoryRepository{
		db:         db,
		Repository: newGormRepository[uint, models.AssetRiskHistory](db),
	}
}

func (r *assetRiskHistoryRepository) GetRiskHistory(assetId uuid.UUID, start, end time.Time) ([]models.AssetRiskHistory, error) {
	var assetRisk []models.AssetRiskHistory = []models.AssetRiskHistory{}
	// get all assetRisk of the asset
	if err := r.Repository.GetDB(r.db).Where("asset_id = ?", assetId).Where(
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

	subQueryAssetVersions := db.Table("asset_versions").
		Select("id::uuid").
		Where("asset_id IN (?)", subQueryAssets)

	if err := db.
		Where("asset_version_id IN (?)", subQueryAssetVersions).
		Where("day = ?", day).
		Order("day ASC").
		Find(&assetRisk).
		Error; err != nil {
		return nil, err
	}

	return assetRisk, nil
}
