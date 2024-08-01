package repositories

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database"
	"github.com/l3montree-dev/devguard/internal/database/models"
)

type assetRecentRiskRepository struct {
	db database.DB
	Repository[uint, models.AssetRecentRisks, core.DB]
}

func NewAssetRiskRepository(db core.DB) *assetRecentRiskRepository {
	if err := db.AutoMigrate(&models.AssetRecentRisks{}); err != nil {
		panic(err)
	}
	return &assetRecentRiskRepository{
		db:         db,
		Repository: newGormRepository[uint, models.AssetRecentRisks](db),
	}
}

func (r *assetRecentRiskRepository) GetAssetRecentRisksByAssetId(assetId uuid.UUID) ([]models.AssetRecentRisks, error) {
	var assetRisks []models.AssetRecentRisks = []models.AssetRecentRisks{}
	// get all assetRisks of the asset
	if err := r.Repository.GetDB(r.db).Where("asset_id = ?", assetId).Find(&assetRisks).Error; err != nil {
		return nil, err
	}
	return assetRisks, nil
}

func (r *assetRecentRiskRepository) UpdateAssetRecentRisks(assetRisks *models.AssetRecentRisks) error {
	return r.Repository.GetDB(r.db).Save(assetRisks).Error
}
