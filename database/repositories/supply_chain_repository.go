package repositories

import (
	"context"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/utils"
	"gorm.io/gorm"
)

type supplyChainRepository struct {
	db *gorm.DB
	utils.Repository[uuid.UUID, models.SupplyChain, *gorm.DB]
}

func NewSupplyChainRepository(db *gorm.DB) *supplyChainRepository {
	return &supplyChainRepository{
		db:         db,
		Repository: newGormRepository[uuid.UUID, models.SupplyChain](db),
	}
}

func (g *supplyChainRepository) FindByDigest(ctx context.Context, tx *gorm.DB, digest string) ([]models.SupplyChain, error) {
	var t []models.SupplyChain

	err := g.GetDB(ctx, tx).Model(&models.SupplyChain{}).
		Where("supply_chain_output_digest = ?", digest).
		Find(&t).Error

	return t, err
}

func (g *supplyChainRepository) FindBySupplyChainID(ctx context.Context, tx *gorm.DB, supplyChainID string) ([]models.SupplyChain, error) {
	var t []models.SupplyChain

	err := g.GetDB(ctx, tx).Model(&models.SupplyChain{}).
		Where("LEFT(supply_chain_id, 8) = ?", supplyChainID).
		Find(&t).Error

	return t, err
}

func (g *supplyChainRepository) Save(ctx context.Context, tx *gorm.DB, model *models.SupplyChain) error {
	return g.GetDB(ctx, tx).Session(&gorm.Session{
		FullSaveAssociations: false,
	}).Save(model).Error
}

func (g *supplyChainRepository) PercentageOfVerifiedSupplyChains(ctx context.Context, tx *gorm.DB, assetVersionName string, assetID uuid.UUID) (float64, error) {
	var count int64

	err := g.GetDB(ctx, tx).Model(&models.SupplyChain{}).
		Where("asset_id = ?", assetID).
		Where("verified = true").
		Count(&count).Error

	if err != nil {
		return 0, err
	}

	var total int64
	err = g.GetDB(ctx, tx).Model(&models.SupplyChain{}).
		Where("asset_id = ?", assetID).
		Count(&total).Error

	if err != nil {
		return 0, err
	}

	if total == 0 {
		return 0, nil
	}

	return float64(count) / float64(total), nil
}
