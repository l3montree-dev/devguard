package repositories

import (
	"os"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"gorm.io/gorm"
)

type supplyChainRepository struct {
	db core.DB
	common.Repository[uuid.UUID, models.SupplyChain, core.DB]
}

func NewSupplyChainRepository(db core.DB) *supplyChainRepository {
	if os.Getenv("DISABLE_AUTOMIGRATE") != "true" {
		if err := db.AutoMigrate(&models.SupplyChain{}); err != nil {
			panic(err)
		}
	}

	return &supplyChainRepository{
		db:         db,
		Repository: newGormRepository[uuid.UUID, models.SupplyChain](db),
	}
}

func (g *supplyChainRepository) FindByDigest(digest string) ([]models.SupplyChain, error) {
	var t []models.SupplyChain

	err := g.db.Model(&models.SupplyChain{}).
		Where("supply_chain_output_digest = ?", digest).
		Find(&t).Error

	return t, err
}

func (g *supplyChainRepository) FindBySupplyChainID(supplyChainID string) ([]models.SupplyChain, error) {
	var t []models.SupplyChain

	err := g.db.Model(&models.SupplyChain{}).
		Where("LEFT(supply_chain_id, 8) = ?", supplyChainID).
		Find(&t).Error

	return t, err
}

func (g *supplyChainRepository) Save(tx core.DB, model *models.SupplyChain) error {
	return g.db.Session(&gorm.Session{
		FullSaveAssociations: false,
	}).Save(model).Error
}

func (g *supplyChainRepository) PercentageOfVerifiedSupplyChains(assetVersionName string, assetID uuid.UUID) (float64, error) {
	var count int64

	err := g.db.Model(&models.SupplyChain{}).
		Where("asset_id = ?", assetID).
		Where("verified = true").
		Count(&count).Error

	if err != nil {
		return 0, err
	}

	var total int64
	err = g.db.Model(&models.SupplyChain{}).
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
