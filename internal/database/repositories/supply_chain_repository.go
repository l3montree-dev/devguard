package repositories

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"gorm.io/gorm"
)

type supplyChainRepository struct {
	db core.DB
	Repository[uuid.UUID, models.SupplyChain, core.DB]
}

func NewSupplyChainRepository(db core.DB) *supplyChainRepository {
	if err := db.AutoMigrate(&models.SupplyChain{}); err != nil {
		panic(err)
	}

	return &supplyChainRepository{
		db:         db,
		Repository: newGormRepository[uuid.UUID, models.SupplyChain](db),
	}
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
