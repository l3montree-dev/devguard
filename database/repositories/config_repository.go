package repositories

import (
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/utils"
	"gorm.io/gorm"
)

type configRepository struct {
	utils.Repository[string, models.Config, *gorm.DB]
	db *gorm.DB
}

func NewConfigRepository(db *gorm.DB) *configRepository {
	return &configRepository{
		db:         db,
		Repository: newGormRepository[string, models.Config](db),
	}
}
