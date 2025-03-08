package repositories

import (
	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
)

type configRepository struct {
	common.Repository[string, models.Config, core.DB]
	db core.DB
}

func NewConfigRepository(db core.DB) *configRepository {
	if err := db.AutoMigrate(&models.Config{}); err != nil {
		panic(err)
	}
	return &configRepository{
		db:         db,
		Repository: newGormRepository[string, models.Config](db),
	}
}
