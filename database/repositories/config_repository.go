package repositories

import (
	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/shared"
)

type configRepository struct {
	common.Repository[string, models.Config, shared.DB]
	db shared.DB
}

func NewConfigRepository(db shared.DB) *configRepository {
	return &configRepository{
		db:         db,
		Repository: newGormRepository[string, models.Config](db),
	}
}
