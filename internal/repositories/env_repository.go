package repositories

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/flawfix/internal/models"
	"gorm.io/gorm"
)

type GormEnvRepository struct {
	db *gorm.DB
	Repository[uuid.UUID, models.Env, *gorm.DB]
}

func NewGormEnvRepository(db *gorm.DB) *GormEnvRepository {
	return &GormEnvRepository{
		db:         db,
		Repository: NewGormRepository[uuid.UUID, models.Env](db),
	}
}
