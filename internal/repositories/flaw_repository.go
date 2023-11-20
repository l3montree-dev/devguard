package repositories

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/flawfix/internal/models"
	"gorm.io/gorm"
)

type GormFlawRepository struct {
	db *gorm.DB
	Repository[uuid.UUID, models.Flaw, *gorm.DB]
}

func NewGormFlawRepository(db *gorm.DB) *GormFlawRepository {
	return &GormFlawRepository{
		db:         db,
		Repository: NewGormRepository[uuid.UUID, models.Flaw](db),
	}
}
