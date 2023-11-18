package repositories

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/flawfix/internal/models"
	"gorm.io/gorm"
)

type GormProjectRepository struct {
	db *gorm.DB
	Repository[uuid.UUID, models.Project]
}

func NewGormProjectRepository(db *gorm.DB) *GormProjectRepository {
	return &GormProjectRepository{
		db:         db,
		Repository: NewGormRepository[uuid.UUID, models.Project](db),
	}
}
