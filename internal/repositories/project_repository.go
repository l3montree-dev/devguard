package repositories

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/flawfix/internal/models"
	"gorm.io/gorm"
)

type GormProjectRepository struct {
	db *gorm.DB
	Repository[uuid.UUID, models.Project, *gorm.DB]
}

func NewGormProjectRepository(db *gorm.DB) *GormProjectRepository {
	return &GormProjectRepository{
		db:         db,
		Repository: NewGormRepository[uuid.UUID, models.Project](db),
	}
}

func (g *GormProjectRepository) ReadBySlug(organizationID uuid.UUID, slug string) (models.Project, error) {
	var t models.Project
	err := g.db.Where("slug = ? AND organization_id = ?", slug, organizationID).First(&t).Error
	return t, err
}
