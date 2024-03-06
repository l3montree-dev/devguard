package project

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/l3montree-dev/flawfix/internal/database"
)

type gormRepository struct {
	db core.DB
	database.Repository[uuid.UUID, Model, core.DB]
}

type repository interface {
	database.Repository[uuid.UUID, Model, core.DB]
	ReadBySlug(organizationID uuid.UUID, slug string) (Model, error)
}

func NewGormRepository(db core.DB) *gormRepository {
	return &gormRepository{
		db:         db,
		Repository: database.NewGormRepository[uuid.UUID, Model](db),
	}
}

func (g *gormRepository) ReadBySlug(organizationID uuid.UUID, slug string) (Model, error) {
	var t Model
	err := g.db.Where("slug = ? AND organization_id = ?", slug, organizationID).First(&t).Error
	return t, err
}
