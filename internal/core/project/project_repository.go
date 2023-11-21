package project

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/l3montree-dev/flawfix/internal/database"
)

type GormRepository struct {
	db core.DB
	database.Repository[uuid.UUID, Model, core.DB]
}

type Repository interface {
	database.Repository[uuid.UUID, Model, core.DB]
	ReadBySlug(organizationID uuid.UUID, slug string) (Model, error)
}

func NewGormRepository(db core.DB) Repository {
	return &GormRepository{
		db:         db,
		Repository: database.NewGormRepository[uuid.UUID, Model](db),
	}
}

func (g *GormRepository) ReadBySlug(organizationID uuid.UUID, slug string) (Model, error) {
	var t Model
	err := g.db.Where("slug = ? AND organization_id = ?", slug, organizationID).First(&t).Error
	return t, err
}
