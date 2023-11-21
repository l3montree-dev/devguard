package env

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
	ReadBySlug(applicationID uuid.UUID, slug string) (Model, error)
}

func NewGormRepository(db core.DB) *GormRepository {
	return &GormRepository{
		db:         db,
		Repository: database.NewGormRepository[uuid.UUID, Model](db),
	}
}

func (g *GormRepository) ReadBySlug(applicationID uuid.UUID, slug string) (Model, error) {
	var env Model
	err := g.db.Where("slug = ? AND application_id = ?", slug, applicationID).First(&env).Error
	return env, err
}
