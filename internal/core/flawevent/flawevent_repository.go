package flawevent

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
}

func NewGormRepository(db core.DB) *GormRepository {
	return &GormRepository{
		db:         db,
		Repository: database.NewGormRepository[uuid.UUID, Model](db),
	}
}
