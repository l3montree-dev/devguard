package cwe

import (
	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/l3montree-dev/flawfix/internal/database"
	"gorm.io/gorm"
)

type Repository interface {
	database.Repository[string, CVEModel, core.DB]
	FindByID(id string) (CVEModel, error)
}

type GormRepository struct {
	database.Repository[string, CVEModel, core.DB]
	db *gorm.DB
}

func NewGormRepository(db core.DB) Repository {
	return &GormRepository{
		db:         db,
		Repository: database.NewGormRepository[string, CVEModel](db),
	}
}

func (g *GormRepository) FindByID(id string) (CVEModel, error) {
	var t CVEModel
	err := g.db.First(&t, "cve = ?", id).Error

	return t, err
}
