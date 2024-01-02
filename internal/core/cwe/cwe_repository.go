package cwe

import (
	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/l3montree-dev/flawfix/internal/database"
)

type CWERepository interface {
	database.Repository[string, CWEModel, core.DB]
}

type GormCWERepository struct {
	database.Repository[string, CWEModel, core.DB]
}

func NewGormCWERepository(db core.DB) CWERepository {
	return &GormCWERepository{
		Repository: database.NewGormRepository[string, CWEModel](db),
	}
}
