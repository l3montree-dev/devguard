package repositories

import (
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
)

type cweRepository struct {
	Repository[string, models.CWE, core.DB]
}

func NewCWERepository(db core.DB) *cweRepository {
	if err := db.AutoMigrate(&models.CWE{}); err != nil {
		panic(err)
	}
	return &cweRepository{
		Repository: newGormRepository[string, models.CWE](db),
	}
}
