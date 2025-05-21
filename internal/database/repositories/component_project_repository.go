package repositories

import (
	"os"
	"time"

	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
)

type componentProjectRepository struct {
	db core.DB
	common.Repository[string, models.ComponentProject, core.DB]
}

func NewComponentProjectRepository(db core.DB) *componentProjectRepository {
	if os.Getenv("DISABLE_AUTOMIGRATE") != "true" {
		err := db.AutoMigrate(&models.ComponentProject{})
		if err != nil {
			panic(err)
		}
	}

	return &componentProjectRepository{
		db:         db,
		Repository: newGormRepository[string, models.ComponentProject](db),
	}
}

func (r *componentProjectRepository) FindAllOutdatedProjects() ([]models.ComponentProject, error) {
	var componentProjects []models.ComponentProject
	// 7 days
	date := time.Now().AddDate(0, 0, -7)

	err := r.db.Where("updated_at <= ?", date).Find(&componentProjects).Error
	return componentProjects, err
}
