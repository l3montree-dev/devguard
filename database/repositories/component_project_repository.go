package repositories

import (
	"time"

	"github.com/l3montree-dev/devguard/common"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/shared"
)

type componentProjectRepository struct {
	db shared.DB
	common.Repository[string, models.ComponentProject, shared.DB]
}

func NewComponentProjectRepository(db shared.DB) *componentProjectRepository {
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
