package repositories

import (
	"time"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/utils"
	"gorm.io/gorm"
)

type componentProjectRepository struct {
	db *gorm.DB
	utils.Repository[string, models.ComponentProject, *gorm.DB]
}

func NewComponentProjectRepository(db *gorm.DB) *componentProjectRepository {
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
