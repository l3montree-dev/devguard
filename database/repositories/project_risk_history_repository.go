package repositories

import (
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"gorm.io/gorm"
)

type projectRiskHistoryRepository struct {
	db *gorm.DB
	Repository[uint, models.ProjectRiskHistory, *gorm.DB]
}

func NewProjectRiskHistoryRepository(db *gorm.DB) *projectRiskHistoryRepository {
	return &projectRiskHistoryRepository{
		db:         db,
		Repository: newGormRepository[uint, models.ProjectRiskHistory](db),
	}
}

func (r *projectRiskHistoryRepository) GetRiskHistory(projectID uuid.UUID, start, end time.Time) ([]models.ProjectRiskHistory, error) {
	var projectRisk = []models.ProjectRiskHistory{}
	// get all projectRisk of the project
	if err := r.Repository.GetDB(r.db).Where("project_id = ?", projectID).Where(
		"day >= ? AND day <= ?", start, end,
	).Order("day ASC").Find(&projectRisk).Error; err != nil {
		return nil, err
	}

	return projectRisk, nil
}

func (r *projectRiskHistoryRepository) UpdateRiskAggregation(projectRisk *models.ProjectRiskHistory) error {
	return r.Repository.GetDB(r.db).Save(projectRisk).Error
}
