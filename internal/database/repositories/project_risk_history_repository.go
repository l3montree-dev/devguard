package repositories

import (
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
)

type projectRiskHistoryRepository struct {
	db core.DB
	common.Repository[uint, models.ProjectRiskHistory, core.DB]
}

func NewProjectRiskHistoryRepository(db core.DB) *projectRiskHistoryRepository {
	if err := db.AutoMigrate(&models.ProjectRiskHistory{}); err != nil {
		panic(err)
	}
	return &projectRiskHistoryRepository{
		db:         db,
		Repository: newGormRepository[uint, models.ProjectRiskHistory](db),
	}
}

func (r *projectRiskHistoryRepository) GetRiskHistory(projectId uuid.UUID, start, end time.Time) ([]models.ProjectRiskHistory, error) {
	var projectRisk []models.ProjectRiskHistory = []models.ProjectRiskHistory{}
	// get all projectRisk of the project
	if err := r.Repository.GetDB(r.db).Where("project_id = ?", projectId).Where(
		"day >= ? AND day <= ?", start, end,
	).Order("day ASC").Find(&projectRisk).Error; err != nil {
		return nil, err
	}

	return projectRisk, nil
}

func (r *projectRiskHistoryRepository) UpdateRiskAggregation(projectRisk *models.ProjectRiskHistory) error {
	return r.Repository.GetDB(r.db).Save(projectRisk).Error
}
