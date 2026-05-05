package repositories

import (
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/utils"
	"gorm.io/gorm"
)

type projectRiskHistoryRepository struct {
	db *gorm.DB
	utils.Repository[uint, models.ProjectRiskHistory, *gorm.DB]
}
