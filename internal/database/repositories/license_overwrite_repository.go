package repositories

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"gorm.io/gorm"
)

type LicenseOverwriteRepository struct {
	common.Repository[string, models.LicenseOverwrite, core.DB]
	db *gorm.DB
}

func (r *LicenseOverwriteRepository) GetAllOverwritesForOrganization(orgID uuid.UUID) ([]models.LicenseOverwrite, error) {
	var result []models.LicenseOverwrite
	err := r.db.Where("organization_id = ?", orgID).Find(&result).Error
	if err != nil {
		return result, err
	}
	return result, nil
}

func (r *LicenseOverwriteRepository) MaybeGetOverwriteForComponent(orgID uuid.UUID, pURL string) (models.LicenseOverwrite, error) {
	var result models.LicenseOverwrite
	err := r.db.Where("organization_id = ? AND component_purl = ?", orgID, pURL).First(&result).Error
	if err != nil {
		return result, err
	}
	return result, nil
}
