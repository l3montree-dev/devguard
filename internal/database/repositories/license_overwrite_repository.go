package repositories

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/package-url/packageurl-go"
	"gorm.io/gorm"
)

type LicenseOverwriteRepository struct {
	common.Repository[string, models.LicenseOverwrite, core.DB]
	db *gorm.DB
}

func (repository *LicenseOverwriteRepository) GetAllOverwritesForOrganization(orgID uuid.UUID) ([]models.LicenseOverwrite, error) {
	var result []models.LicenseOverwrite
	err := repository.db.Where("organization_id = ?", orgID).Find(&result).Error
	if err != nil {
		return result, err
	}
	return result, nil
}

func (repository *LicenseOverwriteRepository) MaybeGetOverwriteForComponent(orgID uuid.UUID, pURL packageurl.PackageURL) (models.LicenseOverwrite, error) {
	var result models.LicenseOverwrite
	err := repository.db.Where("organization_id = ? AND component_purl = ?", orgID, pURL.String()).First(&result).Error
	if err != nil {
		return result, err
	}
	return result, nil
}
