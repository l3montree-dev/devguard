package repositories

import (
	"os"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/package-url/packageurl-go"
	"gorm.io/gorm"
)

type LicenseRiskRepository struct {
	common.Repository[string, models.LicenseRisk, core.DB]
	db *gorm.DB
}

func NewLicenseRiskRepository(db core.DB) *LicenseRiskRepository {
	if os.Getenv("DISABLE_AUTOMIGRATE") != "true" {
		if err := db.AutoMigrate(&models.LicenseRisk{}); err != nil {
			panic(err)
		}
	}
	return &LicenseRiskRepository{
		db:         db,
		Repository: newGormRepository[string, models.LicenseRisk](db),
	}
}

func (repository *LicenseRiskRepository) GetAllLicenseRisksForAssetVersionPaged(tx core.DB, assetID uuid.UUID, assetVersionName string, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery) (core.Paged[models.LicenseRisk], error) {
	var count int64
	var licenseRisks = []models.LicenseRisk{}

	q := repository.Repository.GetDB(tx).Model(&models.LicenseRisk{}).Where("license_risks.asset_version_name = ?", assetVersionName).Where("license_risks.asset_id = ?", assetID)

	// apply filters
	for _, f := range filter {
		q = q.Where(f.SQL(), f.Value())
	}
	if search != "" && len(search) > 2 {
		q = q.Where("license_risks.license_id ILIKE ? OR license_risks.component_purl ILIKE ? OR license_risks.scanner_ids ILIKE ?", "%"+search+"%", "%"+search+"%", "%"+search+"%")
	}

	err := q.Count(&count).Error
	if err != nil {
		return core.Paged[models.LicenseRisk]{}, err
	}

	err = q.Limit(pageInfo.PageSize).Offset((pageInfo.Page - 1) * pageInfo.PageSize).Find(&licenseRisks).Error
	if err != nil {
		return core.Paged[models.LicenseRisk]{}, err
	}
	//TODO: check it
	return core.NewPaged(pageInfo, count, licenseRisks), nil
}

func (repository *LicenseRiskRepository) GetAllLicenseRisksForAssetVersion(assetID uuid.UUID, assetVersionName string) ([]models.LicenseRisk, error) {
	var result []models.LicenseRisk
	err := repository.db.Where("asset_id = ? AND asset_version_name = ?", assetID, assetVersionName).Find(&result).Error
	if err != nil {
		return result, err
	}
	return result, nil
}

func (repository *LicenseRiskRepository) GetAllOverwrittenLicensesForAssetVersion(assetID uuid.UUID, assetVersionName string) ([]models.LicenseRisk, error) {
	var result []models.LicenseRisk
	err := repository.db.Where("asset_id = ? AND asset_version_name = ? AND state = fixed", assetID, assetVersionName).Find(&result).Error
	if err != nil {
		return result, err
	}
	return result, nil
}

func (repository *LicenseRiskRepository) MaybeGetLicenseOverwriteForComponent(assetID uuid.UUID, assetVersionName string, pURL packageurl.PackageURL) (models.LicenseRisk, error) {
	var result models.LicenseRisk
	err := repository.db.Where("asset_id = ? AND asset_version_name = ? AND component_purl = ? AND state = fixed", assetID, assetVersionName, pURL.String()).First(&result).Error
	if err != nil {
		return result, err
	}
	return result, nil
}

func (repository *LicenseRiskRepository) DeleteByComponentPurl(assetID uuid.UUID, assetVersionName string, pURL packageurl.PackageURL) error {
	return repository.db.Where("asset_id = ? AND asset_version_name = ? AND component_purl = ?", assetID, assetVersionName, pURL.String()).Delete(&models.LicenseRisk{}).Error
}
