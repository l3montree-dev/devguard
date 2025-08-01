package repositories

import (
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
		q = q.Where("license_risks.final_license_decision ILIKE ? OR license_risks.component_purl ILIKE ? OR license_risks.scanner_ids ILIKE ?", "%"+search+"%", "%"+search+"%", "%"+search+"%")
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
	err := repository.db.Where("asset_id = ? AND asset_version_name = ? AND state = ?", assetID, assetVersionName, models.VulnStateFixed).Find(&result).Error
	if err != nil {
		return result, err
	}
	return result, nil
}

func (repository *LicenseRiskRepository) MaybeGetLicenseOverwriteForComponent(assetID uuid.UUID, assetVersionName string, pURL packageurl.PackageURL) (models.LicenseRisk, error) {
	var result models.LicenseRisk
	err := repository.db.Where("asset_id = ? AND asset_version_name = ? AND component_purl = ? AND state = ?", assetID, assetVersionName, pURL.String(), models.VulnStateFixed).First(&result).Error
	if err != nil {
		return result, err
	}
	return result, nil
}

func (repository *LicenseRiskRepository) DeleteByComponentPurl(assetID uuid.UUID, assetVersionName string, pURL packageurl.PackageURL) error {
	return repository.db.Where("asset_id = ? AND asset_version_name = ? AND component_purl = ?", assetID, assetVersionName, pURL.String()).Delete(&models.LicenseRisk{}).Error
}

func (repository *LicenseRiskRepository) ListByScanner(assetVersionName string, assetID uuid.UUID, scannerID string) ([]models.LicenseRisk, error) {
	var licenseRisks = []models.LicenseRisk{}
	scannerID = "%" + scannerID + "%"
	err := repository.db.Where("asset_version_name = ? AND asset_id = ? AND scanner_ids LIKE ?", assetVersionName, assetID, scannerID).Find(&licenseRisks).Error
	if err != nil {
		return nil, err
	}
	return licenseRisks, nil
}

func (repository *LicenseRiskRepository) ApplyAndSave(tx core.DB, licenseRisk *models.LicenseRisk, vulnEvent *models.VulnEvent) error {
	if tx == nil {
		// we are not part of a parent transaction - create a new one
		return repository.Transaction(func(d core.DB) error {
			_, err := repository.applyAndSave(d, licenseRisk, vulnEvent)
			return err
		})
	}

	_, err := repository.applyAndSave(tx, licenseRisk, vulnEvent)
	return err
}

func (repository *LicenseRiskRepository) applyAndSave(tx core.DB, licenseRisk *models.LicenseRisk, ev *models.VulnEvent) (models.VulnEvent, error) {
	ev.Apply(licenseRisk)

	// run the updates in the transaction to keep a valid state
	err := repository.Save(tx, licenseRisk)
	if err != nil {
		return models.VulnEvent{}, err
	}
	if err := repository.GetDB(tx).Save(ev).Error; err != nil {
		return models.VulnEvent{}, err
	}
	licenseRisk.Events = append(licenseRisk.Events, *ev)
	return *ev, nil
}
