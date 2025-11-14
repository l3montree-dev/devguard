package repositories

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/common"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/package-url/packageurl-go"
	"gorm.io/gorm"
)

type LicenseRiskRepository struct {
	common.Repository[string, models.LicenseRisk, *gorm.DB]
	db *gorm.DB
}

func NewLicenseRiskRepository(db *gorm.DB) *LicenseRiskRepository {
	return &LicenseRiskRepository{
		db:         db,
		Repository: newGormRepository[string, models.LicenseRisk](db),
	}
}

func (repository *LicenseRiskRepository) GetAllLicenseRisksForAssetVersionPaged(tx *gorm.DB, assetID uuid.UUID, assetVersionName string, pageInfo shared.PageInfo, search string, filter []shared.FilterQuery, sort []shared.SortQuery) (shared.Paged[models.LicenseRisk], error) {
	var count int64
	var licenseRisks = []models.LicenseRisk{}

	q := repository.Repository.GetDB(tx).Model(&models.LicenseRisk{}).Preload("Component").Preload("Artifacts").Joins(
		"LEFT JOIN artifact_license_risks ON artifact_license_risks.license_risk_id = license_risks.id").Where("license_risks.asset_version_name = ?", assetVersionName).Where("license_risks.asset_id = ?", assetID).Distinct()

	// apply filters
	for _, f := range filter {
		q = q.Where(f.SQL(), f.Value())
	}

	if search != "" && len(search) > 2 {
		q = q.Where("license_risks.final_license_decision ILIKE ? OR license_risks.component_purl ILIKE ? ", "%"+search+"%", "%"+search+"%")
	}

	err := q.Session(&gorm.Session{}).Distinct("license_risks.id").Count(&count).Error
	if err != nil {
		return shared.Paged[models.LicenseRisk]{}, err
	}

	err = q.Limit(pageInfo.PageSize).Offset((pageInfo.Page - 1) * pageInfo.PageSize).Find(&licenseRisks).Error
	if err != nil {
		return shared.Paged[models.LicenseRisk]{}, err
	}
	//TODO: check it
	return shared.NewPaged(pageInfo, count, licenseRisks), nil
}

func (repository *LicenseRiskRepository) GetByAssetID(tx *gorm.DB, assetID uuid.UUID) ([]models.LicenseRisk, error) {
	var licenseRisks = []models.LicenseRisk{}

	err := repository.db.Where("asset_id = ? ", assetID).Find(&licenseRisks).Error
	if err != nil {
		return nil, err
	}

	return licenseRisks, nil
}

func (repository *LicenseRiskRepository) GetAllLicenseRisksForAssetVersion(assetID uuid.UUID, assetVersionName string) ([]models.LicenseRisk, error) {
	var result []models.LicenseRisk
	err := repository.db.Preload("Artifacts").Where("asset_id = ? AND asset_version_name = ?", assetID, assetVersionName).Find(&result).Error
	if err != nil {
		return result, err
	}
	return result, nil
}

func (repository *LicenseRiskRepository) GetLicenseRisksByOtherAssetVersions(tx *gorm.DB, assetVersionName string, assetID uuid.UUID) ([]models.LicenseRisk, error) {
	var licenseRisks = []models.LicenseRisk{}

	q := repository.Repository.GetDB(tx).Preload("Events", func(db *gorm.DB) *gorm.DB {
		return db.Order("created_at ASC")
	}).Preload("Artifacts").Where("license_risks.asset_version_name != ? AND license_risks.asset_id = ?", assetVersionName, assetID)

	if err := q.Find(&licenseRisks).Error; err != nil {
		return nil, err
	}
	return licenseRisks, nil
}

func (repository *LicenseRiskRepository) GetAllOverwrittenLicensesForAssetVersion(assetID uuid.UUID, assetVersionName string) ([]models.LicenseRisk, error) {
	var result []models.LicenseRisk
	err := repository.db.Where("asset_id = ? AND asset_version_name = ? AND state = ?", assetID, assetVersionName, dtos.VulnStateFixed).Find(&result).Error
	if err != nil {
		return result, err
	}
	return result, nil
}

func (repository *LicenseRiskRepository) MaybeGetLicenseOverwriteForComponent(assetID uuid.UUID, assetVersionName string, pURL packageurl.PackageURL) (models.LicenseRisk, error) {
	var result models.LicenseRisk
	err := repository.db.Where("asset_id = ? AND asset_version_name = ? AND component_purl = ? AND state = ?", assetID, assetVersionName, pURL.String(), dtos.VulnStateFixed).First(&result).Error
	if err != nil {
		return result, err
	}
	return result, nil
}

func (repository *LicenseRiskRepository) DeleteByComponentPurl(assetID uuid.UUID, assetVersionName string, pURL packageurl.PackageURL) error {
	return repository.db.Where("asset_id = ? AND asset_version_name = ? AND component_purl = ?", assetID, assetVersionName, pURL.String()).Delete(&models.LicenseRisk{}).Error
}

func (repository *LicenseRiskRepository) ListByArtifactName(assetVersionName string, assetID uuid.UUID, artifactName string) ([]models.LicenseRisk, error) {
	var licenseRisks = []models.LicenseRisk{}

	q := repository.db.Model(&models.LicenseRisk{}).
		Joins("JOIN artifact_license_risks ON artifact_license_risks.license_risk_id = license_risks.id").Joins("JOIN artifacts ON artifact_license_risks.artifact_artifact_name = artifacts.artifact_name AND artifact_license_risks.artifact_asset_version_name = artifacts.asset_version_name AND artifact_license_risks.artifact_asset_id = artifacts.asset_id").Where("artifacts.artifact_name = ? AND artifacts.asset_version_name = ? AND artifacts.asset_id = ?", artifactName, assetVersionName, assetID)

	err := q.Find(&licenseRisks).Error
	if err != nil {
		return nil, err
	}
	return licenseRisks, nil
}

func (repository *LicenseRiskRepository) ApplyAndSave(tx *gorm.DB, licenseRisk *models.LicenseRisk, vulnEvent *models.VulnEvent) error {
	if tx == nil {
		// we are not part of a parent transaction - create a new one
		return repository.Transaction(func(d *gorm.DB) error {
			_, err := repository.applyAndSave(d, licenseRisk, vulnEvent)
			return err
		})
	}

	_, err := repository.applyAndSave(tx, licenseRisk, vulnEvent)
	return err
}

func (repository *LicenseRiskRepository) applyAndSave(tx *gorm.DB, licenseRisk *models.LicenseRisk, ev *models.VulnEvent) (models.VulnEvent, error) {
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

func (repository *LicenseRiskRepository) Read(vulnID string) (models.LicenseRisk, error) {
	var licenseRisk models.LicenseRisk
	err := repository.db.Where("id = ?", vulnID).Preload("Artifacts").Preload("Events", func(db *gorm.DB) *gorm.DB {
		return db.Order("created_at ASC")
	}).Preload("Component").First(&licenseRisk).Error
	if err != nil {
		return licenseRisk, err
	}
	return licenseRisk, nil
}
