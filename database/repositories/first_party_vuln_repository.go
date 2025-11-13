package repositories

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/shared"
	"gorm.io/gorm"
)

type firstPartyVulnerabilityRepository struct {
	db *gorm.DB
	VulnerabilityRepository[models.FirstPartyVuln]
}

func NewFirstPartyVulnerabilityRepository(db *gorm.DB) *firstPartyVulnerabilityRepository {
	return &firstPartyVulnerabilityRepository{
		db:                      db,
		VulnerabilityRepository: *NewVulnerabilityRepository[models.FirstPartyVuln](db),
	}
}

func (repository *firstPartyVulnerabilityRepository) GetFirstPartyVulnsByOtherAssetVersions(tx *gorm.DB, assetVersionName string, assetID uuid.UUID, scannerID string) ([]models.FirstPartyVuln, error) {
	var vulns = []models.FirstPartyVuln{}

	query := repository.Repository.GetDB(tx).Model(&models.FirstPartyVuln{}).Preload("Events", func(db *gorm.DB) *gorm.DB {
		return db.Order("created_at ASC")
	}).Where("asset_version_name != ? AND asset_id = ? ", assetVersionName, assetID)

	if scannerID != "" {
		// scanner ids is a string array separated by whitespaces
		query = query.Where("? = ANY(string_to_array(scanner_ids, ' '))", scannerID)
	}

	err := query.Find(&vulns).Error
	if err != nil {
		return nil, err
	}

	return vulns, nil
}

func (repository *firstPartyVulnerabilityRepository) ListByScanner(assetVersionName string, assetID uuid.UUID, scannerID string) ([]models.FirstPartyVuln, error) {
	// tx *gorm.DB missing (or chosen not to be implemented) ?
	var vulns = []models.FirstPartyVuln{}

	query := repository.Repository.GetDB(repository.db).Where("asset_version_name = ? AND asset_id = ? ", assetVersionName, assetID)
	if scannerID != "" {
		// scanner ids is a string array separated by whitespaces
		query = query.Where("? = ANY(string_to_array(scanner_ids, ' '))", scannerID)
	}

	err := query.Find(&vulns).Error
	if err != nil {
		return nil, err
	}

	return vulns, nil
}

func (repository *firstPartyVulnerabilityRepository) GetByAssetVersion(tx *gorm.DB, assetVersionName string, assetID uuid.UUID) ([]models.FirstPartyVuln, error) {
	var firstPartyVulns = []models.FirstPartyVuln{}
	err := repository.Repository.GetDB(tx).Model(&models.FirstPartyVuln{}).
		Where("first_party_vulnerabilities.asset_version_name = ?", assetVersionName).
		Where("first_party_vulnerabilities.asset_id = ?", assetID).
		Find(&firstPartyVulns).Error
	if err != nil {
		return nil, err
	}
	return firstPartyVulns, nil
}

func (repository *firstPartyVulnerabilityRepository) GetByAssetVersionPaged(tx *gorm.DB, assetVersionName string, assetID uuid.UUID, pageInfo shared.PageInfo, search string, filter []shared.FilterQuery, sort []shared.SortQuery) (shared.Paged[models.FirstPartyVuln], map[string]int, error) {

	var count int64
	var firstPartyVulns = []models.FirstPartyVuln{}

	q := repository.Repository.GetDB(tx).Model(&models.FirstPartyVuln{}).Where("first_party_vulnerabilities.asset_version_name = ?", assetVersionName).Where("first_party_vulnerabilities.asset_id = ?", assetID)

	// apply filters
	for _, f := range filter {
		q = q.Where(f.SQL(), f.Value())
	}
	if search != "" && len(search) > 2 {
		q = q.Where("\"first_party_vulnerabilities\".message ILIKE ?  OR first_party_vulnerabilities.uri ILIKE ? OR rule_description ILIKE ? OR first_party_vulnerabilities.scanner_ids ILIKE ?", "%"+search+"%", "%"+search+"%", "%"+search+"%", "%"+search+"%")
	}

	err := q.Count(&count).Error
	if err != nil {
		return shared.Paged[models.FirstPartyVuln]{}, nil, err
	}

	err = q.Limit(pageInfo.PageSize).Offset((pageInfo.Page - 1) * pageInfo.PageSize).Find(&firstPartyVulns).Error

	if err != nil {
		return shared.Paged[models.FirstPartyVuln]{}, nil, err
	}
	//TODO: check it
	return shared.NewPaged(pageInfo, count, firstPartyVulns), nil, nil
}

func (repository firstPartyVulnerabilityRepository) Read(id string) (models.FirstPartyVuln, error) {
	var t models.FirstPartyVuln
	err := repository.db.Preload("Events", func(db *gorm.DB) *gorm.DB {
		return db.Order("created_at ASC")
	}).First(&t, "id = ?", id).Error

	return t, err
}

// TODO: change it
func (repository *firstPartyVulnerabilityRepository) GetFirstPartyVulnsPaged(tx *gorm.DB, assetVersionNamesSubquery any, assetVersionAssetIDSubquery any, pageInfo shared.PageInfo, search string, filter []shared.FilterQuery, sort []shared.SortQuery) (shared.Paged[models.FirstPartyVuln], error) {
	var firstPartyVulns = []models.FirstPartyVuln{}

	q := repository.Repository.GetDB(tx).Model(&models.FirstPartyVuln{}).Where("first_party_vulnerabilities.asset_version_name IN (?) AND first_party_vulnerabilities.asset_id IN (?)", assetVersionNamesSubquery, assetVersionAssetIDSubquery)

	var count int64

	err := q.Count(&count).Error
	if err != nil {
		return shared.Paged[models.FirstPartyVuln]{}, err
	}

	err = q.Limit(pageInfo.PageSize).Offset((pageInfo.Page - 1) * pageInfo.PageSize).Find(&firstPartyVulns).Error

	if err != nil {
		return shared.Paged[models.FirstPartyVuln]{}, err
	}

	return shared.NewPaged(pageInfo, count, firstPartyVulns), nil
}

func (repository *firstPartyVulnerabilityRepository) GetDefaultFirstPartyVulnsByProjectIDPaged(tx *gorm.DB, projectID uuid.UUID, pageInfo shared.PageInfo, search string, filter []shared.FilterQuery, sort []shared.SortQuery) (shared.Paged[models.FirstPartyVuln], error) {
	subQueryAssetIDs := repository.Repository.GetDB(tx).Model(&models.Asset{}).Select("assets.id").Where("project_id = ?", projectID)

	subQuery := repository.Repository.GetDB(tx).Model(&models.AssetVersion{}).Select("name").Where("asset_id IN (?) AND default_branch = ?", subQueryAssetIDs, true)

	return repository.GetFirstPartyVulnsPaged(tx, subQuery, subQueryAssetIDs, pageInfo, search, filter, sort)
}

func (repository *firstPartyVulnerabilityRepository) GetDefaultFirstPartyVulnsByOrgIDPaged(tx *gorm.DB, userAllowedProjectIds []string, pageInfo shared.PageInfo, search string, filter []shared.FilterQuery, sort []shared.SortQuery) (shared.Paged[models.FirstPartyVuln], error) {

	subQueryAssetIDs := repository.Repository.GetDB(tx).Model(&models.Asset{}).Select("assets.id").Where("assets.project_id IN (?)", userAllowedProjectIds)

	subQuery1 := repository.Repository.GetDB(tx).Model(&models.AssetVersion{}).Select("name").Where("asset_id IN (?) AND default_branch = ?", subQueryAssetIDs, true)

	return repository.GetFirstPartyVulnsPaged(tx, subQuery1, subQueryAssetIDs, pageInfo, search, filter, sort)
}

func (repository *firstPartyVulnerabilityRepository) GetOrgFromVulnID(tx *gorm.DB, firstPartyVulnID string) (models.Org, error) {
	var org models.Org
	if err := repository.GetDB(tx).Raw("SELECT organizations.* from organizations left join projects p on organizations.id = p.organization_id left join assets a on p.id = a.project_id left join first_party_vulnerabilities f on a.id = f.asset_id where f.id = ?", firstPartyVulnID).First(&org).Error; err != nil {
		return models.Org{}, err
	}
	return org, nil
}

func (repository *firstPartyVulnerabilityRepository) ApplyAndSave(tx *gorm.DB, firstPartyVuln *models.FirstPartyVuln, ev *models.VulnEvent) error {
	if tx == nil {
		// we are not part of a parent transaction - create a new one
		return repository.Transaction(func(d *gorm.DB) error {
			_, err := repository.applyAndSave(d, firstPartyVuln, ev)
			return err
		})
	}

	_, err := repository.applyAndSave(tx, firstPartyVuln, ev)
	return err
}

func (repository *firstPartyVulnerabilityRepository) applyAndSave(tx *gorm.DB, firstPartyVuln *models.FirstPartyVuln, ev *models.VulnEvent) (models.VulnEvent, error) {
	// apply the event on the dependencyVuln
	ev.Apply(firstPartyVuln)
	// save the event
	if err := repository.Save(tx, firstPartyVuln); err != nil {
		return models.VulnEvent{}, err
	}
	if err := repository.GetDB(tx).Save(ev).Error; err != nil {
		return models.VulnEvent{}, err
	}
	return *ev, nil
}
