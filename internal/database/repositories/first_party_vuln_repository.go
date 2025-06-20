package repositories

import (
	"os"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
)

type firstPartyVulnerabilityRepository struct {
	db core.DB
	VulnerabilityRepository[models.FirstPartyVuln]
}

func NewFirstPartyVulnerabilityRepository(db core.DB) *firstPartyVulnerabilityRepository {
	if os.Getenv("DISABLE_AUTOMIGRATE") != "true" {
		if err := db.AutoMigrate(&models.FirstPartyVuln{}); err != nil {
			panic(err)
		}
	}
	return &firstPartyVulnerabilityRepository{
		db:                      db,
		VulnerabilityRepository: *NewVulnerabilityRepository[models.FirstPartyVuln](db),
	}
}

func (repository *firstPartyVulnerabilityRepository) ListByScanner(assetVersionName string, assetID uuid.UUID, scannerID string) ([]models.FirstPartyVuln, error) {
	var vulns = []models.FirstPartyVuln{}
	scannerID = "%" + scannerID + "%"
	if err := repository.Repository.GetDB(repository.db).Where("asset_version_name = ? AND asset_id = ? AND scanner_ids LIKE ?", assetVersionName, assetID, scannerID).Find(&vulns).Error; err != nil {
		return nil, err
	}
	return vulns, nil
}

func (repository *firstPartyVulnerabilityRepository) GetByAssetVersion(tx core.DB, assetVersionName string, assetID uuid.UUID) ([]models.FirstPartyVuln, error) {
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

func (repository *firstPartyVulnerabilityRepository) GetByAssetVersionPaged(tx core.DB, assetVersionName string, assetID uuid.UUID, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery) (core.Paged[models.FirstPartyVuln], map[string]int, error) {

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
		return core.Paged[models.FirstPartyVuln]{}, nil, err
	}

	err = q.Limit(pageInfo.PageSize).Offset((pageInfo.Page - 1) * pageInfo.PageSize).Find(&firstPartyVulns).Error

	if err != nil {
		return core.Paged[models.FirstPartyVuln]{}, nil, err
	}
	//TODO: check it
	return core.NewPaged(pageInfo, count, firstPartyVulns), nil, nil
}

func (repository firstPartyVulnerabilityRepository) Read(id string) (models.FirstPartyVuln, error) {
	var t models.FirstPartyVuln
	err := repository.db.Preload("Events", func(db core.DB) core.DB {
		return db.Order("created_at ASC")
	}).First(&t, "id = ?", id).Error

	return t, err
}

// TODO: change it
func (repository *firstPartyVulnerabilityRepository) GetFirstPartyVulnsPaged(tx core.DB, assetVersionNamesSubquery any, assetVersionAssetIDSubquery any, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery) (core.Paged[models.FirstPartyVuln], error) {
	var firstPartyVulns = []models.FirstPartyVuln{}

	q := repository.Repository.GetDB(tx).Model(&models.FirstPartyVuln{}).Where("first_party_vulnerabilities.asset_version_name IN (?) AND first_party_vulnerabilities.asset_id IN (?)", assetVersionNamesSubquery, assetVersionAssetIDSubquery)

	var count int64

	err := q.Count(&count).Error
	if err != nil {
		return core.Paged[models.FirstPartyVuln]{}, err
	}

	err = q.Limit(pageInfo.PageSize).Offset((pageInfo.Page - 1) * pageInfo.PageSize).Find(&firstPartyVulns).Error

	if err != nil {
		return core.Paged[models.FirstPartyVuln]{}, err
	}

	return core.NewPaged(pageInfo, count, firstPartyVulns), nil
}

func (repository *firstPartyVulnerabilityRepository) GetDefaultFirstPartyVulnsByProjectIDPaged(tx core.DB, projectID uuid.UUID, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery) (core.Paged[models.FirstPartyVuln], error) {
	subQueryAssetIDs := repository.Repository.GetDB(tx).Model(&models.Asset{}).Select("assets.id").Where("project_id = ?", projectID)

	subQuery := repository.Repository.GetDB(tx).Model(&models.AssetVersion{}).Select("name").Where("asset_id IN (?) AND default_branch = ?", subQueryAssetIDs, true)

	return repository.GetFirstPartyVulnsPaged(tx, subQuery, subQueryAssetIDs, pageInfo, search, filter, sort)
}

func (repository *firstPartyVulnerabilityRepository) GetDefaultFirstPartyVulnsByOrgIDPaged(tx core.DB, userAllowedProjectIds []string, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery) (core.Paged[models.FirstPartyVuln], error) {

	subQueryAssetIDs := repository.Repository.GetDB(tx).Model(&models.Asset{}).Select("assets.id").Where("assets.project_id IN (?)", userAllowedProjectIds)

	subQuery1 := repository.Repository.GetDB(tx).Model(&models.AssetVersion{}).Select("name").Where("asset_id IN (?) AND default_branch = ?", subQueryAssetIDs, true)

	return repository.GetFirstPartyVulnsPaged(tx, subQuery1, subQueryAssetIDs, pageInfo, search, filter, sort)
}

func (repository *firstPartyVulnerabilityRepository) GetOrgFromVulnID(tx core.DB, firstPartyVulnID string) (models.Org, error) {
	var org models.Org
	if err := repository.GetDB(tx).Raw("SELECT organizations.* from organizations left join projects p on organizations.id = p.organization_id left join assets a on p.id = a.project_id left join firstPartyVulns f on a.id = f.asset_id where f.id = ?", firstPartyVulnID).First(&org).Error; err != nil {
		return models.Org{}, err
	}
	return org, nil
}

func (repository *firstPartyVulnerabilityRepository) ApplyAndSave(tx core.DB, firstPartyVuln *models.FirstPartyVuln, ev *models.VulnEvent) error {
	if tx == nil {
		// we are not part of a parent transaction - create a new one
		return repository.Transaction(func(d core.DB) error {
			_, err := repository.applyAndSave(d, firstPartyVuln, ev)
			return err
		})
	}

	_, err := repository.applyAndSave(tx, firstPartyVuln, ev)
	return err
}

func (repository *firstPartyVulnerabilityRepository) applyAndSave(tx core.DB, firstPartyVuln *models.FirstPartyVuln, ev *models.VulnEvent) (models.VulnEvent, error) {
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
