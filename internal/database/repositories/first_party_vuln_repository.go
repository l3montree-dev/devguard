package repositories

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
)

type firstPartyVulnerabilityRepository struct {
	db core.DB
	VulnerabilityRepository[models.FirstPartyVuln]
}

func NewFirstPartyVulnerabilityRepository(db core.DB) *firstPartyVulnerabilityRepository {
	if err := db.AutoMigrate(&models.FirstPartyVuln{}); err != nil {
		panic(err)
	}
	return &firstPartyVulnerabilityRepository{
		db:                      db,
		VulnerabilityRepository: *NewVulnerabilityRepository[models.FirstPartyVuln](db),
	}
}

func (r *firstPartyVulnerabilityRepository) ListByScanner(assetVersionName string, assetID uuid.UUID, scannerID string) ([]models.FirstPartyVuln, error) {
	var vulns []models.FirstPartyVuln = []models.FirstPartyVuln{}
	scannerID = "%" + scannerID + "%"
	if err := r.Repository.GetDB(r.db).Where("asset_version_name = ? AND asset_id = ? AND scanner_ids LIKE ?", assetVersionName, assetID, scannerID).Find(&vulns).Error; err != nil {
		return nil, err
	}
	return vulns, nil
}

func (r *firstPartyVulnerabilityRepository) GetByAssetVersionPaged(tx core.DB, assetVersionName string, assetID uuid.UUID, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery) (core.Paged[models.FirstPartyVuln], map[string]int, error) {

	var count int64
	var firstPartyVulns []models.FirstPartyVuln = []models.FirstPartyVuln{}

	q := r.Repository.GetDB(tx).Model(&models.FirstPartyVuln{}).Where("first_party_vulnerabilities.asset_version_name = ?", assetVersionName).Where("first_party_vulnerabilities.asset_id = ?", assetID)

	// apply filters
	for _, f := range filter {
		q = q.Where(f.SQL(), f.Value())
	}
	if search != "" && len(search) > 2 {
		q = q.Where("(\"first_party_vulnerabilities\".message ILIKE ?  OR first_party_vulnerabilities.filename ILIKE ? OR rule_description ILIKE ?", "%"+search+"%", "%"+search+"%", "%"+search+"%")
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

func (g firstPartyVulnerabilityRepository) ReadDependencyVulnWithAssetVersionEvents(id string) (models.FirstPartyVuln, []models.VulnEvent, error) {
	var t models.FirstPartyVuln
	err := g.db.First(&t, "id = ?", id).Error

	if err != nil {
		return models.FirstPartyVuln{}, []models.VulnEvent{}, err
	}

	var VulnEvents []models.VulnEvent
	// get the asset id - and read dependencyVulns with the same cve id and asset id
	err = g.db.Model(&models.VulnEvent{}).Where("id IN ?", g.db.Model(models.DependencyVuln{}).Where(
		"asset_id = ?", t.AssetID,
	)).Order("created_at ASC").Find(&t.Events).Error
	if err != nil {
		return models.FirstPartyVuln{}, VulnEvents, err
	}

	return t, VulnEvents, err
}

// TODO: change it
func (r *firstPartyVulnerabilityRepository) GetFirstPartyVulnsPaged(tx core.DB, assetVersionNamesSubquery any, assetVersionAssetIdSubquery any, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery) (core.Paged[models.FirstPartyVuln], error) {
	var firstPartyVulns []models.FirstPartyVuln = []models.FirstPartyVuln{}

	q := r.Repository.GetDB(tx).Model(&models.FirstPartyVuln{}).Where("first_party_vulnerabilities.asset_version_name IN (?) AND first_party_vulnerabilities.asset_id IN (?)", assetVersionNamesSubquery, assetVersionAssetIdSubquery)

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

func (r *firstPartyVulnerabilityRepository) GetDefaultFirstPartyVulnsByProjectIdPaged(tx core.DB, projectID uuid.UUID, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery) (core.Paged[models.FirstPartyVuln], error) {
	subQueryAssetIDs := r.Repository.GetDB(tx).Model(&models.Asset{}).Select("assets.id").Where("project_id = ?", projectID)

	subQuery := r.Repository.GetDB(tx).Model(&models.AssetVersion{}).Select("name").Where("asset_id IN (?) AND default_branch = ?", subQueryAssetIDs, true)

	return r.GetFirstPartyVulnsPaged(tx, subQuery, subQueryAssetIDs, pageInfo, search, filter, sort)
}

func (r *firstPartyVulnerabilityRepository) GetDefaultFirstPartyVulnsByOrgIdPaged(tx core.DB, userAllowedProjectIds []string, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery) (core.Paged[models.FirstPartyVuln], error) {

	subQueryAssetIDs := r.Repository.GetDB(tx).Model(&models.Asset{}).Select("assets.id").Where("assets.project_id IN (?)", userAllowedProjectIds)

	subQuery1 := r.Repository.GetDB(tx).Model(&models.AssetVersion{}).Select("name").Where("asset_id IN (?) AND default_branch = ?", subQueryAssetIDs, true)

	return r.GetFirstPartyVulnsPaged(tx, subQuery1, subQueryAssetIDs, pageInfo, search, filter, sort)
}

func (r *firstPartyVulnerabilityRepository) GetOrgFromVulnID(tx core.DB, firstPartyVulnID string) (models.Org, error) {
	var org models.Org
	if err := r.GetDB(tx).Raw("SELECT organizations.* from organizations left join projects p on organizations.id = p.organization_id left join assets a on p.id = a.project_id left join firstPartyVulns f on a.id = f.asset_id where f.id = ?", firstPartyVulnID).First(&org).Error; err != nil {
		return models.Org{}, err
	}
	return org, nil
}

func (r *firstPartyVulnerabilityRepository) ApplyAndSave(tx core.DB, firstPartyVuln *models.FirstPartyVuln, ev *models.VulnEvent) error {
	if tx == nil {
		// we are not part of a parent transaction - create a new one
		return r.Transaction(func(d core.DB) error {
			_, err := r.applyAndSave(d, firstPartyVuln, ev)
			return err
		})
	}

	_, err := r.applyAndSave(tx, firstPartyVuln, ev)
	return err
}

func (r *firstPartyVulnerabilityRepository) applyAndSave(tx core.DB, firstPartyVuln *models.FirstPartyVuln, ev *models.VulnEvent) (models.VulnEvent, error) {
	// apply the event on the dependencyVuln
	ev.Apply(firstPartyVuln)
	// save the event
	if err := r.VulnerabilityRepository.Save(tx, firstPartyVuln); err != nil {
		return models.VulnEvent{}, err
	}
	if err := r.GetDB(tx).Save(ev).Error; err != nil {
		return models.VulnEvent{}, err
	}
	return *ev, nil
}
