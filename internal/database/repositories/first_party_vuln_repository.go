package repositories

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
)

type firstPartyVulnerabilityRepository struct {
	db core.DB
	VulnerabilityRepository[models.FirstPartyVulnerability]
}

func NewFirstPartyVulnerabilityRepository(db core.DB) *firstPartyVulnerabilityRepository {
	if err := db.AutoMigrate(&models.FirstPartyVulnerability{}); err != nil {
		panic(err)
	}
	return &firstPartyVulnerabilityRepository{
		db:                      db,
		VulnerabilityRepository: *NewVulnerabilityRepository[models.FirstPartyVulnerability](db),
	}
}

func (r *firstPartyVulnerabilityRepository) ListByScanner(assetVersionName string, assetID uuid.UUID, scannerID string) ([]models.FirstPartyVulnerability, error) {
	var vulns []models.FirstPartyVulnerability = []models.FirstPartyVulnerability{}
	if err := r.Repository.GetDB(r.db).Where("asset_version_name = ? AND asset_id = ? AND scanner_id LIKE %?%", assetVersionName, assetID, scannerID).Find(&vulns).Error; err != nil {
		return nil, err
	}
	return vulns, nil
}

func (r *firstPartyVulnerabilityRepository) GetByAssetVersionPaged(tx core.DB, assetVersionName string, assetID uuid.UUID, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery) (core.Paged[models.FirstPartyVulnerability], map[string]int, error) {

	var count int64
	var firstPartyVulns []models.FirstPartyVulnerability = []models.FirstPartyVulnerability{}

	q := r.Repository.GetDB(tx).Model(&models.FirstPartyVulnerability{}).Where("firstPartyVulns.asset_version_name = ?", assetVersionName).Where("firstPartyVulns.asset_id = ?", assetID)

	/* 	// apply filters
	   	for _, f := range filter {
	   		q = q.Where(f.SQL(), f.Value())
	   	}
	   	if search != "" && len(search) > 2 {
	   		q = q.Where("(\"CVE\".description ILIKE ?  OR dependencyVulns.cve_id ILIKE ? OR component_purl ILIKE ?)", "%"+search+"%", "%"+search+"%", "%"+search+"%")
	   	}

	*/

	err := q.Count(&count).Error
	if err != nil {
		return core.Paged[models.FirstPartyVulnerability]{}, nil, err
	}

	err = q.Limit(pageInfo.PageSize).Offset((pageInfo.Page - 1) * pageInfo.PageSize).Find(&firstPartyVulns).Error

	if err != nil {
		return core.Paged[models.FirstPartyVulnerability]{}, nil, err
	}
	//TODO: check it
	return core.NewPaged(pageInfo, count, firstPartyVulns), nil, nil
}

func (r *firstPartyVulnerabilityRepository) GetFirstPartyVulnsByAssetIdPagedAndFlat(tx core.DB, assetVersionName string, assetID uuid.UUID, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery) (core.Paged[models.FirstPartyVulnerability], error) {
	return r.GetFirstPartyVulnsPaged(tx, []string{assetVersionName}, []string{assetID.String()}, pageInfo, search, filter, sort)
}

func (r firstPartyVulnerabilityRepository) Read(id string) (models.FirstPartyVulnerability, error) {
	var t models.FirstPartyVulnerability
	err := r.db.First(&t, id).Error

	return t, err
}

func (g firstPartyVulnerabilityRepository) ReadDependencyVulnWithAssetVersionEvents(id string) (models.FirstPartyVulnerability, []models.VulnEvent, error) {
	var t models.FirstPartyVulnerability
	err := g.db.First(&t, "id = ?", id).Error

	if err != nil {
		return models.FirstPartyVulnerability{}, []models.VulnEvent{}, err
	}

	var VulnEvents []models.VulnEvent
	// get the asset id - and read dependencyVulns with the same cve id and asset id
	err = g.db.Model(&models.VulnEvent{}).Where("id IN ?", g.db.Model(models.DependencyVuln{}).Where(
		"asset_id = ?", t.AssetID,
	)).Order("created_at ASC").Find(&t.Events).Error
	if err != nil {
		return models.FirstPartyVulnerability{}, VulnEvents, err
	}

	return t, VulnEvents, err
}

// TODO: change it
func (r *firstPartyVulnerabilityRepository) GetFirstPartyVulnsPaged(tx core.DB, assetVersionNamesSubquery any, assetVersionAssetIdSubquery any, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery) (core.Paged[models.FirstPartyVulnerability], error) {
	var firstPartyVulns []models.FirstPartyVulnerability = []models.FirstPartyVulnerability{}

	q := r.Repository.GetDB(tx).Model(&models.FirstPartyVulnerability{}).Where("firstPartyVulns.asset_version_name IN (?) AND firstPartyVulns.asset_id IN (?)", assetVersionNamesSubquery, assetVersionAssetIdSubquery)

	var count int64

	err := q.Count(&count).Error
	if err != nil {
		return core.Paged[models.FirstPartyVulnerability]{}, err
	}

	err = q.Limit(pageInfo.PageSize).Offset((pageInfo.Page - 1) * pageInfo.PageSize).Find(&firstPartyVulns).Error

	if err != nil {
		return core.Paged[models.FirstPartyVulnerability]{}, err
	}

	return core.NewPaged(pageInfo, count, firstPartyVulns), nil
}

func (r *firstPartyVulnerabilityRepository) GetDefaultFirstPartyVulnsByProjectIdPaged(tx core.DB, projectID uuid.UUID, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery) (core.Paged[models.FirstPartyVulnerability], error) {
	subQueryAssetIDs := r.Repository.GetDB(tx).Model(&models.Asset{}).Select("assets.id").Where("project_id = ?", projectID)

	subQuery := r.Repository.GetDB(tx).Model(&models.AssetVersion{}).Select("name").Where("asset_id IN (?) AND default_branch = ?", subQueryAssetIDs, true)

	return r.GetFirstPartyVulnsPaged(tx, subQuery, subQueryAssetIDs, pageInfo, search, filter, sort)
}

func (r *firstPartyVulnerabilityRepository) GetDefaultFirstPartyVulnsByOrgIdPaged(tx core.DB, userAllowedProjectIds []string, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery) (core.Paged[models.FirstPartyVulnerability], error) {

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
