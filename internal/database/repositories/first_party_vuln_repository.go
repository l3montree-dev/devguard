package repositories

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
)

type FirstPartyVulnerabilityRepository struct {
	db core.DB
	VulnerabilityRepository[models.FirstPartyVulnerability]
}

func NewFirstPartyVulnerabilityRepository(db core.DB) *FirstPartyVulnerabilityRepository {
	if err := db.AutoMigrate(&models.FirstPartyVulnerability{}); err != nil {
		panic(err)
	}
	return &FirstPartyVulnerabilityRepository{
		db:                      db,
		VulnerabilityRepository: *NewVulnerabilityRepository[models.FirstPartyVulnerability](db),
	}
}

// TODO: change it
func (r *FirstPartyVulnerabilityRepository) GetByAssetIdPaged(tx core.DB, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery, assetId uuid.UUID) (core.Paged[models.FirstPartyVulnerability], map[string]int, error) {
	var count int64
	var flaws []models.FirstPartyVulnerability = []models.FirstPartyVulnerability{}

	q := r.Repository.GetDB(tx).Model(&models.FirstPartyVulnerability{}).Where("flaws.asset_id = ?", assetId)

	// apply filters
	for _, f := range filter {
		q = q.Where(f.SQL(), f.Value())
	}

	if search != "" && len(search) > 2 {
		q = q.Where("(\"CVE\".description ILIKE ?  OR flaws.cve_id ILIKE ? OR component_purl ILIKE ?)", "%"+search+"%", "%"+search+"%", "%"+search+"%")
	}

	err := q.Distinct("flaws.component_purl").Count(&count).Error
	if err != nil {
		return core.Paged[models.FirstPartyVulnerability]{}, map[string]int{}, err
	}

	// get all flaws of the asset
	q = r.Repository.GetDB(tx).Model(&models.DependencyVulnerability{}).Joins("CVE").Where("flaws.asset_id = ?", assetId)

	// apply filters
	for _, f := range filter {
		q = q.Where(f.SQL(), f.Value())
	}

	if search != "" && len(search) > 2 {
		q = q.Where("(\"CVE\".description ILIKE ?  OR flaws.cve_id ILIKE ? OR component_purl ILIKE ?)", "%"+search+"%", "%"+search+"%", "%"+search+"%")
	}

	packageNameQuery := r.GetDB(tx).Table("components").
		Select("SUM(f.raw_risk_assessment) as total_risk, AVG(f.raw_risk_assessment) as avg_risk, MAX(f.raw_risk_assessment) as max_risk, COUNT(f.id) as flaw_count, components.purl as package_name").
		Joins("INNER JOIN flaws f ON components.purl = f.component_purl").
		Where("f.asset_id = ?", assetId.String()).
		Group("components.purl").Limit(pageInfo.PageSize).Offset((pageInfo.Page - 1) * pageInfo.PageSize)

	// apply sorting
	if len(sort) > 0 {
		for _, s := range sort {
			packageNameQuery = packageNameQuery.Order(s.SQL())
		}
	} else {
		packageNameQuery = packageNameQuery.Order("max_risk DESC")
	}

	res := []VulnStats{}
	if err := packageNameQuery.Scan(&res).Error; err != nil {
		return core.Paged[models.FirstPartyVulnerability]{}, map[string]int{}, err
	}

	packageNames := utils.Map(res, func(r VulnStats) string {
		return r.PackageName
	})

	err = q.Where("flaws.component_purl IN (?)", packageNames).Order("raw_risk_assessment DESC").Find(&flaws).Error

	if err != nil {
		return core.Paged[models.FirstPartyVulnerability]{}, map[string]int{}, err
	}
	// order the flaws based on the package name ordering
	packageNameIndexMap := make(map[string]int)
	for i, name := range packageNames {
		packageNameIndexMap[name] = i
	}

	return core.NewPaged(pageInfo, count, flaws), packageNameIndexMap, nil
}

func (r *FirstPartyVulnerabilityRepository) GetFlawsByAssetIdPagedAndFlat(tx core.DB, assetId uuid.UUID, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery) (core.Paged[models.FirstPartyVulnerability], error) {
	return r.GetFlawsPaged(tx, []string{assetId.String()}, pageInfo, search, filter, sort)
}

func (r FirstPartyVulnerabilityRepository) Read(id string) (models.FirstPartyVulnerability, error) {
	var t models.FirstPartyVulnerability
	err := r.db.First(&t, id).Error

	return t, err
}

// TODO: change it
func (r *FirstPartyVulnerabilityRepository) GetFlawsPaged(tx core.DB, assetIdInSubQuery any, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery) (core.Paged[models.FirstPartyVulnerability], error) {
	var flaws []models.FirstPartyVulnerability = []models.FirstPartyVulnerability{}

	q := r.Repository.GetDB(tx).Model(&models.FirstPartyVulnerability{}).Where("flaws.asset_id IN (?)", assetIdInSubQuery)

	// apply filters
	for _, f := range filter {
		q = q.Where(f.SQL(), f.Value())
	}
	if search != "" && len(search) > 2 {
		q = q.Where("(\"CVE\".description ILIKE ?  OR flaws.cve_id ILIKE ? OR component_purl ILIKE ?)", "%"+search+"%", "%"+search+"%", "%"+search+"%")
	}

	// apply sorting
	if len(sort) > 0 {
		for _, s := range sort {
			q = q.Order(s.SQL())
		}
	} else {
		q = q.Order("flaws.cve_id DESC")
	}

	var count int64

	err := q.Count(&count).Error
	if err != nil {
		return core.Paged[models.FirstPartyVulnerability]{}, err
	}

	err = q.Limit(pageInfo.PageSize).Offset((pageInfo.Page - 1) * pageInfo.PageSize).Find(&flaws).Error

	if err != nil {
		return core.Paged[models.FirstPartyVulnerability]{}, err
	}

	return core.NewPaged(pageInfo, count, flaws), nil
}

func (r *FirstPartyVulnerabilityRepository) GetFlawsByProjectIdPaged(tx core.DB, projectID uuid.UUID, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery) (core.Paged[models.FirstPartyVulnerability], error) {
	subQuery := r.Repository.GetDB(tx).Model(&models.Asset{}).Select("id").Where("project_id = ?", projectID)

	return r.GetFlawsPaged(tx, subQuery, pageInfo, search, filter, sort)
}

func (r *FirstPartyVulnerabilityRepository) GetFlawsByOrgIdPaged(tx core.DB, userAllowedProjectIds []string, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery) (core.Paged[models.FirstPartyVulnerability], error) {

	subQuery := r.Repository.GetDB(tx).Model(&models.Asset{}).Select("assets.id").Where("assets.project_id IN (?)", userAllowedProjectIds)

	return r.GetFlawsPaged(tx, subQuery, pageInfo, search, filter, sort)
}
