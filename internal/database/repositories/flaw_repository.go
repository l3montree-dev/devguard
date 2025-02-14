package repositories

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/utils"

	"github.com/l3montree-dev/devguard/internal/database/models"
)

type DependencyVulnerability struct {
	db core.DB
	VulnerabilityRepository[models.DependencyVulnerability]
}

func NewDependencyVulnerability(db core.DB) *DependencyVulnerability {
	if err := db.AutoMigrate(&models.DependencyVulnerability{}); err != nil {
		panic(err)
	}
	return &DependencyVulnerability{
		db:                      db,
		VulnerabilityRepository: *NewVulnerabilityRepository[models.DependencyVulnerability](db),
	}
}

func (r *DependencyVulnerability) GetByAssetIdPaged(tx core.DB, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery, assetId uuid.UUID) (core.Paged[models.DependencyVulnerability], map[string]int, error) {
	var count int64
	var vulns []models.DependencyVulnerability = []models.DependencyVulnerability{}

	q := r.Repository.GetDB(tx).Model(&models.DependencyVulnerability{}).Joins("CVE").Where("vulns.asset_id = ?", assetId)

	// apply filters
	for _, f := range filter {
		q = q.Where(f.SQL(), f.Value())
	}
	if search != "" && len(search) > 2 {
		q = q.Where("(\"CVE\".description ILIKE ?  OR vulns.cve_id ILIKE ? OR component_purl ILIKE ?)", "%"+search+"%", "%"+search+"%", "%"+search+"%")
	}

	err := q.Distinct("vulns.component_purl").Count(&count).Error
	if err != nil {
		return core.Paged[models.DependencyVulnerability]{}, map[string]int{}, err
	}

	// get all vulns of the asset
	q = r.Repository.GetDB(tx).Model(&models.DependencyVulnerability{}).Joins("CVE").Where("vulns.asset_id = ?", assetId)

	// apply filters
	for _, f := range filter {
		q = q.Where(f.SQL(), f.Value())
	}

	if search != "" && len(search) > 2 {
		q = q.Where("(\"CVE\".description ILIKE ?  OR vulns.cve_id ILIKE ? OR component_purl ILIKE ?)", "%"+search+"%", "%"+search+"%", "%"+search+"%")
	}

	packageNameQuery := r.GetDB(tx).Table("components").
		Select("SUM(f.raw_risk_assessment) as total_risk, AVG(f.raw_risk_assessment) as avg_risk, MAX(f.raw_risk_assessment) as max_risk, COUNT(f.id) as vuln_count, components.purl as package_name").
		Joins("INNER JOIN vulns f ON components.purl = f.component_purl").
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
		return core.Paged[models.DependencyVulnerability]{}, map[string]int{}, err
	}

	packageNames := utils.Map(res, func(r VulnStats) string {
		return r.PackageName
	})

	err = q.Where("vulns.component_purl IN (?)", packageNames).Order("raw_risk_assessment DESC").Find(&vulns).Error

	if err != nil {
		return core.Paged[models.DependencyVulnerability]{}, map[string]int{}, err
	}
	// order the vulns based on the package name ordering
	packageNameIndexMap := make(map[string]int)
	for i, name := range packageNames {
		packageNameIndexMap[name] = i
	}

	return core.NewPaged(pageInfo, count, vulns), packageNameIndexMap, nil
}

func (r *DependencyVulnerability) GetVulnsByAssetIdPagedAndFlat(tx core.DB, assetId uuid.UUID, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery) (core.Paged[models.DependencyVulnerability], error) {
	return r.GetVulnsPaged(tx, []string{assetId.String()}, pageInfo, search, filter, sort)
}

func (r DependencyVulnerability) Read(id string) (models.DependencyVulnerability, error) {
	var t models.DependencyVulnerability
	err := r.db.Preload("CVE.Weaknesses").Preload("Events", func(db core.DB) core.DB {
		return db.Order("created_at ASC")
	}).Preload("CVE").Preload("CVE.Exploits").First(&t, "id = ?", id).Error

	return t, err
}

func (r *DependencyVulnerability) GetVulnsByPurl(tx core.DB, purl []string) ([]models.DependencyVulnerability, error) {

	var vulns []models.DependencyVulnerability = []models.DependencyVulnerability{}
	if len(purl) == 0 {
		return vulns, nil
	}

	if err := r.Repository.GetDB(tx).Preload("Events").Joins("CVE").Where("component_purl IN ?", purl).Find(&vulns).Error; err != nil {
		return nil, err
	}

	return vulns, nil
}

func (r *DependencyVulnerability) GetVulnsPaged(tx core.DB, assetIdInSubQuery any, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery) (core.Paged[models.DependencyVulnerability], error) {
	var vulns []models.DependencyVulnerability = []models.DependencyVulnerability{}

	q := r.Repository.GetDB(tx).Model(&models.DependencyVulnerability{}).Preload("Events").Joins("CVE").Where("vulns.asset_id IN (?)", assetIdInSubQuery)

	// apply filters
	for _, f := range filter {
		q = q.Where(f.SQL(), f.Value())
	}
	if search != "" && len(search) > 2 {
		q = q.Where("(\"CVE\".description ILIKE ?  OR vulns.cve_id ILIKE ? OR component_purl ILIKE ?)", "%"+search+"%", "%"+search+"%", "%"+search+"%")
	}

	// apply sorting
	if len(sort) > 0 {
		for _, s := range sort {
			q = q.Order(s.SQL())
		}
	} else {
		q = q.Order("vulns.cve_id DESC")
	}

	var count int64

	err := q.Count(&count).Error
	if err != nil {
		return core.Paged[models.DependencyVulnerability]{}, err
	}

	err = q.Limit(pageInfo.PageSize).Offset((pageInfo.Page - 1) * pageInfo.PageSize).Find(&vulns).Error

	if err != nil {
		return core.Paged[models.DependencyVulnerability]{}, err
	}

	return core.NewPaged(pageInfo, count, vulns), nil
}

func (r *DependencyVulnerability) GetVulnsByProjectIdPaged(tx core.DB, projectID uuid.UUID, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery) (core.Paged[models.DependencyVulnerability], error) {
	subQuery := r.Repository.GetDB(tx).Model(&models.Asset{}).Select("id").Where("project_id = ?", projectID)

	return r.GetVulnsPaged(tx, subQuery, pageInfo, search, filter, sort)
}

func (r *DependencyVulnerability) GetVulnsByOrgIdPaged(tx core.DB, userAllowedProjectIds []string, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery) (core.Paged[models.DependencyVulnerability], error) {

	subQuery := r.Repository.GetDB(tx).Model(&models.Asset{}).Select("assets.id").Where("assets.project_id IN (?)", userAllowedProjectIds)

	return r.GetVulnsPaged(tx, subQuery, pageInfo, search, filter, sort)
}
