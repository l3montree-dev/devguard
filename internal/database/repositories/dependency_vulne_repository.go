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

func (r *DependencyVulnerability) ListByScanner(assetID uuid.UUID, scannerID string) ([]models.DependencyVulnerability, error) {
	var vulns []models.DependencyVulnerability = []models.DependencyVulnerability{}
	if err := r.Repository.GetDB(r.db).Preload("CVE").Where("asset_id = ? AND scanner_id = ?", assetID, scannerID).Find(&vulns).Error; err != nil {
		return nil, err
	}
	return vulns, nil
}

func (r *DependencyVulnerability) GetByAssetIdPaged(tx core.DB, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery, assetId uuid.UUID) (core.Paged[models.DependencyVulnerability], map[string]int, error) {
	var count int64
	var dependencyVulns []models.DependencyVulnerability = []models.DependencyVulnerability{}

	q := r.Repository.GetDB(tx).Model(&models.DependencyVulnerability{}).Joins("CVE").Where("dependencyVulns.asset_id = ?", assetId)

	// apply filters
	for _, f := range filter {
		q = q.Where(f.SQL(), f.Value())
	}
	if search != "" && len(search) > 2 {
		q = q.Where("(\"CVE\".description ILIKE ?  OR dependencyVulns.cve_id ILIKE ? OR component_purl ILIKE ?)", "%"+search+"%", "%"+search+"%", "%"+search+"%")
	}

	err := q.Distinct("dependencyVulns.component_purl").Count(&count).Error
	if err != nil {
		return core.Paged[models.DependencyVulnerability]{}, map[string]int{}, err
	}

	// get all dependencyVulns of the asset
	q = r.Repository.GetDB(tx).Model(&models.DependencyVulnerability{}).Joins("CVE").Where("dependencyVulns.asset_id = ?", assetId)

	// apply filters
	for _, f := range filter {
		q = q.Where(f.SQL(), f.Value())
	}

	if search != "" && len(search) > 2 {
		q = q.Where("(\"CVE\".description ILIKE ?  OR dependencyVulns.cve_id ILIKE ? OR component_purl ILIKE ?)", "%"+search+"%", "%"+search+"%", "%"+search+"%")
	}

	packageNameQuery := r.GetDB(tx).Table("components").
		Select("SUM(f.raw_risk_assessment) as total_risk, AVG(f.raw_risk_assessment) as avg_risk, MAX(f.raw_risk_assessment) as max_risk, COUNT(f.id) as dependencyVuln_count, components.purl as package_name").
		Joins("INNER JOIN dependencyVulns f ON components.purl = f.component_purl").
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

	err = q.Where("dependencyVulns.component_purl IN (?)", packageNames).Order("raw_risk_assessment DESC").Find(&dependencyVulns).Error

	if err != nil {
		return core.Paged[models.DependencyVulnerability]{}, map[string]int{}, err
	}
	// order the dependencyVulns based on the package name ordering
	packageNameIndexMap := make(map[string]int)
	for i, name := range packageNames {
		packageNameIndexMap[name] = i
	}

	return core.NewPaged(pageInfo, count, dependencyVulns), packageNameIndexMap, nil
}

func (r *DependencyVulnerability) GetDependencyVulnsByAssetIdPagedAndFlat(tx core.DB, assetId uuid.UUID, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery) (core.Paged[models.DependencyVulnerability], error) {
	return r.GetDependencyVulnsPaged(tx, []string{assetId.String()}, pageInfo, search, filter, sort)
}

func (r DependencyVulnerability) Read(id string) (models.DependencyVulnerability, error) {
	var t models.DependencyVulnerability
	err := r.db.Preload("CVE.Weaknesses").Preload("Events", func(db core.DB) core.DB {
		return db.Order("created_at ASC")
	}).Preload("CVE").Preload("CVE.Exploits").First(&t, "id = ?", id).Error

	return t, err
}

func (r *DependencyVulnerability) GetDependencyVulnsByPurl(tx core.DB, purl []string) ([]models.DependencyVulnerability, error) {

	var dependencyVulns []models.DependencyVulnerability = []models.DependencyVulnerability{}
	if len(purl) == 0 {
		return dependencyVulns, nil
	}

	if err := r.Repository.GetDB(tx).Preload("Events").Joins("CVE").Where("component_purl IN ?", purl).Find(&dependencyVulns).Error; err != nil {
		return nil, err
	}

	return dependencyVulns, nil
}

func (r *DependencyVulnerability) GetDependencyVulnsPaged(tx core.DB, assetIdInSubQuery any, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery) (core.Paged[models.DependencyVulnerability], error) {
	var dependencyVulns []models.DependencyVulnerability = []models.DependencyVulnerability{}

	q := r.Repository.GetDB(tx).Model(&models.DependencyVulnerability{}).Preload("Events").Joins("CVE").Where("dependencyVulns.asset_id IN (?)", assetIdInSubQuery)

	// apply filters
	for _, f := range filter {
		q = q.Where(f.SQL(), f.Value())
	}
	if search != "" && len(search) > 2 {
		q = q.Where("(\"CVE\".description ILIKE ?  OR dependencyVulns.cve_id ILIKE ? OR component_purl ILIKE ?)", "%"+search+"%", "%"+search+"%", "%"+search+"%")
	}

	// apply sorting
	if len(sort) > 0 {
		for _, s := range sort {
			q = q.Order(s.SQL())
		}
	} else {
		q = q.Order("dependencyVulns.cve_id DESC")
	}

	var count int64

	err := q.Count(&count).Error
	if err != nil {
		return core.Paged[models.DependencyVulnerability]{}, err
	}

	err = q.Limit(pageInfo.PageSize).Offset((pageInfo.Page - 1) * pageInfo.PageSize).Find(&dependencyVulns).Error

	if err != nil {
		return core.Paged[models.DependencyVulnerability]{}, err
	}

	return core.NewPaged(pageInfo, count, dependencyVulns), nil
}

func (r *DependencyVulnerability) GetDependencyVulnsByProjectIdPaged(tx core.DB, projectID uuid.UUID, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery) (core.Paged[models.DependencyVulnerability], error) {
	subQuery := r.Repository.GetDB(tx).Model(&models.Asset{}).Select("id").Where("project_id = ?", projectID)

	return r.GetDependencyVulnsPaged(tx, subQuery, pageInfo, search, filter, sort)
}

func (r *DependencyVulnerability) GetDependencyVulnsByOrgIdPaged(tx core.DB, userAllowedProjectIds []string, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery) (core.Paged[models.DependencyVulnerability], error) {

	subQuery := r.Repository.GetDB(tx).Model(&models.Asset{}).Select("assets.id").Where("assets.project_id IN (?)", userAllowedProjectIds)

	return r.GetDependencyVulnsPaged(tx, subQuery, pageInfo, search, filter, sort)
}
