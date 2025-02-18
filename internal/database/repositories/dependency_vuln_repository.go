package repositories

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/utils"

	"github.com/l3montree-dev/devguard/internal/database/models"
	"gorm.io/gorm"
)

type dependencyVulnRepository struct {
	db core.DB
	VulnerabilityRepository[models.DependencyVuln]
}

func NewDependencyVulnRepository(db core.DB) *dependencyVulnRepository {
	if err := db.AutoMigrate(&models.DependencyVuln{}); err != nil {
		panic(err)
	}
	return &dependencyVulnRepository{
		db:                      db,
		VulnerabilityRepository: *NewVulnerabilityRepository[models.DependencyVuln](db),
	}
}

func (r *dependencyVulnRepository) GetDependencyVulnsByAssetID(tx core.DB, assetID uuid.UUID) ([]models.DependencyVuln, error) {
	var dependencyVulns []models.DependencyVuln = []models.DependencyVuln{}

	if err := r.Repository.GetDB(tx).Model(&models.DependencyVuln{}).Where("asset_id = ?", assetID).Find(&dependencyVulns).Error; err != nil {
		return nil, err
	}

	return dependencyVulns, nil

}

func (r *dependencyVulnRepository) GetDependencyVulnsByAssetVersion(tx *gorm.DB, assetVersionName string, assetID uuid.UUID) ([]models.DependencyVuln, error) {

	var dependencyVulns []models.DependencyVuln = []models.DependencyVuln{}
	if err := r.Repository.GetDB(tx).Where("asset_version_name = ? AND asset_id = ?", assetVersionName, assetID).Find(&dependencyVulns).Error; err != nil {
		return nil, err
	}
	return dependencyVulns, nil
}

func (r *dependencyVulnRepository) ListByScanner(assetVersionName string, assetID uuid.UUID, scannerID string) ([]models.DependencyVuln, error) {
	var dependencyVulns []models.DependencyVuln = []models.DependencyVuln{}
	if err := r.Repository.GetDB(r.db).Preload("CVE").Where("asset_version_name = ? AND asset_id = ? AND scanner_id = ?", assetVersionName, assetID, scannerID).Find(&dependencyVulns).Error; err != nil {
		return nil, err
	}
	return dependencyVulns, nil
}

type riskStats struct {
	TotalRisk           float64 `json:"total_risk"`
	AvgRisk             float64 `json:"avg_risk"`
	MaxRisk             float64 `json:"max_risk"`
	DependencyVulnCount int64   `json:"dependencyVuln_count"`
	PackageName         string  `json:"package_name"`
}

func (r *dependencyVulnRepository) GetByAssetVersionPaged(tx core.DB, assetVersionName string, assetID uuid.UUID, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery) (core.Paged[models.DependencyVuln], map[string]int, error) {
	var count int64
	var dependencyVulns []models.DependencyVuln = []models.DependencyVuln{}

	q := r.Repository.GetDB(tx).Model(&models.DependencyVuln{}).Joins("CVE").Where("dependencyVulns.asset_version_name = ?", assetVersionName).Where("dependencyVulns.asset_id = ?", assetID)

	// apply filters
	for _, f := range filter {
		q = q.Where(f.SQL(), f.Value())
	}
	if search != "" && len(search) > 2 {
		q = q.Where("(\"CVE\".description ILIKE ?  OR dependencyVulns.cve_id ILIKE ? OR component_purl ILIKE ?)", "%"+search+"%", "%"+search+"%", "%"+search+"%")
	}

	err := q.Distinct("dependencyVulns.component_purl").Count(&count).Error
	if err != nil {
		return core.Paged[models.DependencyVuln]{}, map[string]int{}, err
	}

	// get all dependencyVulns of the asset
	q = r.Repository.GetDB(tx).Model(&models.DependencyVuln{}).Joins("CVE").Where("dependencyVulns.asset_version_name = ?", assetVersionName).Where("dependencyVulns.asset_id = ?", assetID)

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
		Where("f.asset_version_name = ?", assetVersionName).
		Where("f.asset_id = ?", assetID).
		Group("components.purl").Limit(pageInfo.PageSize).Offset((pageInfo.Page - 1) * pageInfo.PageSize)

	// apply sorting
	if len(sort) > 0 {
		for _, s := range sort {
			packageNameQuery = packageNameQuery.Order(s.SQL())
		}
	} else {
		packageNameQuery = packageNameQuery.Order("max_risk DESC")
	}

	res := []riskStats{}
	if err := packageNameQuery.Scan(&res).Error; err != nil {
		return core.Paged[models.DependencyVuln]{}, map[string]int{}, err
	}

	packageNames := utils.Map(res, func(r riskStats) string {
		return r.PackageName
	})

	err = q.Where("dependencyVulns.component_purl IN (?)", packageNames).Order("raw_risk_assessment DESC").Find(&dependencyVulns).Error

	if err != nil {
		return core.Paged[models.DependencyVuln]{}, map[string]int{}, err
	}
	// order the dependencyVulns based on the package name ordering
	packageNameIndexMap := make(map[string]int)
	for i, name := range packageNames {
		packageNameIndexMap[name] = i
	}

	return core.NewPaged(pageInfo, count, dependencyVulns), packageNameIndexMap, nil
}

func (r *dependencyVulnRepository) GetDependencyVulnsByAssetVersionPagedAndFlat(tx core.DB, assetVersionName string, assetID uuid.UUID, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery) (core.Paged[models.DependencyVuln], error) {
	return r.GetDependencyVulnsPaged(tx, []string{assetVersionName}, []string{assetID.String()}, pageInfo, search, filter, sort)
}

func (r *dependencyVulnRepository) GetAllOpenDependencyVulnsByAssetVersion(tx core.DB, assetVersionName string, assetID uuid.UUID) ([]models.DependencyVuln, error) {
	var dependencyVulns []models.DependencyVuln = []models.DependencyVuln{}
	if err := r.Repository.GetDB(tx).Where("asset_version_name = ? AND asset_id = ? AND state = ?", assetVersionName, assetID, models.VulnStateOpen).Find(&dependencyVulns).Error; err != nil {
		return nil, err
	}
	return dependencyVulns, nil
}

func (g dependencyVulnRepository) Read(id string) (models.DependencyVuln, error) {
	var t models.DependencyVuln
	err := g.db.Preload("CVE.Weaknesses").Preload("Events", func(db core.DB) core.DB {
		return db.Order("created_at ASC")
	}).Preload("CVE").Preload("CVE.Exploits").First(&t, "id = ?", id).Error

	return t, err
}

func (g dependencyVulnRepository) ReadDependencyVulnWithAssetEvents(id string) (models.DependencyVuln, []models.VulnEvent, error) {
	var t models.DependencyVuln
	err := g.db.Preload("CVE.Weaknesses").Preload("CVE").Preload("CVE.Exploits").First(&t, "id = ?", id).Error

	if err != nil {
		return models.DependencyVuln{}, []models.VulnEvent{}, err
	}

	var VulnEvents []models.VulnEvent
	// get the asset id - and read dependencyVulns with the same cve id and asset id
	err = g.db.Model(&models.VulnEvent{}).Where("dependencyVuln_id IN ?", g.db.Model(models.DependencyVuln{}).Where(
		"asset_id = ? AND cve_id = ?", t.AssetID, t.CVEID,
	)).Order("created_at ASC").Find(&t.Events).Error
	if err != nil {
		return models.DependencyVuln{}, VulnEvents, err
	}

	return t, VulnEvents, err
}

func (r *dependencyVulnRepository) GetDependencyVulnsByPurl(tx core.DB, purl []string) ([]models.DependencyVuln, error) {

	var dependencyVulns []models.DependencyVuln = []models.DependencyVuln{}
	if len(purl) == 0 {
		return dependencyVulns, nil
	}

	if err := r.Repository.GetDB(tx).Preload("Events").Joins("CVE").Where("component_purl IN ?", purl).Find(&dependencyVulns).Error; err != nil {
		return nil, err
	}

	return dependencyVulns, nil
}

func (r *dependencyVulnRepository) FindByTicketID(tx core.DB, ticketID string) (models.DependencyVuln, error) {
	var dependencyVuln models.DependencyVuln
	if err := r.Repository.GetDB(tx).Where("ticket_id = ?", ticketID).First(&dependencyVuln).Error; err != nil {
		return models.DependencyVuln{}, err
	}
	return dependencyVuln, nil
}

func (r *dependencyVulnRepository) GetOrgFromDependencyVulnID(tx core.DB, dependencyVulnID string) (models.Org, error) {
	var org models.Org
	if err := r.GetDB(tx).Raw("SELECT organizations.* from organizations left join projects p on organizations.id = p.organization_id left join assets a on p.id = a.project_id left join asset_version av on a.id = av.asset_id left join dependencyVulns f on av.id = f.asset_version_id where f.id = ?", dependencyVulnID).First(&org).Error; err != nil {
		return models.Org{}, err
	}
	return org, nil
}
func (r *dependencyVulnRepository) GetDependencyVulnsPaged(tx core.DB, assetVersionNamesSubquery any, assetVersionAssetIdSubquery any, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery) (core.Paged[models.DependencyVuln], error) {
	var dependencyVulns []models.DependencyVuln = []models.DependencyVuln{}

	q := r.Repository.GetDB(tx).Model(&models.DependencyVuln{}).Preload("Events").Joins("CVE").Where("dependencyVulns.asset_version_name IN (?) AND dependencyVulns.asset_id IN (?)", assetVersionNamesSubquery, assetVersionAssetIdSubquery)

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
		return core.Paged[models.DependencyVuln]{}, err
	}

	err = q.Limit(pageInfo.PageSize).Offset((pageInfo.Page - 1) * pageInfo.PageSize).Find(&dependencyVulns).Error

	if err != nil {
		return core.Paged[models.DependencyVuln]{}, err
	}

	return core.NewPaged(pageInfo, count, dependencyVulns), nil
}

func (r *dependencyVulnRepository) GetDefaultDependencyVulnsByProjectIdPaged(tx core.DB, projectID uuid.UUID, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery) (core.Paged[models.DependencyVuln], error) {

	subQueryAssetIDs := r.Repository.GetDB(tx).Model(&models.Asset{}).Select("assets.id").Where("project_id = ?", projectID)

	subQuery := r.Repository.GetDB(tx).Model(&models.AssetVersion{}).Select("name").Where("asset_id IN (?) AND default_branch = ?", subQueryAssetIDs, true)

	return r.GetDependencyVulnsPaged(tx, subQuery, subQueryAssetIDs, pageInfo, search, filter, sort)
}

func (r *dependencyVulnRepository) GetDefaultDependencyVulnsByOrgIdPaged(tx core.DB, userAllowedProjectIds []string, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery) (core.Paged[models.DependencyVuln], error) {

	subQueryAssetIDs := r.Repository.GetDB(tx).Model(&models.Asset{}).Select("assets.id").Where("assets.project_id IN (?)", userAllowedProjectIds)

	subQuery1 := r.Repository.GetDB(tx).Model(&models.AssetVersion{}).Select("name").Where("asset_id IN (?) AND default_branch = ?", subQueryAssetIDs, true)

	return r.GetDependencyVulnsPaged(tx, subQuery1, subQueryAssetIDs, pageInfo, search, filter, sort)
}

func (r *dependencyVulnRepository) GetDependencyVulnAssetIDByDependencyVulnID(tx core.DB, dependencyVulnID string) (string, error) {
	var dependencyVulnAssetID string
	if err := r.Repository.GetDB(tx).Model(&models.DependencyVuln{}).Select("dependencyVuln_asset_id").Where("id = ?", dependencyVulnID).Row().Scan(&dependencyVulnAssetID); err != nil {
		return "", err
	}
	return dependencyVulnAssetID, nil
}
