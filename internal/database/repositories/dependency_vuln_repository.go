package repositories

import (
	"os"

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
	if os.Getenv("DISABLE_AUTOMIGRATE") != "true" {
		if err := db.AutoMigrate(&models.DependencyVuln{}); err != nil {
			panic(err)
		}
	}
	return &dependencyVulnRepository{
		db:                      db,
		VulnerabilityRepository: *NewVulnerabilityRepository[models.DependencyVuln](db),
	}
}

func (repository *dependencyVulnRepository) ApplyAndSave(tx core.DB, dependencyVuln *models.DependencyVuln, vulnEvent *models.VulnEvent) error {
	if tx == nil {
		// we are not part of a parent transaction - create a new one
		return repository.Transaction(func(d core.DB) error {
			_, err := repository.applyAndSave(d, dependencyVuln, vulnEvent)
			return err
		})
	}

	_, err := repository.applyAndSave(tx, dependencyVuln, vulnEvent)
	return err
}

func (repository *dependencyVulnRepository) applyAndSave(tx core.DB, dependencyVuln *models.DependencyVuln, ev *models.VulnEvent) (models.VulnEvent, error) {
	// apply the event on the dependencyVuln
	ev.Apply(dependencyVuln)

	// run the updates in the transaction to keep a valid state
	err := repository.Save(tx, dependencyVuln)
	if err != nil {
		return models.VulnEvent{}, err
	}
	if err := repository.GetDB(tx).Save(ev).Error; err != nil {
		return models.VulnEvent{}, err
	}
	dependencyVuln.Events = append(dependencyVuln.Events, *ev)
	return *ev, nil
}

func (repository *dependencyVulnRepository) GetDependencyVulnsByAssetVersion(tx *gorm.DB, assetVersionName string, assetID uuid.UUID, scannerID string) ([]models.DependencyVuln, error) {

	var dependencyVulns = []models.DependencyVuln{}

	q := repository.Repository.GetDB(tx).Preload("Events").Preload("CVE").Preload("CVE.Exploits").Where("asset_version_name = ? AND asset_id = ?", assetVersionName, assetID)

	if scannerID != "" {
		// scanner ids is a string array separated by whitespaces
		q = q.Where("? = ANY(string_to_array(scanner_ids, ' '))", scannerID)
	}

	if err := q.Find(&dependencyVulns).Error; err != nil {
		return nil, err
	}
	return dependencyVulns, nil
}

func (repository *dependencyVulnRepository) GetDependencyVulnsByDefaultAssetVersion(tx core.DB, assetID uuid.UUID, scannerID string) ([]models.DependencyVuln, error) {
	subQuery := repository.Repository.GetDB(tx).Model(&models.AssetVersion{}).Select("name").Where("asset_id IN (?) AND default_branch = ?", assetID, true)

	var dependencyVulns = []models.DependencyVuln{}
	q := repository.Repository.GetDB(tx).Preload("CVE").Preload("Events").Preload("CVE.Exploits").Where("asset_version_name IN (?) AND asset_id = ?", subQuery, assetID)

	if scannerID != "" {
		// scanner ids is a string array separated by whitespaces
		q = q.Where("? = ANY(string_to_array(scanner_ids, ' '))", scannerID)
	}
	if err := q.Find(&dependencyVulns).Error; err != nil {
		return nil, err
	}

	return dependencyVulns, nil
}

func (repository *dependencyVulnRepository) ListByAssetAndAssetVersion(assetVersionName string, assetID uuid.UUID) ([]models.DependencyVuln, error) {
	var dependencyVulns = []models.DependencyVuln{}
	if err := repository.Repository.GetDB(repository.db).Preload("CVE").Preload("CVE.Exploits").Where("asset_version_name = ? AND asset_id = ?", assetVersionName, assetID).Find(&dependencyVulns).Error; err != nil {
		return nil, err
	}
	return dependencyVulns, nil
}

func (repository *dependencyVulnRepository) ListUnfixedByAssetAndAssetVersionAndScannerID(assetVersionName string, assetID uuid.UUID, scannerID string) ([]models.DependencyVuln, error) {
	var dependencyVulns = []models.DependencyVuln{}
	q := repository.Repository.GetDB(repository.db).Preload("CVE").Preload("Events").Preload("CVE.Exploits").Where("asset_version_name = ? AND asset_id = ? AND state != 'fixed'", assetVersionName, assetID)

	if scannerID != "" {
		// scanner ids is a string array separated by whitespaces
		q = q.Where("? = ANY(string_to_array(scanner_ids, ' '))", scannerID)
	}

	if err := q.Find(&dependencyVulns).Error; err != nil {
		return nil, err
	}
	return dependencyVulns, nil
}

type riskStats struct {
	TotalRisk           float64 `json:"total_risk"`
	AvgRisk             float64 `json:"avg_risk"`
	MaxRisk             float64 `json:"max_risk"`
	MaxCVSS             float64 `json:"max_cvss"`
	DependencyVulnCount int64   `json:"dependency_vuln_count"`
	PackageName         string  `json:"package_name"`
}

func (repository *dependencyVulnRepository) GetByAssetVersionPaged(tx core.DB, assetVersionName string, assetID uuid.UUID, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery) (core.Paged[models.DependencyVuln], map[string]int, error) {
	var count int64
	var dependencyVulns = []models.DependencyVuln{}

	q := repository.Repository.GetDB(tx).Model(&models.DependencyVuln{}).Joins("CVE").Where("dependency_vulns.asset_version_name = ?", assetVersionName).Where("dependency_vulns.asset_id = ?", assetID)

	// apply filters
	for _, f := range filter {
		q.Where(f.SQL(), f.Value())
	}
	if search != "" && len(search) > 2 {
		q.Where("(\"CVE\".description ILIKE ?  OR dependency_vulns.cve_id ILIKE ? OR dependency_vulns.scanner_ids ILIKE ? OR component_purl ILIKE ?)", "%"+search+"%", "%"+search+"%", "%"+search+"%", "%"+search+"%")
	}

	err := q.Session(&gorm.Session{}).Distinct("dependency_vulns.component_purl").Count(&count).Error
	if err != nil {
		return core.Paged[models.DependencyVuln]{}, map[string]int{}, err
	}

	packageNameQuery := repository.GetDB(tx).Table("components").
		Select("SUM(f.raw_risk_assessment) as total_risk, AVG(f.raw_risk_assessment) as avg_risk, MAX(f.raw_risk_assessment) as max_risk, MAX(c.cvss) as max_cvss, COUNT(f.id) as dependency_vuln_count, components.purl as package_name").
		Joins("INNER JOIN dependency_vulns f ON components.purl = f.component_purl").
		Joins("INNER JOIN cves c ON f.cve_id = c.cve").
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

	packageNames := utils.Map(res, func(repository riskStats) string {
		return repository.PackageName
	})

	err = q.Where("dependency_vulns.component_purl IN (?)", packageNames).Order("raw_risk_assessment DESC").Preload("CVE").Find(&dependencyVulns).Error

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

func (repository *dependencyVulnRepository) GetDependencyVulnsByAssetVersionPagedAndFlat(tx core.DB, assetVersionName string, assetID uuid.UUID, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery) (core.Paged[models.DependencyVuln], error) {
	return repository.GetDependencyVulnsPaged(tx, []string{assetVersionName}, []string{assetID.String()}, pageInfo, search, filter, sort)
}

func (repository dependencyVulnRepository) Read(id string) (models.DependencyVuln, error) {
	var t models.DependencyVuln
	err := repository.db.Preload("CVE.Weaknesses").Preload("Events", func(db core.DB) core.DB {
		return db.Order("created_at ASC")
	}).Preload("CVE").Preload("CVE.Exploits").First(&t, "id = ?", id).Error

	return t, err
}

func (repository *dependencyVulnRepository) GetDependencyVulnsByPurl(tx core.DB, purl []string) ([]models.DependencyVuln, error) {

	var dependencyVulns = []models.DependencyVuln{}
	if len(purl) == 0 {
		return dependencyVulns, nil
	}

	if err := repository.Repository.GetDB(tx).Preload("Events").Joins("CVE").Where("component_purl IN ?", purl).Find(&dependencyVulns).Error; err != nil {
		return nil, err
	}

	return dependencyVulns, nil
}

func (repository *dependencyVulnRepository) GetDependencyVulnsPaged(tx core.DB, assetVersionNamesSubquery any, assetVersionAssetIDSubquery any, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery) (core.Paged[models.DependencyVuln], error) {
	var dependencyVulns = []models.DependencyVuln{}

	q := repository.Repository.GetDB(tx).Model(&models.DependencyVuln{}).Preload("Events").Joins("CVE").Where("dependency_vulns.asset_version_name IN (?) AND dependency_vulns.asset_id IN (?)", assetVersionNamesSubquery, assetVersionAssetIDSubquery)

	// apply filters
	for _, f := range filter {
		q = q.Where(f.SQL(), f.Value())
	}
	if search != "" && len(search) > 2 {
		q = q.Where("(\"CVE\".description ILIKE ?  OR dependency_vulns.cve_id ILIKE ? OR component_purl ILIKE ?)", "%"+search+"%", "%"+search+"%", "%"+search+"%")
	}

	// apply sorting
	if len(sort) > 0 {
		for _, s := range sort {
			q = q.Order(s.SQL())
		}
	} else {
		q = q.Order("dependency_vulns.cve_id DESC")
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

func (repository *dependencyVulnRepository) GetDefaultDependencyVulnsByProjectIDPaged(tx core.DB, projectID uuid.UUID, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery) (core.Paged[models.DependencyVuln], error) {

	subQueryAssetIDs := repository.Repository.GetDB(tx).Model(&models.Asset{}).Select("assets.id").Where("project_id = ?", projectID)

	subQuery := repository.Repository.GetDB(tx).Model(&models.AssetVersion{}).Select("name").Where("asset_id IN (?) AND default_branch = ?", subQueryAssetIDs, true)

	return repository.GetDependencyVulnsPaged(tx, subQuery, subQueryAssetIDs, pageInfo, search, filter, sort)
}

func (repository *dependencyVulnRepository) GetDefaultDependencyVulnsByOrgIDPaged(tx core.DB, userAllowedProjectIds []string, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery) (core.Paged[models.DependencyVuln], error) {

	subQueryAssetIDs := repository.Repository.GetDB(tx).Model(&models.Asset{}).Select("assets.id").Where("assets.project_id IN (?)", userAllowedProjectIds)

	subQuery1 := repository.Repository.GetDB(tx).Model(&models.AssetVersion{}).Select("name").Where("asset_id IN (?) AND default_branch = ?", subQueryAssetIDs, true)

	return repository.GetDependencyVulnsPaged(tx, subQuery1, subQueryAssetIDs, pageInfo, search, filter, sort)

}

func (repository *dependencyVulnRepository) GetDependencyVulnAssetIDByDependencyVulnID(tx core.DB, dependencyVulnID string) (string, error) {
	var dependencyVulnAssetID string
	if err := repository.Repository.GetDB(tx).Model(&models.DependencyVuln{}).Select("dependency_vuln_asset_id").Where("id = ?", dependencyVulnID).Row().Scan(&dependencyVulnAssetID); err != nil {
		return "", err
	}
	return dependencyVulnAssetID, nil
}

func (repository *dependencyVulnRepository) GetOrgFromVulnID(tx core.DB, dependencyVulnID string) (models.Org, error) {
	var org models.Org
	if err := repository.GetDB(tx).Raw("SELECT organizations.* from organizations left join projects p on organizations.id = p.organization_id left join assets a on p.id = a.project_id left join dependency_vulns f on a.id = f.asset_id where f.id = ?", dependencyVulnID).First(&org).Error; err != nil {
		return models.Org{}, err
	}
	return org, nil
}

func (repository *dependencyVulnRepository) FindByTicketID(tx core.DB, ticketID string) (models.DependencyVuln, error) {
	var vuln models.DependencyVuln
	if err := repository.Repository.GetDB(tx).Preload("CVE").Preload("CVE.Exploits").Where("ticket_id = ?", ticketID).First(&vuln).Error; err != nil {
		return vuln, err
	}
	return vuln, nil
}
