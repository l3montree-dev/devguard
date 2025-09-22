package repositories

import (
	"fmt"
	"log/slog"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/common"
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

func (repository *dependencyVulnRepository) GetDependencyVulnsByAssetVersion(tx *gorm.DB, assetVersionName string, assetID uuid.UUID, artifactName *string) ([]models.DependencyVuln, error) {

	var dependencyVulns = []models.DependencyVuln{}
	q := repository.Repository.GetDB(tx).Preload("Events").Preload("CVE").Preload("CVE.Exploits").Preload("Artifacts").Where("dependency_vulns.asset_version_name = ? AND dependency_vulns.asset_id = ?", assetVersionName, assetID)

	if artifactName != nil {
		q = q.Where(`EXISTS (
        SELECT 1 FROM artifact_dependency_vulns adv 
        WHERE adv.dependency_vuln_id = dependency_vulns.id 
            AND adv.artifact_artifact_name = ? 
            AND adv.artifact_asset_version_name = ? 
            AND adv.artifact_asset_id = ?
    	)`, artifactName, assetVersionName, assetID)
	}

	if err := q.Find(&dependencyVulns).Error; err != nil {
		return nil, err
	}
	return dependencyVulns, nil
}

func (repository *dependencyVulnRepository) GetDependencyVulnsByOtherAssetVersions(tx core.DB, assetVersionName string, assetID uuid.UUID) ([]models.DependencyVuln, error) {
	var dependencyVulns = []models.DependencyVuln{}

	q := repository.Repository.GetDB(tx).Preload("Events").Preload("CVE").Preload("CVE.Exploits").Where("dependency_vulns.asset_version_name != ? AND dependency_vulns.asset_id = ?", assetVersionName, assetID)

	if err := q.Find(&dependencyVulns).Error; err != nil {
		return nil, err
	}
	return dependencyVulns, nil
}

func (repository *dependencyVulnRepository) GetDependencyVulnsByDefaultAssetVersion(tx core.DB, assetID uuid.UUID, artifactName *string) ([]models.DependencyVuln, error) {
	subQuery := repository.Repository.GetDB(tx).Model(&models.AssetVersion{}).Select("name").Where("asset_id IN (?) AND default_branch = ?", assetID, true)

	var dependencyVulns = []models.DependencyVuln{}
	q := repository.Repository.GetDB(tx).Preload("CVE").Preload("Events").Preload("CVE.Exploits").Where("dependency_vulns.asset_version_name IN (?) AND dependency_vulns.asset_id = ?", subQuery, assetID)

	if artifactName != nil {
		q = q.Joins("JOIN artifact_dependency_vulns ON artifact_dependency_vulns.dependency_vuln_id = dependency_vulns.id").Joins("JOIN artifacts ON artifact_dependency_vulns.artifact_artifact_name = artifacts.artifact_name AND artifact_dependency_vulns.artifact_asset_version_name = artifacts.asset_version_name AND artifact_dependency_vulns.artifact_asset_id = artifacts.asset_id").Where("artifacts.artifact_name = ? AND artifacts.asset_id = ? AND artifacts.asset_version_name IN (?)", artifactName, assetID, subQuery)
	}

	if err := q.Find(&dependencyVulns).Error; err != nil {
		return nil, err
	}

	return dependencyVulns, nil
}

func (repository *dependencyVulnRepository) ListByAssetAndAssetVersion(assetVersionName string, assetID uuid.UUID) ([]models.DependencyVuln, error) {
	var dependencyVulns = []models.DependencyVuln{}
	if err := repository.Repository.GetDB(repository.db).Preload("Artifacts").Preload("CVE").Preload("CVE.Exploits").Where("asset_version_name = ? AND asset_id = ?", assetVersionName, assetID).Find(&dependencyVulns).Error; err != nil {
		return nil, err
	}
	return dependencyVulns, nil
}

func (repository *dependencyVulnRepository) ListUnfixedByAssetAndAssetVersion(assetVersionName string, assetID uuid.UUID, artifactName *string) ([]models.DependencyVuln, error) {
	var dependencyVulns = []models.DependencyVuln{}
	q := repository.Repository.GetDB(repository.db).Preload("Artifacts").Preload("CVE").Preload("Events").Preload("CVE.Exploits").Where("dependency_vulns.asset_version_name = ? AND dependency_vulns.asset_id = ? AND dependency_vulns.state != ?", assetVersionName, assetID, models.VulnStateFixed)

	if artifactName != nil {
		// scanner ids is a string array separated by whitespaces
		q = q.Joins("JOIN artifact_dependency_vulns ON artifact_dependency_vulns.dependency_vuln_id = dependency_vulns.id").Joins("JOIN artifacts ON artifact_dependency_vulns.artifact_artifact_name = artifacts.artifact_name AND artifact_dependency_vulns.artifact_asset_version_name = artifacts.asset_version_name AND artifact_dependency_vulns.artifact_asset_id = artifacts.asset_id").Where("artifacts.artifact_name = ? AND artifacts.asset_version_name = ? AND artifacts.asset_id = ?", artifactName, assetVersionName, assetID)
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

	q := repository.Repository.GetDB(tx).Model(&models.DependencyVuln{}).Preload("Artifacts").Joins("LEFT JOIN artifact_dependency_vulns ON artifact_dependency_vulns.dependency_vuln_id = dependency_vulns.id").Joins("CVE").Where("dependency_vulns.asset_version_name = ?", assetVersionName).Where("dependency_vulns.asset_id = ?", assetID)

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
	}).Preload("CVE").Preload("CVE.Exploits").Preload("Artifacts").First(&t, "id = ?", id).Error

	return t, err
}

func (repository *dependencyVulnRepository) GetDependencyVulnsByPurl(tx core.DB, purl []string) ([]models.DependencyVuln, error) {

	var dependencyVulns = []models.DependencyVuln{}
	if len(purl) == 0 {
		return dependencyVulns, nil
	}

	if err := repository.Repository.GetDB(tx).Preload("Artifacts").Preload("Events").Joins("CVE").Where("component_purl IN ?", purl).Find(&dependencyVulns).Error; err != nil {
		return nil, err
	}

	return dependencyVulns, nil
}

func (repository *dependencyVulnRepository) GetDependencyVulnsPaged(tx core.DB, assetVersionNamesSubquery any, assetVersionAssetIDSubquery any, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery) (core.Paged[models.DependencyVuln], error) {
	var dependencyVulns = []models.DependencyVuln{}

	q := repository.Repository.GetDB(tx).Model(&models.DependencyVuln{}).Preload("Artifacts").Preload("Events").Joins("left join artifact_dependency_vulns ON artifact_dependency_vulns.dependency_vuln_id = dependency_vulns.id").Joins("CVE").Where("dependency_vulns.asset_version_name IN (?) AND dependency_vulns.asset_id IN (?)", assetVersionNamesSubquery, assetVersionAssetIDSubquery)

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
	if err := repository.Repository.GetDB(tx).Preload("Artifacts").Preload("CVE").Preload("CVE.Exploits").Where("ticket_id = ?", ticketID).First(&vuln).Error; err != nil {
		return vuln, err
	}
	return vuln, nil
}

func (repository *dependencyVulnRepository) GetHintsInOrganizationForVuln(tx core.DB, orgID uuid.UUID, pURL string, cveID string) (common.DependencyVulnHints, error) {
	type stateCount struct {
		State string `json:"state"`
		Count int    `json:"count"`
	}
	var hints common.DependencyVulnHints
	stateCounts := make([]stateCount, 0, 7)

	err := repository.GetDB(tx).Raw(`SELECT state, COUNT(*) as "count" FROM (
	SELECT DISTINCT d.asset_id, d.state as "state"
    FROM dependency_vulns d
    WHERE d.asset_id IN (
        SELECT id FROM assets WHERE project_id IN (
            SELECT id FROM projects WHERE organization_id = ?
        )
    )
    AND d.cve_id = ?
    AND d.component_purl = ?
	) AS distinct_deps GROUP BY state`, orgID, cveID, pURL).Scan(&stateCounts).Error
	if err != nil {
		return hints, err
	}
	// convert information from query to hints struct
	for _, state := range stateCounts {
		//maybe use VulnStates for this, needs conversion then
		switch state.State {
		case "open":
			hints.AmountOpen += state.Count
		case "fixed":
			hints.AmountFixed += state.Count
		case "accepted":
			hints.AmountAccepted += state.Count
		case "falsePositive":
			hints.AmountFalsePositive += state.Count
		case "markedForTransfer":
			hints.AmountMarkedForTransfer += state.Count
		default:
			slog.Error("invalid state", "state", state.State) //debug for now, can be removed later
			return hints, fmt.Errorf("invalid state")
		}
	}
	return hints, nil
}

func (repository *dependencyVulnRepository) GetAllOpenVulnsByAssetVersionNameAndAssetID(tx core.DB, artifactName *string, assetVersionName string, assetID uuid.UUID) ([]models.DependencyVuln, error) {
	var vulns = []models.DependencyVuln{}

	if artifactName != nil {
		if err := repository.Repository.GetDB(tx).Preload("CVE").Where("asset_version_name = ? AND asset_id = ? AND state = ? AND EXISTS(SELECT 1 from artifact_dependency_vulns WHERE dependency_vuln_id = id AND artifact_artifact_name = ?)", assetVersionName, assetID, models.VulnStateOpen, *artifactName).Find(&vulns).Error; err != nil {
			return nil, err
		}
		return vulns, nil
	} else {
		if err := repository.Repository.GetDB(tx).Preload("CVE").Where("asset_version_name = ? AND asset_id = ? AND state = ?", assetVersionName, assetID, models.VulnStateOpen).Find(&vulns).Error; err != nil {
			return nil, err
		}
		return vulns, nil
	}

}

// Override the base GetAllVulnsByAssetID method to preload artifacts
func (repository *dependencyVulnRepository) GetAllVulnsByAssetID(tx core.DB, assetID uuid.UUID) ([]models.DependencyVuln, error) {
	var vulns = []models.DependencyVuln{}
	if err := repository.Repository.GetDB(tx).Preload("CVE").Preload("Artifacts").Where("asset_id = ?", assetID).Find(&vulns).Error; err != nil {
		return nil, err
	}
	return vulns, nil
}

func (repository *dependencyVulnRepository) GetAllVulnsByAssetIDWithTicketIDs(tx core.DB, assetID uuid.UUID) ([]models.DependencyVuln, error) {
	var vulns = []models.DependencyVuln{}
	sql := fmt.Sprintf("SELECT * FROM dependency_vulns WHERE asset_id = '%s' AND ticket_id IS NOT NULL", assetID.String())
	err := repository.Repository.GetDB(tx).Raw(sql).Find(&vulns).Error
	if err != nil {
		return nil, err
	}
	return vulns, nil
}
