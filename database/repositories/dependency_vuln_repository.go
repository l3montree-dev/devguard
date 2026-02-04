package repositories

import (
	"fmt"
	"log/slog"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/statemachine"
	"github.com/l3montree-dev/devguard/utils"

	"github.com/l3montree-dev/devguard/database/models"
	"gorm.io/gorm"
)

type dependencyVulnRepository struct {
	db *gorm.DB
	VulnerabilityRepository[models.DependencyVuln]
}

func NewDependencyVulnRepository(db *gorm.DB) *dependencyVulnRepository {
	return &dependencyVulnRepository{
		db:                      db,
		VulnerabilityRepository: *NewVulnerabilityRepository[models.DependencyVuln](db),
	}
}

func (repository *dependencyVulnRepository) ApplyAndSave(tx *gorm.DB, dependencyVuln *models.DependencyVuln, vulnEvent *models.VulnEvent) error {
	if tx == nil {
		// we are not part of a parent transaction - create a new one
		return repository.Transaction(func(d *gorm.DB) error {
			_, err := repository.applyAndSave(d, dependencyVuln, vulnEvent)
			return err
		})
	}

	_, err := repository.applyAndSave(tx, dependencyVuln, vulnEvent)
	return err
}

func (repository *dependencyVulnRepository) applyAndSave(tx *gorm.DB, dependencyVuln *models.DependencyVuln, ev *models.VulnEvent) (models.VulnEvent, error) {
	// apply the event on the dependencyVuln
	statemachine.Apply(dependencyVuln, *ev)

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
	q := repository.Repository.GetDB(tx).Preload("Events", func(db *gorm.DB) *gorm.DB {
		return db.Order("created_at ASC")
	}).Preload("CVE").Preload("CVE.Exploits").Preload("Artifacts").Where("dependency_vulns.asset_version_name = ? AND dependency_vulns.asset_id = ?", assetVersionName, assetID)

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

func (repository *dependencyVulnRepository) GetDependencyVulnsByOtherAssetVersions(tx *gorm.DB, assetVersionName string, assetID uuid.UUID) ([]models.DependencyVuln, error) {
	var dependencyVulns = []models.DependencyVuln{}

	q := repository.Repository.GetDB(tx).Preload("Events", func(db *gorm.DB) *gorm.DB {
		return db.Order("created_at ASC")
	}).Preload("CVE").Preload("CVE.Exploits").Where("dependency_vulns.asset_version_name != ? AND dependency_vulns.asset_id = ?", assetVersionName, assetID)

	if err := q.Find(&dependencyVulns).Error; err != nil {
		return nil, err
	}
	return dependencyVulns, nil
}

func (repository *dependencyVulnRepository) GetDependencyVulnsByDefaultAssetVersion(tx *gorm.DB, assetID uuid.UUID, artifactName *string) ([]models.DependencyVuln, error) {
	subQuery := repository.Repository.GetDB(tx).Model(&models.AssetVersion{}).Select("name").Where("asset_id IN (?) AND default_branch = ?", assetID, true)

	var dependencyVulns = []models.DependencyVuln{}
	q := repository.Repository.GetDB(tx).Preload("CVE").Preload("Events", func(db *gorm.DB) *gorm.DB {
		return db.Order("created_at ASC")
	}).Preload("CVE.Exploits").Where("dependency_vulns.asset_version_name IN (?) AND dependency_vulns.asset_id = ?", subQuery, assetID)

	if artifactName != nil {
		q = q.Joins("JOIN artifact_dependency_vulns ON artifact_dependency_vulns.dependency_vuln_id = dependency_vulns.id").Joins("JOIN artifacts ON artifact_dependency_vulns.artifact_artifact_name = artifacts.artifact_name AND artifact_dependency_vulns.artifact_asset_version_name = artifacts.asset_version_name AND artifact_dependency_vulns.artifact_asset_id = artifacts.asset_id").Where("artifacts.artifact_name = ? AND artifacts.asset_id = ? AND artifacts.asset_version_name IN (?)", artifactName, assetID, subQuery)
	}

	if err := q.Find(&dependencyVulns).Error; err != nil {
		return nil, err
	}

	return dependencyVulns, nil
}

func (repository *dependencyVulnRepository) ListByAssetIDWithoutHandledExternalEvents(assetID uuid.UUID, assetVersionName string, pageInfo shared.PageInfo, search string, filter []shared.FilterQuery, sort []shared.SortQuery) (shared.Paged[models.DependencyVuln], error) {
	var dependencyVulns = []models.DependencyVuln{}

	// Get all dependency vulns that have events with upstream=2 but no events with upstream=1
	q := repository.Repository.GetDB(repository.db).Model(&models.DependencyVuln{}).
		Preload("Artifacts").
		Preload("Events", func(db *gorm.DB) *gorm.DB {
			return db.Order("created_at ASC")
		}).
		Joins("CVE").
		Preload("CVE.Exploits").
		Joins("LEFT JOIN artifact_dependency_vulns ON artifact_dependency_vulns.dependency_vuln_id = dependency_vulns.id").
		Where(`asset_id = ? AND asset_version_name = ? AND EXISTS (
			SELECT 1 FROM vuln_events ve1 
			WHERE ve1.vuln_id = dependency_vulns.id 
			AND ve1.upstream = 2 AND NOT EXISTS (
				SELECT 1 FROM vuln_events ve2 
				WHERE ve2.vuln_id = dependency_vulns.id 
				AND ve2.created_at > ve1.created_at
				AND (ve2.upstream = 1 OR (ve2.upstream = 0 AND ve2.type IN ?))
			)
		)`, assetID, assetVersionName, []string{
			string(dtos.EventTypeAccepted),
			string(dtos.EventTypeFalsePositive),
		})

	// apply filters
	for _, f := range filter {
		q = q.Where(f.SQL(), f.Value())
	}

	// apply search
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

	// count total results
	var count int64
	err := q.Count(&count).Error
	if err != nil {
		return shared.Paged[models.DependencyVuln]{}, err
	}

	// apply pagination
	err = q.Limit(pageInfo.PageSize).Offset((pageInfo.Page - 1) * pageInfo.PageSize).Find(&dependencyVulns).Error
	if err != nil {
		return shared.Paged[models.DependencyVuln]{}, err
	}

	return shared.NewPaged(pageInfo, count, dependencyVulns), nil
}

func (repository *dependencyVulnRepository) ListByAssetAndAssetVersion(assetVersionName string, assetID uuid.UUID) ([]models.DependencyVuln, error) {
	var dependencyVulns = []models.DependencyVuln{}
	if err := repository.Repository.GetDB(repository.db).Preload("Artifacts").Preload("CVE").Preload("CVE.Exploits").Preload("Events", func(db *gorm.DB) *gorm.DB {
		return db.Order("created_at ASC")
	}).Where("asset_version_name = ? AND asset_id = ?", assetVersionName, assetID).Find(&dependencyVulns).Error; err != nil {
		return nil, err
	}
	return dependencyVulns, nil
}

func (repository *dependencyVulnRepository) ListUnfixedByAssetAndAssetVersion(tx shared.DB, assetVersionName string, assetID uuid.UUID, artifactName *string) ([]models.DependencyVuln, error) {
	var dependencyVulns = []models.DependencyVuln{}
	q := repository.Repository.GetDB(tx).Preload("Artifacts").Preload("CVE").Preload("Events", func(db *gorm.DB) *gorm.DB {
		return db.Order("created_at ASC")
	}).Preload("CVE.Exploits").Where("dependency_vulns.asset_version_name = ? AND dependency_vulns.asset_id = ? AND dependency_vulns.state != ?", assetVersionName, assetID, dtos.VulnStateFixed)

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

// FindByCVEAndComponentPurl finds all dependency vulnerabilities in an asset with the
// specified CVE and component PURL (regardless of path). This is used for applying
// status changes to all instances of a CVE+component combination.
func (repository *dependencyVulnRepository) FindByCVEAndComponentPurl(tx *gorm.DB, assetID uuid.UUID, cveID string, componentPurl string) ([]models.DependencyVuln, error) {
	var vulns []models.DependencyVuln
	err := repository.Repository.GetDB(tx).
		Preload("Events", func(db *gorm.DB) *gorm.DB {
			return db.Order("created_at ASC")
		}).
		Preload("Artifacts").
		Preload("CVE").
		Where("asset_id = ? AND cve_id = ? AND component_purl = ?", assetID, cveID, componentPurl).
		Find(&vulns).Error
	return vulns, err
}

func (repository *dependencyVulnRepository) GetByAssetVersionPaged(tx *gorm.DB, assetVersionName string, assetID uuid.UUID, pageInfo shared.PageInfo, search string, filter []shared.FilterQuery, sort []shared.SortQuery) (shared.Paged[models.DependencyVuln], map[string]int, error) {
	var count int64
	var dependencyVulns = []models.DependencyVuln{}

	q := repository.Repository.GetDB(tx).Model(&models.DependencyVuln{}).Preload("Artifacts").Joins("LEFT JOIN artifact_dependency_vulns ON artifact_dependency_vulns.dependency_vuln_id = dependency_vulns.id").Joins("CVE").Where("dependency_vulns.asset_version_name = ?", assetVersionName).Where("dependency_vulns.asset_id = ?", assetID).Distinct()

	// apply filters
	for _, f := range filter {
		q.Where(f.SQL(), f.Value())
	}

	if search != "" && len(search) > 2 {
		q.Where("(\"CVE\".description ILIKE ?  OR dependency_vulns.cve_id ILIKE ? OR component_purl ILIKE ?)", "%"+search+"%", "%"+search+"%", "%"+search+"%")
	}

	err := q.Session(&gorm.Session{}).Distinct("dependency_vulns.component_purl").Count(&count).Error
	if err != nil {
		return shared.Paged[models.DependencyVuln]{}, map[string]int{}, err
	}

	packageNameQuery := repository.GetDB(tx).Table("components").
		Select("SUM(dependency_vulns.raw_risk_assessment) as total_risk, AVG(dependency_vulns.raw_risk_assessment) as avg_risk, MAX(dependency_vulns.raw_risk_assessment) as max_risk, MAX(\"CVE\".cvss) as max_cvss, COUNT(dependency_vulns.id) as dependency_vuln_count, dependency_vulns.component_purl as package_name").
		Joins("RIGHT JOIN dependency_vulns ON components.id = dependency_vulns.component_purl AND dependency_vulns.asset_id = ? AND dependency_vulns.asset_version_name = ?", assetID, assetVersionName).
		Joins("LEFT JOIN artifact_dependency_vulns ON artifact_dependency_vulns.dependency_vuln_id = dependency_vulns.id").
		Joins("INNER JOIN cves \"CVE\" ON dependency_vulns.cve_id = \"CVE\".cve").
		Where("dependency_vulns.asset_version_name = ?", assetVersionName).
		Where("dependency_vulns.asset_id = ?", assetID).
		Group("dependency_vulns.component_purl").Limit(pageInfo.PageSize).Offset((pageInfo.Page - 1) * pageInfo.PageSize)
	// apply the same filters to the packageNameQuery
	for _, f := range filter {
		packageNameQuery = packageNameQuery.Where(f.SQL(), f.Value())
	}

	// apply sorting
	if len(sort) > 0 {
		for _, s := range sort {
			packageNameQuery = packageNameQuery.Order(s.SQL())
		}
	} else {
		packageNameQuery = packageNameQuery.Order("max_risk DESC")
	}

	res := []riskStats{}
	if err := packageNameQuery.Debug().Scan(&res).Error; err != nil {
		return shared.Paged[models.DependencyVuln]{}, map[string]int{}, err
	}

	packageNames := utils.Map(res, func(repository riskStats) string {
		return repository.PackageName
	})

	err = q.Where("dependency_vulns.component_purl IN (?)", packageNames).Order("raw_risk_assessment DESC").Preload("CVE").Find(&dependencyVulns).Error

	if err != nil {
		return shared.Paged[models.DependencyVuln]{}, map[string]int{}, err
	}
	// order the dependencyVulns based on the package name ordering
	packageNameIndexMap := make(map[string]int)
	for i, name := range packageNames {
		packageNameIndexMap[name] = i
	}

	return shared.NewPaged(pageInfo, count, dependencyVulns), packageNameIndexMap, nil
}

func (repository *dependencyVulnRepository) GetDependencyVulnsByAssetVersionPagedAndFlat(tx *gorm.DB, assetVersionName string, assetID uuid.UUID, pageInfo shared.PageInfo, search string, filter []shared.FilterQuery, sort []shared.SortQuery) (shared.Paged[models.DependencyVuln], error) {
	return repository.GetDependencyVulnsPaged(tx, []string{assetVersionName}, []string{assetID.String()}, pageInfo, search, filter, sort)
}

func (repository dependencyVulnRepository) Read(id string) (models.DependencyVuln, error) {
	var t models.DependencyVuln
	err := repository.db.Preload("CVE.Weaknesses").Preload("Events", func(db *gorm.DB) *gorm.DB {
		return db.Order("created_at ASC")
	}).Preload("CVE").Preload("CVE.Exploits").Preload("CVE.Relationships").Preload("Artifacts").First(&t, "id = ?", id).Error

	return t, err
}

func (repository *dependencyVulnRepository) GetDependencyVulnsByPurl(tx *gorm.DB, purl []string) ([]models.DependencyVuln, error) {

	var dependencyVulns = []models.DependencyVuln{}
	if len(purl) == 0 {
		return dependencyVulns, nil
	}

	if err := repository.Repository.GetDB(tx).Preload("Artifacts").Preload("Events", func(db *gorm.DB) *gorm.DB {
		return db.Order("created_at ASC")
	}).Joins("CVE").Where("component_purl IN ?", purl).Find(&dependencyVulns).Error; err != nil {
		return nil, err
	}

	return dependencyVulns, nil
}

func (repository *dependencyVulnRepository) GetDependencyVulnsPaged(tx *gorm.DB, assetVersionNamesSubquery any, assetVersionAssetIDSubquery any, pageInfo shared.PageInfo, search string, filter []shared.FilterQuery, sort []shared.SortQuery) (shared.Paged[models.DependencyVuln], error) {
	var dependencyVulns = []models.DependencyVuln{}

	q := repository.Repository.GetDB(tx).Model(&models.DependencyVuln{}).Preload("Artifacts").Preload("Events", func(db *gorm.DB) *gorm.DB {
		return db.Order("created_at ASC")
	}).Joins("left join artifact_dependency_vulns ON artifact_dependency_vulns.dependency_vuln_id = dependency_vulns.id").Joins("CVE").Where("dependency_vulns.asset_version_name IN (?) AND dependency_vulns.asset_id IN (?)", assetVersionNamesSubquery, assetVersionAssetIDSubquery).Distinct()

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
		return shared.Paged[models.DependencyVuln]{}, err
	}

	err = q.Limit(pageInfo.PageSize).Offset((pageInfo.Page - 1) * pageInfo.PageSize).Find(&dependencyVulns).Error

	if err != nil {
		return shared.Paged[models.DependencyVuln]{}, err
	}

	return shared.NewPaged(pageInfo, count, dependencyVulns), nil
}

func (repository *dependencyVulnRepository) GetDefaultDependencyVulnsByProjectIDPaged(tx *gorm.DB, projectID uuid.UUID, pageInfo shared.PageInfo, search string, filter []shared.FilterQuery, sort []shared.SortQuery) (shared.Paged[models.DependencyVuln], error) {

	subQueryAssetIDs := repository.Repository.GetDB(tx).Model(&models.Asset{}).Select("assets.id").Where("project_id = ?", projectID)

	subQuery := repository.Repository.GetDB(tx).Model(&models.AssetVersion{}).Select("name").Where("asset_id IN (?) AND default_branch = ?", subQueryAssetIDs, true)

	return repository.GetDependencyVulnsPaged(tx, subQuery, subQueryAssetIDs, pageInfo, search, filter, sort)
}

func (repository *dependencyVulnRepository) GetDefaultDependencyVulnsByOrgIDPaged(tx *gorm.DB, userAllowedProjectIds []string, pageInfo shared.PageInfo, search string, filter []shared.FilterQuery, sort []shared.SortQuery) (shared.Paged[models.DependencyVuln], error) {

	subQueryAssetIDs := repository.Repository.GetDB(tx).Model(&models.Asset{}).Select("assets.id").Where("assets.project_id IN (?)", userAllowedProjectIds)

	subQuery1 := repository.Repository.GetDB(tx).Model(&models.AssetVersion{}).Select("name").Where("asset_id IN (?) AND default_branch = ?", subQueryAssetIDs, true)

	return repository.GetDependencyVulnsPaged(tx, subQuery1, subQueryAssetIDs, pageInfo, search, filter, sort)

}

func (repository *dependencyVulnRepository) GetDependencyVulnAssetIDByDependencyVulnID(tx *gorm.DB, dependencyVulnID string) (string, error) {
	var dependencyVulnAssetID string
	if err := repository.Repository.GetDB(tx).Model(&models.DependencyVuln{}).Select("dependency_vuln_asset_id").Where("id = ?", dependencyVulnID).Row().Scan(&dependencyVulnAssetID); err != nil {
		return "", err
	}
	return dependencyVulnAssetID, nil
}

func (repository *dependencyVulnRepository) GetOrgFromVulnID(tx *gorm.DB, dependencyVulnID string) (models.Org, error) {
	var org models.Org
	if err := repository.GetDB(tx).Raw("SELECT organizations.* from organizations left join projects p on organizations.id = p.organization_id left join assets a on p.id = a.project_id left join dependency_vulns f on a.id = f.asset_id where f.id = ?", dependencyVulnID).First(&org).Error; err != nil {
		return models.Org{}, err
	}
	return org, nil
}

func (repository *dependencyVulnRepository) FindByTicketID(tx *gorm.DB, ticketID string) (models.DependencyVuln, error) {
	var vuln models.DependencyVuln
	if err := repository.Repository.GetDB(tx).Preload("Artifacts").Preload("CVE").Preload("CVE.Exploits").Where("ticket_id = ?", ticketID).First(&vuln).Error; err != nil {
		return vuln, err
	}
	return vuln, nil
}

func (repository *dependencyVulnRepository) GetHintsInOrganizationForVuln(tx *gorm.DB, orgID uuid.UUID, pURL string, cveID string) (dtos.DependencyVulnHints, error) {
	type stateCount struct {
		State string `json:"state"`
		Count int    `json:"count"`
	}
	var hints dtos.DependencyVulnHints
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

func (repository *dependencyVulnRepository) GetAllOpenVulnsByAssetVersionNameAndAssetID(tx *gorm.DB, artifactName *string, assetVersionName string, assetID uuid.UUID) ([]models.DependencyVuln, error) {
	var vulns = []models.DependencyVuln{}

	if artifactName != nil {
		if err := repository.Repository.GetDB(tx).Preload("CVE").Where("asset_version_name = ? AND asset_id = ? AND state = ? AND EXISTS(SELECT 1 from artifact_dependency_vulns WHERE dependency_vuln_id = id AND artifact_artifact_name = ?)", assetVersionName, assetID, dtos.VulnStateOpen, *artifactName).Find(&vulns).Error; err != nil {
			return nil, err
		}
		return vulns, nil
	} else {
		if err := repository.Repository.GetDB(tx).Preload("CVE").Where("asset_version_name = ? AND asset_id = ? AND state = ?", assetVersionName, assetID, dtos.VulnStateOpen).Find(&vulns).Error; err != nil {
			return nil, err
		}
		return vulns, nil
	}

}

// Override the base GetAllVulnsByAssetID method to preload artifacts
func (repository *dependencyVulnRepository) GetAllVulnsByAssetID(tx *gorm.DB, assetID uuid.UUID) ([]models.DependencyVuln, error) {
	var vulns = []models.DependencyVuln{}
	if err := repository.Repository.GetDB(tx).Preload("CVE").Preload("Artifacts").Preload("Events", func(db *gorm.DB) *gorm.DB {
		return db.Order("created_at ASC")
	}).Where("asset_id = ?", assetID).Find(&vulns).Error; err != nil {
		return nil, err
	}
	return vulns, nil
}

func (repository *dependencyVulnRepository) GetAllVulnsByAssetIDWithTicketIDs(tx *gorm.DB, assetID uuid.UUID) ([]models.DependencyVuln, error) {
	var vulns = []models.DependencyVuln{}
	err := repository.Repository.GetDB(tx).Raw("SELECT * FROM dependency_vulns WHERE asset_id = ? AND ticket_id IS NOT NULL", assetID.String()).Find(&vulns).Error
	if err != nil {
		return nil, err
	}
	return vulns, nil
}

func (repository *dependencyVulnRepository) GetAllVulnsByArtifact(
	tx *gorm.DB,
	artifact models.Artifact,
) ([]models.DependencyVuln, error) {

	var vulns []models.DependencyVuln

	err := repository.Repository.GetDB(tx).
		Model(&models.DependencyVuln{}).
		Where(`
			EXISTS (
				SELECT 1
				FROM artifact_dependency_vulns adv
				WHERE adv.dependency_vuln_id = dependency_vulns.id
				  AND adv.artifact_artifact_name = ?
				  AND adv.artifact_asset_version_name = ?
				  AND adv.artifact_asset_id = ?
			)
		`,
			artifact.ArtifactName,
			artifact.AssetVersionName,
			artifact.AssetID,
		).
		Preload("Artifacts").
		Preload("CVE").
		Find(&vulns).Error

	return vulns, err
}

func (repository *dependencyVulnRepository) GetAllVulnsForTagsAndDefaultBranchInAsset(tx *gorm.DB, assetID uuid.UUID, excludedStates []dtos.VulnState) ([]models.DependencyVuln, error) {
	var vulns []models.DependencyVuln
	var err error
	// choose which states we want to include
	if len(excludedStates) == 0 {
		err = repository.Repository.GetDB(tx).Raw(`SELECT vulns.* FROM dependency_vulns vulns 
		LEFT JOIN asset_versions av ON vulns.asset_id = av.asset_id AND vulns.asset_version_name = av.name
		WHERE vulns.asset_id = ? AND (av.default_branch = true OR av.type = 'tag');`, assetID).Preload("Events", func(db *gorm.DB) *gorm.DB {
			return db.Order("created_at ASC")
		}).Preload("Artifacts").Find(&vulns).Error
	} else {
		err = repository.Repository.GetDB(tx).Raw(`SELECT vulns.* FROM dependency_vulns vulns 
		LEFT JOIN asset_versions av ON vulns.asset_id = av.asset_id AND vulns.asset_version_name = av.name
		WHERE vulns.asset_id = ? AND vulns.state NOT IN ? AND (av.default_branch = true OR av.type = 'tag');`, assetID, excludedStates).Preload("Events", func(db *gorm.DB) *gorm.DB {
			return db.Order("created_at ASC")
		}).Preload("Artifacts").Find(&vulns).Error
	}
	if err != nil {
		return nil, err
	}
	return vulns, nil
}

func (repository *dependencyVulnRepository) GetDependencyVulnByCVEIDAndAssetID(tx *gorm.DB, cveID string, assetID uuid.UUID) ([]models.DependencyVuln, error) {
	var vuln []models.DependencyVuln
	err := repository.Repository.GetDB(tx).Preload("Events", func(db *gorm.DB) *gorm.DB {
		return db.Order("created_at ASC")
	}).Preload("Artifacts").Preload("CVE").Where("cve_id = ? AND asset_id = ?", cveID, assetID).Find(&vuln).Error
	return vuln, err
}

// FindByVEXRule finds all dependency vulnerabilities matching a VEX rule's CVE and path pattern.
// Supports wildcards in path patterns:
//   - "*" matches any number of path elements (zero or more)
//   - "**" matches any number of path elements (zero or more)
//
// The pattern is matched as a suffix against the vulnerability path.
// Filtering is done in Go to maintain database compatibility (PostgreSQL, SQLite, etc.).
func (repository *dependencyVulnRepository) FindByVEXRule(tx *gorm.DB, rule models.VEXRule) ([]models.DependencyVuln, error) {
	result, err := repository.FindByVEXRules(tx, []models.VEXRule{rule})
	if err != nil {
		return nil, err
	}
	return result[&rule], nil
}

func (repository *dependencyVulnRepository) FindByVEXRules(tx *gorm.DB, rules []models.VEXRule) (map[*models.VEXRule][]models.DependencyVuln, error) {
	result := make(map[*models.VEXRule][]models.DependencyVuln)

	if len(rules) == 0 {
		return result, nil
	}

	cveIDs := make(map[string]bool)
	for _, rule := range rules {
		cveIDs[rule.CVEID] = true
	}

	assetID := rules[0].AssetID
	assetVersionName := rules[0].AssetVersionName

	// Convert CVE IDs to slice
	cveIDSlice := make([]string, 0, len(cveIDs))
	for id := range cveIDs {
		cveIDSlice = append(cveIDSlice, id)
	}

	// Single query for all vulns
	var vulns []models.DependencyVuln
	err := repository.Repository.GetDB(tx).
		Where("asset_id = ?", assetID).
		Where("asset_version_name = ?", assetVersionName).
		Where("cve_id IN ?", cveIDSlice).
		Preload("Events", func(db *gorm.DB) *gorm.DB {
			return db.Order("created_at ASC")
		}).
		Preload("Artifacts").
		Preload("CVE").
		Find(&vulns).Error

	if err != nil {
		return nil, err
	}

	return result, nil
}
