package repositories

import (
	"context"
	"fmt"
	"iter"
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

var _ shared.DependencyVulnRepository = (*dependencyVulnRepository)(nil)

func NewDependencyVulnRepository(db *gorm.DB) *dependencyVulnRepository {
	return &dependencyVulnRepository{
		db:                      db,
		VulnerabilityRepository: *NewVulnerabilityRepository[models.DependencyVuln](db),
	}
}

func (repository *dependencyVulnRepository) ApplyAndSave(ctx context.Context, tx *gorm.DB, dependencyVuln *models.DependencyVuln, vulnEvent *models.VulnEvent) error {
	if tx == nil {
		// we are not part of a parent transaction - create a new one
		return repository.Transaction(ctx, func(d *gorm.DB) error {
			_, err := repository.applyAndSave(ctx, d, dependencyVuln, vulnEvent)
			return err
		})
	}

	_, err := repository.applyAndSave(ctx, tx, dependencyVuln, vulnEvent)
	return err
}

func (repository *dependencyVulnRepository) applyAndSave(ctx context.Context, tx *gorm.DB, dependencyVuln *models.DependencyVuln, ev *models.VulnEvent) (models.VulnEvent, error) {
	// apply the event on the dependencyVuln
	statemachine.Apply(dependencyVuln, *ev)

	// run the updates in the transaction to keep a valid state
	err := repository.Save(ctx, tx, dependencyVuln)
	if err != nil {
		return models.VulnEvent{}, err
	}
	if err := repository.GetDB(ctx, tx).Save(ev).Error; err != nil {
		return models.VulnEvent{}, err
	}
	dependencyVuln.Events = append(dependencyVuln.Events, *ev)
	return *ev, nil
}

func (repository *dependencyVulnRepository) GetByAssetID(ctx context.Context, tx *gorm.DB, assetID uuid.UUID) ([]models.DependencyVuln, error) {
	var dependencyVulns = []models.DependencyVuln{}
	err := repository.Repository.GetDB(ctx, tx).Preload("Events", func(db *gorm.DB) *gorm.DB {
		return db.Order("created_at ASC")
	}).Preload("CVE").Preload("CVE.Exploits").Where("asset_id = ?", assetID).Find(&dependencyVulns).Error
	if err != nil {
		return nil, err
	}
	return dependencyVulns, nil
}

func (repository *dependencyVulnRepository) GetByVexRuleID(ctx context.Context, tx *gorm.DB, vexRuleID string) ([]models.DependencyVuln, error) {
	var dependencyVulns = []models.DependencyVuln{}
	err := repository.Repository.GetDB(ctx, tx).Model(&models.VulnEvent{}).Select("DISTINCT dependency_vulns.*").Joins("JOIN dependency_vulns ON vuln_events.dependency_vuln_id = dependency_vulns.id").Where("vuln_events.vex_rule_id = ?", vexRuleID).Preload("Events", func(db *gorm.DB) *gorm.DB {
		return db.Order("created_at ASC")
	}).Preload("Events.VexRule").Find(&dependencyVulns).Error
	if err != nil {
		return nil, err
	}
	return dependencyVulns, nil
}

func (repository *dependencyVulnRepository) GetDependencyVulnsByAssetVersion(ctx context.Context, tx *gorm.DB, assetVersionName string, assetID uuid.UUID, artifactName *string) ([]models.DependencyVuln, error) {

	var dependencyVulns = []models.DependencyVuln{}
	q := repository.Repository.GetDB(ctx, tx).Preload("Events", func(db *gorm.DB) *gorm.DB {
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

// otherAssetVersionsBatchSize bounds how many rows GetDependencyVulnsByOtherAssetVersions
// materializes per round trip.
//
// GORM resolves a Preload with a single `... IN (?, ?, ...)` carrying one bind parameter
// per parent row already fetched - the same behaviour getAllOpenVulns documents above.
// Postgres' extended protocol caps a statement at 65535 bind parameters, so an asset whose
// other versions hold more vulns than that fails with "extended protocol limited to 65535
// parameters" inside the Events preload, not in the Where below. Batching the parents
// bounds every preload issued for them.
const otherAssetVersionsBatchSize = 1000

func (repository *dependencyVulnRepository) GetDependencyVulnsByOtherAssetVersions(ctx context.Context, tx *gorm.DB, assetVersionName string, assetID uuid.UUID) ([]models.DependencyVuln, error) {
	var dependencyVulns = []models.DependencyVuln{}

	q := repository.Repository.GetDB(ctx, tx).Preload("Events", func(db *gorm.DB) *gorm.DB {
		return db.Order("created_at ASC")
	}).Preload("CVE").Preload("CVE.Exploits").Where("dependency_vulns.asset_version_name != ? AND dependency_vulns.asset_id = ?", assetVersionName, assetID)

	var batch []models.DependencyVuln
	if err := q.FindInBatches(&batch, otherAssetVersionsBatchSize, func(*gorm.DB, int) error {
		dependencyVulns = append(dependencyVulns, batch...)
		return nil
	}).Error; err != nil {
		return nil, err
	}

	return dependencyVulns, nil
}

func (repository *dependencyVulnRepository) GetDependencyVulnsByDefaultAssetVersion(ctx context.Context, tx *gorm.DB, assetID uuid.UUID, artifactName *string) ([]models.DependencyVuln, error) {
	subQuery := repository.Repository.GetDB(ctx, tx).Model(&models.AssetVersion{}).Select("name").Where("asset_id IN (?) AND default_branch = ?", assetID, true)

	var dependencyVulns = []models.DependencyVuln{}
	q := repository.Repository.GetDB(ctx, tx).Preload("CVE").Preload("Events", func(db *gorm.DB) *gorm.DB {
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

func (repository *dependencyVulnRepository) ListByAssetAndAssetVersion(ctx context.Context, tx *gorm.DB, assetVersionName string, assetID uuid.UUID) ([]models.DependencyVuln, error) {
	var dependencyVulns = []models.DependencyVuln{}
	if err := repository.Repository.GetDB(ctx, tx).Preload("Artifacts").Preload("CVE").Preload("CVE.Exploits").Preload("Events", func(db *gorm.DB) *gorm.DB {
		return db.Order("created_at ASC")
	}).Where("asset_version_name = ? AND asset_id = ?", assetVersionName, assetID).Find(&dependencyVulns).Error; err != nil {
		return nil, err
	}
	return dependencyVulns, nil
}

func (repository *dependencyVulnRepository) ListUnfixedByAssetAndAssetVersion(ctx context.Context, tx *gorm.DB, assetVersionName string, assetID uuid.UUID, artifactName *string) ([]models.DependencyVuln, error) {
	var dependencyVulns = []models.DependencyVuln{}
	q := repository.Repository.GetDB(ctx, tx).Preload("Artifacts").Preload("CVE").Preload("Events", func(db *gorm.DB) *gorm.DB {
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
func (repository *dependencyVulnRepository) FindByCVEAndComponentPurl(ctx context.Context, tx *gorm.DB, assetID uuid.UUID, cveID string, componentPurl string) ([]models.DependencyVuln, error) {
	var vulns []models.DependencyVuln
	err := repository.Repository.GetDB(ctx, tx).
		Preload("Events", func(db *gorm.DB) *gorm.DB {
			return db.Order("created_at ASC")
		}).
		Preload("Artifacts").
		Preload("CVE").
		Where("asset_id = ? AND LOWER(cve_id) = LOWER(?) AND component_purl = ?", assetID, cveID, componentPurl).
		Find(&vulns).Error
	return vulns, err
}
func dependencyVulnSortSQL(s shared.SortQuery) string {
	switch s.Field {
	case "max_risk":
		s.Field = "dependency_vulns.raw_risk_assessment"
	case "max_cvss":
		s.Field = "CVE.cvss"
	default:
		s.Field = "dependency_vulns.raw_risk_assessment"
	}
	return s.SQL()
}

func (repository *dependencyVulnRepository) GetByAssetVersionPaged(ctx context.Context, tx *gorm.DB, assetVersionName string, assetID uuid.UUID, pageInfo shared.PageInfo, search string, filter []shared.FilterQuery, sort []shared.SortQuery) (shared.Paged[models.DependencyVuln], map[string]int, error) {
	var count int64
	var dependencyVulns = []models.DependencyVuln{}

	q := repository.Repository.GetDB(ctx, tx).Model(&models.DependencyVuln{}).Preload("Artifacts").Joins("LEFT JOIN artifact_dependency_vulns ON artifact_dependency_vulns.dependency_vuln_id = dependency_vulns.id").Joins("CVE").Where("dependency_vulns.asset_version_name = ?", assetVersionName).Where("dependency_vulns.asset_id = ?", assetID).Distinct()

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

	packageNameQuery := repository.GetDB(ctx, tx).Table("components").
		Select("SUM(dependency_vulns.raw_risk_assessment) as total_risk, AVG(dependency_vulns.raw_risk_assessment) as avg_risk, MAX(dependency_vulns.raw_risk_assessment) as max_risk, MAX(\"CVE\".cvss) as max_cvss, COUNT(dependency_vulns.id) as dependency_vuln_count, components.id as package_name").
		Joins("INNER JOIN dependency_vulns ON components.id = dependency_vulns.component_purl AND dependency_vulns.asset_id = ? AND dependency_vulns.asset_version_name = ?", assetID, assetVersionName).
		Joins("LEFT JOIN artifact_dependency_vulns ON artifact_dependency_vulns.dependency_vuln_id = dependency_vulns.id").
		Joins("INNER JOIN cves \"CVE\" ON dependency_vulns.cve_id = \"CVE\".cve").
		Where("dependency_vulns.asset_version_name = ?", assetVersionName).
		Where("dependency_vulns.asset_id = ?", assetID).
		Group("components.id").Limit(pageInfo.PageSize).Offset((pageInfo.Page - 1) * pageInfo.PageSize)
	// apply the same filters to the packageNameQuery
	for _, f := range filter {
		packageNameQuery = packageNameQuery.Where(f.SQL(), f.Value())
	}

	if search != "" && len(search) > 2 {
		packageNameQuery.Where("(\"CVE\".description ILIKE ?  OR dependency_vulns.cve_id ILIKE ? OR component_purl ILIKE ?)", "%"+search+"%", "%"+search+"%", "%"+search+"%")
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
	if err := packageNameQuery.Scan(&res).Error; err != nil {
		return shared.Paged[models.DependencyVuln]{}, map[string]int{}, err
	}

	packageNames := utils.Map(res, func(repository riskStats) string {
		return repository.PackageName
	})

	q = q.Where("dependency_vulns.component_purl IN (?)", packageNames)
	if len(sort) > 0 {
		for _, s := range sort {
			q = q.Order(dependencyVulnSortSQL(s))
		}
	} else {
		q = q.Order("raw_risk_assessment DESC")
	}

	err = q.Preload("CVE").Find(&dependencyVulns).Error

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

func (repository *dependencyVulnRepository) GetDependencyVulnsByAssetVersionPagedAndFlat(ctx context.Context, tx *gorm.DB, assetVersionName string, assetID uuid.UUID, pageInfo shared.PageInfo, search string, filter []shared.FilterQuery, sort []shared.SortQuery) (shared.Paged[models.DependencyVuln], error) {
	return repository.GetDependencyVulnsPaged(ctx, tx, []string{assetVersionName}, []string{assetID.String()}, pageInfo, search, filter, sort)
}

func (repository dependencyVulnRepository) Read(ctx context.Context, tx *gorm.DB, id uuid.UUID) (models.DependencyVuln, error) {
	var t models.DependencyVuln
	db := withOwnershipScope(ctx, repository.GetDB(ctx, tx).Where("dependency_vulns.id = ?", id), t)
	err := db.Preload("Events", func(db *gorm.DB) *gorm.DB {
		return db.Order("created_at ASC")
	}).Preload("Events.VexRule").Joins("CVE").Preload("CVE.Exploits").Preload("CVE.Relationships").Preload("Artifacts").First(&t).Error

	return t, err
}

func (repository *dependencyVulnRepository) GetDependencyVulnsByPurl(ctx context.Context, tx *gorm.DB, purl []string) ([]models.DependencyVuln, error) {

	var dependencyVulns = []models.DependencyVuln{}
	if len(purl) == 0 {
		return dependencyVulns, nil
	}

	if err := repository.Repository.GetDB(ctx, tx).Preload("Artifacts").Preload("Events", func(db *gorm.DB) *gorm.DB {
		return db.Order("created_at ASC")
	}).Joins("CVE").Where("component_purl IN ?", purl).Find(&dependencyVulns).Error; err != nil {
		return nil, err
	}

	return dependencyVulns, nil
}

func (repository *dependencyVulnRepository) GetDependencyVulnsPaged(ctx context.Context, tx *gorm.DB, assetVersionNamesSubquery any, assetVersionAssetIDSubquery any, pageInfo shared.PageInfo, search string, filter []shared.FilterQuery, sort []shared.SortQuery) (shared.Paged[models.DependencyVuln], error) {
	var dependencyVulns = []models.DependencyVuln{}

	q := repository.Repository.GetDB(ctx, tx).Model(&models.DependencyVuln{}).Preload("Artifacts").Preload("Events", func(db *gorm.DB) *gorm.DB {
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

func (repository *dependencyVulnRepository) GetDefaultDependencyVulnsByProjectIDPaged(ctx context.Context, tx *gorm.DB, projectID uuid.UUID, pageInfo shared.PageInfo, search string, filter []shared.FilterQuery, sort []shared.SortQuery) (shared.Paged[models.DependencyVuln], error) {

	subQueryAssetIDs := repository.Repository.GetDB(ctx, tx).Model(&models.Asset{}).Select("assets.id").Where("project_id = ?", projectID)

	subQuery := repository.Repository.GetDB(ctx, tx).Model(&models.AssetVersion{}).Select("name").Where("asset_id IN (?) AND default_branch = ?", subQueryAssetIDs, true)

	return repository.GetDependencyVulnsPaged(ctx, tx, subQuery, subQueryAssetIDs, pageInfo, search, filter, sort)
}

func (repository *dependencyVulnRepository) GetDefaultDependencyVulnsByOrgIDPaged(ctx context.Context, tx *gorm.DB, userAllowedProjectIds []string, pageInfo shared.PageInfo, search string, filter []shared.FilterQuery, sort []shared.SortQuery) (shared.Paged[models.DependencyVuln], error) {

	subQueryAssetIDs := repository.Repository.GetDB(ctx, tx).Model(&models.Asset{}).Select("assets.id").Where("assets.project_id IN (?)", userAllowedProjectIds)

	subQuery1 := repository.Repository.GetDB(ctx, tx).Model(&models.AssetVersion{}).Select("name").Where("asset_id IN (?) AND default_branch = ?", subQueryAssetIDs, true)

	return repository.GetDependencyVulnsPaged(ctx, tx, subQuery1, subQueryAssetIDs, pageInfo, search, filter, sort)

}

func (repository *dependencyVulnRepository) GetDependencyVulnAssetIDByDependencyVulnID(ctx context.Context, tx *gorm.DB, dependencyVulnID uuid.UUID) (string, error) {
	var dependencyVulnAssetID string
	if err := repository.Repository.GetDB(ctx, tx).Model(&models.DependencyVuln{}).Select("dependency_vuln_asset_id").Where("id = ?", dependencyVulnID).Row().Scan(&dependencyVulnAssetID); err != nil {
		return "", err
	}
	return dependencyVulnAssetID, nil
}

func (repository *dependencyVulnRepository) GetOrgFromVulnID(ctx context.Context, tx *gorm.DB, dependencyVulnID uuid.UUID) (models.Org, error) {
	var org models.Org
	if err := repository.GetDB(ctx, tx).Raw("SELECT organizations.* from organizations left join projects p on organizations.id = p.organization_id left join assets a on p.id = a.project_id left join dependency_vulns f on a.id = f.asset_id where f.id = ?", dependencyVulnID).First(&org).Error; err != nil {
		return models.Org{}, err
	}
	return org, nil
}

func (repository *dependencyVulnRepository) FindByTicketID(ctx context.Context, tx *gorm.DB, ticketID string) (models.DependencyVuln, error) {
	var vuln models.DependencyVuln
	if err := repository.Repository.GetDB(ctx, tx).Preload("Artifacts").Preload("CVE").Preload("CVE.Exploits").Where("ticket_id = ?", ticketID).First(&vuln).Error; err != nil {
		return vuln, err
	}
	return vuln, nil
}

func (repository *dependencyVulnRepository) GetHintsInOrganizationForVuln(ctx context.Context, tx *gorm.DB, orgID uuid.UUID, pURL string, cveID string) (dtos.DependencyVulnHints, error) {
	type stateCount struct {
		State string `json:"state"`
		Count int    `json:"count"`
	}
	var hints dtos.DependencyVulnHints
	stateCounts := make([]stateCount, 0, 7)

	err := repository.GetDB(ctx, tx).Raw(`SELECT state, COUNT(*) as "count" FROM (
	SELECT DISTINCT d.asset_id, d.state as "state"
    FROM dependency_vulns d
    WHERE d.asset_id IN (
        SELECT id FROM assets WHERE project_id IN (
            SELECT id FROM projects WHERE organization_id = ?
        )
    )
    AND LOWER(d.cve_id) = LOWER(?)
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

func (repository *dependencyVulnRepository) GetAllOpenVulnsByAssetVersionNameAndAssetID(ctx context.Context, tx *gorm.DB, artifactName *string, assetVersionName string, assetID uuid.UUID) ([]models.DependencyVuln, error) {
	var vulns = []models.DependencyVuln{}

	if artifactName != nil {
		if err := repository.Repository.GetDB(ctx, tx).Preload("CVE").Where("asset_version_name = ? AND asset_id = ? AND state = ? AND EXISTS(SELECT 1 from artifact_dependency_vulns WHERE dependency_vuln_id = id AND artifact_artifact_name = ?)", assetVersionName, assetID, dtos.VulnStateOpen, *artifactName).Find(&vulns).Error; err != nil {
			return nil, err
		}
		return vulns, nil
	} else {
		if err := repository.Repository.GetDB(ctx, tx).Preload("CVE").Preload("Artifacts").Where("asset_version_name = ? AND asset_id = ? AND state = ?", assetVersionName, assetID, dtos.VulnStateOpen).Find(&vulns).Error; err != nil {
			return nil, err
		}
		return vulns, nil
	}

}

// GetAllOpenVulnsByAssetID preloads Events, needed by CEL VEX rule matching to
// tell whether a rule's outcome was already applied to a vuln.
func (repository *dependencyVulnRepository) GetAllOpenVulnsByAssetID(ctx context.Context, tx *gorm.DB, assetID uuid.UUID, batchSize int) iter.Seq2[[]models.DependencyVuln, error] {
	return repository.GetVulnsWithCveAndArtifacts(ctx, tx, batchSize,
		func(db *gorm.DB) *gorm.DB { return db.Where("state = ?", dtos.VulnStateOpen) },
		func(db *gorm.DB) *gorm.DB { return db.Where("asset_id = ?", assetID) },
		func(db *gorm.DB) *gorm.DB { return db.Preload("Events") },
	)
}

// GetAllOpenVulnsByAssetIDWithoutEvents skips the Events preload for callers
// that don't need it, such as the crowdsourced-vexing recommendation response.
func (repository *dependencyVulnRepository) GetAllOpenVulnsByAssetIDWithoutEvents(ctx context.Context, tx *gorm.DB, assetID uuid.UUID, batchSize int) iter.Seq2[[]models.DependencyVuln, error] {
	return repository.GetVulnsWithCveAndArtifacts(ctx, tx, batchSize,
		func(db *gorm.DB) *gorm.DB { return db.Where("state = ?", dtos.VulnStateOpen) },
		func(db *gorm.DB) *gorm.DB { return db.Where("asset_id = ?", assetID) },
	)
}

// GetOpenVulnsBySignaturesWithoutEvents fetches every open vuln whose signature is in the
// given set, regardless of asset - used to find vulns that upstream VEX rules
// didn't already produce a recommendation for.
func (repository *dependencyVulnRepository) GetOpenVulnsBySignaturesWithoutEvents(ctx context.Context, tx *gorm.DB, signatures []int64, batchSize int) iter.Seq2[[]models.DependencyVuln, error] {
	return repository.GetVulnsWithCveAndArtifacts(ctx, tx, batchSize,
		func(db *gorm.DB) *gorm.DB { return db.Where("state = ?", dtos.VulnStateOpen) },
		func(db *gorm.DB) *gorm.DB { return db.Where("signature IN (?)", signatures) },
	)
}

func (repository *dependencyVulnRepository) ApplyGroupEventAndSave(ctx context.Context, tx *gorm.DB, assetSignature int64, ev *models.VulnEvent) error {
	scratch := &models.DependencyVuln{}
	statemachine.Apply(scratch, *ev)

	if err := repository.Repository.GetDB(ctx, tx).Model(&models.DependencyVuln{}).
		Where("state != ? AND asset_signature = ?", dtos.VulnStateFixed, assetSignature).
		Update("state", scratch.GetState()).Error; err != nil {
		return err
	}

	return repository.GetDB(ctx, tx).Save(ev).Error
}

// ApplyGroupEventsAndSave is the bulk counterpart to ApplyGroupEventAndSave: instead of
// one UPDATE + one INSERT round trip per event, it does one UPDATE covering every touched
// asset signature and one bulk INSERT for all the events. Returns the asset signatures it
// touched, so the caller can look up the vulns it affected (e.g. via
// GetVulnsByAssetSignatures) without duplicating this loop at every call site.
func (repository *dependencyVulnRepository) ApplyGroupEventsAndSave(ctx context.Context, tx *gorm.DB, events []models.VulnEvent) ([]int64, error) {
	if len(events) == 0 {
		return nil, nil
	}

	assetSignatures := make([]int64, 0, len(events))
	states := make([]string, 0, len(events))
	for i := range events {
		ev := &events[i]
		if ev.AssetSignature == nil {
			continue
		}
		scratch := &models.DependencyVuln{}
		statemachine.Apply(scratch, *ev)
		assetSignatures = append(assetSignatures, *ev.AssetSignature)
		states = append(states, string(scratch.GetState()))
	}
	if len(assetSignatures) == 0 {
		return nil, nil
	}

	if err := repository.GetDB(ctx, tx).Exec(`
		UPDATE dependency_vulns dv
		SET state = v.state
		FROM (SELECT unnest($1::bigint[]) AS asset_signature, unnest($2::text[]) AS state) v
		WHERE dv.asset_signature = v.asset_signature AND dv.state != $3
	`, assetSignatures, states, dtos.VulnStateFixed).Error; err != nil {
		return nil, err
	}

	if err := repository.GetDB(ctx, tx).Create(&events).Error; err != nil {
		return nil, err
	}

	return assetSignatures, nil
}

func (repository *dependencyVulnRepository) GetVulnsDistinctBySignature(ctx context.Context, tx *gorm.DB, assetID uuid.UUID, state dtos.VulnState) ([]models.DependencyVuln, error) {
	var vulns = []models.DependencyVuln{}
	if err := repository.Repository.GetDB(ctx, tx).Preload("CVE", func(db *gorm.DB) *gorm.DB {
		return db.Omit("Description", "References")
	}).Where("asset_id = ? AND state = ?", assetID, state).Distinct("signature").Find(&vulns).Error; err != nil {
		return nil, err
	}
	return vulns, nil
}

func (repository *dependencyVulnRepository) GetVulnsByAssetSignatures(ctx context.Context, tx *gorm.DB, assetSignatures []int64) ([]models.DependencyVuln, error) {
	var vulns = []models.DependencyVuln{}
	if len(assetSignatures) == 0 {
		return vulns, nil
	}
	if err := repository.Repository.GetDB(ctx, tx).Preload("CVE", func(db *gorm.DB) *gorm.DB {
		return db.Omit("Description", "References")
	}).Preload("Artifacts").Where("asset_signature IN (?)", assetSignatures).Find(&vulns).Error; err != nil {
		return nil, err
	}
	return vulns, nil
}

// GetOpenVulnsDistinctBySignatureIn fetches one representative open vuln per
// given signature - used by the VEX rule recommendation daemon to fetch just
// the representatives a SQL join against upstream_vex_rules.cve_scope already
// identified as candidates, instead of paging through every open vuln.
func (repository *dependencyVulnRepository) GetOpenVulnsDistinctBySignatureIn(ctx context.Context, tx *gorm.DB, signatures []int64) ([]models.DependencyVuln, error) {
	if len(signatures) == 0 {
		return nil, nil
	}
	var vulns = []models.DependencyVuln{}
	if err := repository.Repository.GetDB(ctx, tx).Preload("CVE", func(db *gorm.DB) *gorm.DB {
		return db.Omit("Description", "References")
	}).Select("DISTINCT ON (signature) *").
		Where("state = ? AND signature IN ?", dtos.VulnStateOpen, signatures).
		Order("signature ASC, id ASC").
		Find(&vulns).Error; err != nil {
		return nil, err
	}
	return vulns, nil
}

// GetOpenVulnsDistinctBySignatureWithoutUpstreamRecommendation is
// GetAllOpenVulnsDistinctBySignature, scoped to vulns whose signature has no
// upstream-rule recommendation yet - upstream matches are stable across runs
// (matchScopedUpstreamRules already skips re-checking unchanged rule/vuln
// pairs), so once a signature has one there's no need to keep re-fetching it
// here just to discard it in Go. Crowdsourced recommendations are excluded
// from this filter on purpose: those must be re-evaluated every run (trust
// scores etc. can change), so a signature that only has a crowdsourced
// recommendation still needs to flow through here again.
func (repository *dependencyVulnRepository) GetOpenVulnsDistinctBySignatureWithoutUpstreamRecommendation(ctx context.Context, tx *gorm.DB, batchSize int) iter.Seq2[[]models.DependencyVuln, error] {
	return repository.getAllOpenVulnsDistinctBySignature(ctx, tx, batchSize, func(db *gorm.DB) *gorm.DB {
		return db.Where(`NOT EXISTS (
			SELECT 1 FROM vex_rule_recommendations r
			WHERE r.dependency_vuln_signature = dependency_vulns.signature AND r.upstream_vex_rule_id IS NOT NULL
		)`)
	})
}

func (repository *dependencyVulnRepository) GetAllOpenVulnsDistinctBySignature(ctx context.Context, tx *gorm.DB, batchSize int) iter.Seq2[[]models.DependencyVuln, error] {
	return repository.getAllOpenVulnsDistinctBySignature(ctx, tx, batchSize)
}

func (repository *dependencyVulnRepository) getAllOpenVulnsDistinctBySignature(ctx context.Context, tx *gorm.DB, batchSize int, extraScopes ...func(*gorm.DB) *gorm.DB) iter.Seq2[[]models.DependencyVuln, error] {
	return func(yield func([]models.DependencyVuln, error) bool) {
		db := repository.GetDB(ctx, tx)
		var lastSignature int64
		hasLastSignature := false

		for {
			query := db.Preload("CVE", func(db *gorm.DB) *gorm.DB {
				return db.Omit("Description", "References")
			}).Select("DISTINCT ON (signature) *").
				Where("state = ?", dtos.VulnStateOpen).
				Scopes(extraScopes...)

			if hasLastSignature {
				query = query.Where("signature > ?", lastSignature)
			}

			var vulns = []models.DependencyVuln{}
			if err := query.Order("signature ASC, id ASC").Limit(batchSize).Find(&vulns).Error; err != nil {
				yield(nil, err)
				return
			}

			if len(vulns) == 0 {
				return
			}

			if !yield(vulns, nil) {
				return
			}

			// batchSize <= 0 means "no limit" (GORM treats Limit(-1) as unlimited) -
			// the query above already returned everything there is, so stop instead
			// of issuing a second, pointless round trip.
			if batchSize <= 0 || len(vulns) < batchSize {
				return
			}

			lastSignature = vulns[len(vulns)-1].Signature
			hasLastSignature = true
		}
	}
}

// GetVulnsWithCveAndArtifacts omits CVE.Description/References - they're large
// text/jsonb columns that dominate scan/materialization cost for thousands of
// rows, and aren't needed by any caller. Artifacts are loaded manually (not via
// Preload) so the dependency_vuln_id filter stays a subquery on the scoped IDs
// instead of GORM's Preload building a literal IN(...) list of every
// already-fetched vuln ID, which is expensive for Postgres to plan at thousands
// of IDs.
func (repository *dependencyVulnRepository) GetVulnsWithCveAndArtifacts(ctx context.Context, tx *gorm.DB, batchSize int, scopes ...func(*gorm.DB) *gorm.DB) iter.Seq2[[]models.DependencyVuln, error] {
	return func(yield func([]models.DependencyVuln, error) bool) {
		db := repository.GetDB(ctx, tx)
		offset := 0
		for {
			query := db.Preload("CVE", func(db *gorm.DB) *gorm.DB {
				return db.Omit("Description", "References")
			}).Scopes(scopes...)

			var vulns = []models.DependencyVuln{}
			if err := query.Order("cve_id, vulnerability_path, created_at ASC").Limit(batchSize).Offset(offset).Find(&vulns).Error; err != nil {
				yield(nil, err)
				return
			}

			if len(vulns) == 0 {
				return
			}

			openIDs := db.Table("dependency_vulns").
				Select("id").
				Scopes(scopes...)

			type artifactRow struct {
				models.Artifact
				DependencyVulnID uuid.UUID
			}
			var rows []artifactRow
			if err := db.Table("artifact_dependency_vulns AS adv").
				Select("artifacts.*, adv.dependency_vuln_id").
				Joins("JOIN artifacts ON adv.artifact_artifact_name = artifacts.artifact_name AND adv.artifact_asset_version_name = artifacts.asset_version_name AND adv.artifact_asset_id = artifacts.asset_id").
				Where("adv.dependency_vuln_id IN (?)", openIDs).
				Find(&rows).Error; err != nil {
				yield(nil, err)
				return
			}

			artifactsByVulnID := make(map[uuid.UUID][]models.Artifact, len(vulns))
			for _, r := range rows {
				artifactsByVulnID[r.DependencyVulnID] = append(artifactsByVulnID[r.DependencyVulnID], r.Artifact)
			}
			for i := range vulns {
				vulns[i].Artifacts = artifactsByVulnID[vulns[i].ID]
			}

			if !yield(vulns, nil) {
				return
			}

			// batchSize <= 0 means "no limit" (GORM treats Limit(-1) as unlimited) -
			// the query above already returned everything there is, so stop instead
			// of issuing a second, pointless round trip.
			if batchSize <= 0 || len(vulns) < batchSize {
				return
			}

			offset += len(vulns)
		}
	}
}

// Override the base GetAllVulnsByAssetID method to preload artifacts
func (repository *dependencyVulnRepository) GetAllVulnsByAssetID(ctx context.Context, tx *gorm.DB, assetID uuid.UUID) ([]models.DependencyVuln, error) {
	var vulns = []models.DependencyVuln{}
	if err := repository.Repository.GetDB(ctx, tx).Preload("CVE").Preload("Artifacts").Preload("Events", func(db *gorm.DB) *gorm.DB {
		return db.Order("created_at ASC")
	}).Where("asset_id = ?", assetID).Find(&vulns).Error; err != nil {
		return nil, err
	}
	return vulns, nil
}

func (repository *dependencyVulnRepository) GetAllVulnsByAssetIDWithTicketIDs(ctx context.Context, tx *gorm.DB, assetID uuid.UUID) ([]models.DependencyVuln, error) {
	var vulns = []models.DependencyVuln{}
	err := repository.Repository.GetDB(ctx, tx).Raw("SELECT * FROM dependency_vulns WHERE asset_id = ? AND ticket_id IS NOT NULL", assetID.String()).Find(&vulns).Error
	if err != nil {
		return nil, err
	}
	return vulns, nil
}

func (repository *dependencyVulnRepository) GetAllVulnsByArtifact(
	ctx context.Context,
	tx *gorm.DB,
	artifact models.Artifact,
) ([]models.DependencyVuln, error) {

	var vulns []models.DependencyVuln

	err := repository.Repository.GetDB(ctx, tx).
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

func (repository *dependencyVulnRepository) GetAllVulnsForTagsAndDefaultBranchInAsset(ctx context.Context, tx *gorm.DB, assetID uuid.UUID, excludedStates []dtos.VulnState) ([]models.DependencyVuln, error) {
	var vulns []models.DependencyVuln
	var err error
	// choose which states we want to include
	if len(excludedStates) == 0 {
		err = repository.Repository.GetDB(ctx, tx).Raw(`SELECT vulns.* FROM dependency_vulns vulns 
		LEFT JOIN asset_versions av ON vulns.asset_id = av.asset_id AND vulns.asset_version_name = av.name
		WHERE vulns.asset_id = ? AND (av.default_branch = true OR av.type = 'tag');`, assetID).Preload("Events", func(db *gorm.DB) *gorm.DB {
			return db.Order("created_at ASC")
		}).Preload("Artifacts").Find(&vulns).Error
	} else {
		err = repository.Repository.GetDB(ctx, tx).Raw(`SELECT vulns.* FROM dependency_vulns vulns 
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

func (repository *dependencyVulnRepository) GetDependencyVulnByCVEIDAndAssetID(ctx context.Context, tx *gorm.DB, cveID string, assetID uuid.UUID) ([]models.DependencyVuln, error) {
	var vuln []models.DependencyVuln
	err := repository.Repository.GetDB(ctx, tx).Preload("Events", func(db *gorm.DB) *gorm.DB {
		return db.Order("created_at ASC")
	}).Preload("Artifacts").Preload("CVE").Where("LOWER(cve_id) = LOWER(?) AND asset_id = ?", cveID, assetID).Find(&vuln).Error
	return vuln, err
}

func (repository *dependencyVulnRepository) GetDirectDependencyFixedVersionByPackageName(ctx context.Context, tx *gorm.DB, packageName string) (*string, error) {
	var directDependencyFixedVersion *string

	err := repository.GetDB(ctx, tx).
		WithContext(ctx).
		Table("dependency_vulns").
		Where("direct_dependency_fixed_version IS NOT NULL AND direct_dependency_fixed_version != ''").
		Where("vulnerability_path ->> 0 LIKE '%/' || ? || '@%'", packageName).
		Select("direct_dependency_fixed_version").
		Order("last_detected DESC").
		Limit(1).
		Scan(&directDependencyFixedVersion).Error

	if err != nil {
		return nil, err
	}

	return directDependencyFixedVersion, nil
}
