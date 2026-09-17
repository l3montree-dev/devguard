package repositories

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/lib/pq"
	"gorm.io/gorm"
)

type eventRepository struct {
	db *gorm.DB
	utils.Repository[uuid.UUID, models.VulnEvent, *gorm.DB]
}

func NewVulnEventRepository(db *gorm.DB) *eventRepository {
	return &eventRepository{
		db:         db,
		Repository: newGormRepository[uuid.UUID, models.VulnEvent](db),
	}
}

func (r *eventRepository) ReadAssetEventsByVulnID(ctx context.Context, tx *gorm.DB, vulnID uuid.UUID, vulnType dtos.VulnType) ([]models.VulnEventDetail, error) {
	if vulnType == dtos.VulnTypeDependencyVuln {
		return r.readDependencyVulnAssetEvents(ctx, tx, vulnID)
	}
	return r.readFirstPartyVulnAssetEvents(ctx, tx, vulnID)
}

func (r *eventRepository) readFirstPartyVulnAssetEvents(ctx context.Context, tx *gorm.DB, vulnID uuid.UUID) ([]models.VulnEventDetail, error) {
	var events []models.VulnEventDetail

	//get the first party vuln to get the asset id and rule info
	var t models.FirstPartyVuln
	db := withOwnershipScope(ctx, r.GetDB(ctx, tx).Where("id = ?", vulnID), t)
	err := db.First(&t).Error
	if err != nil {
		return nil, err
	}

	err = r.GetDB(ctx, tx).Table("vuln_events").
		Select("vuln_events.*, first_party_vulnerabilities.asset_version_name, first_party_vulnerabilities.asset_id, asset_versions.slug").
		Joins("LEFT JOIN first_party_vulnerabilities ON vuln_events.first_party_vuln_id = first_party_vulnerabilities.id").
		Joins("LEFT JOIN asset_versions ON first_party_vulnerabilities.asset_id = asset_versions.asset_id AND first_party_vulnerabilities.asset_version_name = asset_versions.name").
		Where("vuln_events.first_party_vuln_id = ANY (?)",
			r.GetDB(ctx, tx).Table("first_party_vulnerabilities").
				Select("id").
				Where("asset_id = ? AND scanner_ids = ? AND rule_id = ? AND uri = ? ", t.AssetID, t.ScannerIDs, t.RuleID, t.URI),
		).
		Order("vuln_events.created_at ASC").
		Find(&events).Error

	if err != nil {
		return nil, err
	}

	return events, nil
}

func (r *eventRepository) readDependencyVulnAssetEvents(ctx context.Context, tx *gorm.DB, vulnID uuid.UUID) ([]models.VulnEventDetail, error) {
	var events []models.VulnEventDetail

	//get the dependency vuln to get the asset id and cve id
	var t models.DependencyVuln
	db := withOwnershipScope(ctx, r.GetDB(ctx, tx).Where("id = ?", vulnID), t)
	err := db.Preload("CVE.Weaknesses").Preload("CVE").Preload("CVE.Exploits").First(&t).Error
	if err != nil {
		return nil, err
	}

	err = r.GetDB(ctx, tx).Table("vuln_events").
		Select("vuln_events.*, dependency_vulns.asset_version_name, dependency_vulns.asset_id, asset_versions.slug").
		Joins("LEFT JOIN dependency_vulns ON vuln_events.dependency_vuln_id = dependency_vulns.id").
		Joins("LEFT JOIN asset_versions ON dependency_vulns.asset_id = asset_versions.asset_id AND dependency_vulns.asset_version_name = asset_versions.name").
		Where("vuln_events.dependency_vuln_id = ANY (?)",
			r.GetDB(ctx, tx).Table("dependency_vulns").
				Select("id").
				Where("asset_id = ? AND LOWER(cve_id) = LOWER(?) AND component_purl = ?", t.AssetID, t.CVEID, t.ComponentPurl),
		).
		Order("vuln_events.created_at ASC").
		Find(&events).Error

	if err != nil {
		return nil, err
	}

	return events, nil
}

func (r *eventRepository) ReadEventsByAssetIDAndAssetVersionName(ctx context.Context, tx *gorm.DB, assetID uuid.UUID, assetVersionName string, pageInfo shared.PageInfo, filter []shared.FilterQuery) (shared.Paged[models.VulnEventDetail], error) {

	var events []models.VulnEventDetail

	// Driven from the vuln tables, which have an (asset_id, asset_version_name) index:
	// filtering vuln_events by "dependency_vuln_id = ANY (...) OR first_party_vuln_id =
	// ANY (...)" cannot use an index and seq scans the whole table. Group events carry an
	// asset_signature instead of a parent and so belong to no asset version.
	eventsOfAssetVersion := r.GetDB(ctx, tx).Raw(`
		SELECT ev.* FROM dependency_vulns dvi
			JOIN vuln_events ev ON ev.dependency_vuln_id = dvi.id
			WHERE dvi.asset_id = ? AND dvi.asset_version_name = ?
		UNION ALL
		SELECT ev.* FROM first_party_vulnerabilities fvi
			JOIN vuln_events ev ON ev.first_party_vuln_id = fvi.id
			WHERE fvi.asset_id = ? AND fvi.asset_version_name = ?
		UNION ALL
		SELECT ev.* FROM license_risks lri
			JOIN vuln_events ev ON ev.license_risk_id = lri.id
			WHERE lri.asset_id = ? AND lri.asset_version_name = ?
		UNION ALL
		SELECT ev.* FROM compliance_postures cpi
			JOIN vuln_events ev ON ev.compliance_posture_id = cpi.id
			WHERE cpi.asset_id = ? AND cpi.asset_version_name = ?
		UNION ALL
		SELECT ev.* FROM advisories advi
			JOIN vuln_events ev ON ev.security_advisory_id = advi.id
			WHERE advi.asset_id = ? AND advi.asset_version_name = ?`,
		assetID, assetVersionName, assetID, assetVersionName, assetID,
		assetVersionName, assetID, assetVersionName, assetID, assetVersionName)

	// joined on the outside so filters can still address e, dv, fv and lr
	withDetails := func(from any) *gorm.DB {
		return r.GetDB(ctx, tx).
			Table("(?) AS e", from).
			Joins("LEFT JOIN dependency_vulns dv ON e.dependency_vuln_id = dv.id").
			Joins("LEFT JOIN first_party_vulnerabilities fv ON e.first_party_vuln_id = fv.id").
			Joins("LEFT JOIN license_risks lr ON e.license_risk_id = lr.id").
			// id breaks ties - batched events share a created_at, and without it
			// the same row lands on two pages while another lands on none
			Order("e.created_at DESC, e.id DESC")
	}

	q := withDetails(eventsOfAssetVersion)
	for _, f := range filter {
		q = f.Where(q)
	}

	// counted separately: COUNT(*) OVER() has to build every row before LIMIT drops them
	var count int64
	if err := q.Session(&gorm.Session{}).Count(&count).Error; err != nil {
		return shared.Paged[models.VulnEventDetail]{}, err
	}

	page := q.Session(&gorm.Session{}).
		Limit(pageInfo.PageSize).
		Offset((pageInfo.Page - 1) * pageInfo.PageSize)

	if len(filter) == 0 {
		// unfiltered, the page can be cut before the detail joins run; with filters it
		// cannot, since they apply to the outer query and would hit a truncated page
		paged := r.GetDB(ctx, tx).Raw("SELECT * FROM (?) u ORDER BY u.created_at DESC, u.id DESC LIMIT ? OFFSET ?",
			eventsOfAssetVersion, pageInfo.PageSize, (pageInfo.Page-1)*pageInfo.PageSize)
		page = withDetails(paged).Session(&gorm.Session{})
	}

	// a license risk names its component in the same field a dependency vuln does
	if err := page.Select("e.*, dv.cve_id, COALESCE(dv.component_purl, lr.component_purl) AS component_purl, fv.uri").
		Scan(&events).Error; err != nil {
		return shared.Paged[models.VulnEventDetail]{}, err
	}

	return shared.NewPaged(pageInfo, count, events), nil
}

func (r *eventRepository) CountByVexRuleIDs(ctx context.Context, tx *gorm.DB, ruleIDs []string) (map[string]int, error) {
	result := make(map[string]int, len(ruleIDs))
	if len(ruleIDs) == 0 {
		return result, nil
	}

	type row struct {
		VexRuleID string
		Count     int
	}
	var rows []row
	err := r.Repository.GetDB(ctx, tx).Table("vuln_events").
		Select("vex_rule_id, COUNT(DISTINCT dependency_vuln_id) AS count").
		Where("vex_rule_id = ANY (?)", pq.Array(ruleIDs)).
		Group("vex_rule_id").
		Scan(&rows).Error
	if err != nil {
		return nil, err
	}

	for _, r := range rows {
		result[r.VexRuleID] = r.Count
	}
	return result, nil
}

func (r *eventRepository) GetSecurityRelevantEventsForVulnIDs(ctx context.Context, tx *gorm.DB, vulnIDs []uuid.UUID) ([]models.VulnEvent, error) {
	var events []models.VulnEvent
	err := r.Repository.GetDB(ctx, tx).Raw("SELECT * FROM vuln_events WHERE (dependency_vuln_id = ANY (?) OR first_party_vuln_id = ANY (?) OR license_risk_id = ANY (?)) AND type IN ('detected','accepted','falsePositive','fixed','reopened') ORDER BY created_at ASC;", pq.Array(vulnIDs), pq.Array(vulnIDs), pq.Array(vulnIDs)).Find(&events).Error
	if err != nil {
		return nil, err
	}
	return events, nil
}

func (r *eventRepository) GetEventsByDependencyVulnIDs(ctx context.Context, tx *gorm.DB, vulnIDs []uuid.UUID) ([]models.VulnEvent, error) {
	if len(vulnIDs) == 0 {
		return nil, nil
	}
	var events []models.VulnEvent
	err := r.Repository.GetDB(ctx, tx).
		Where("dependency_vuln_id = ANY (?)", pq.Array(vulnIDs)).
		Order("created_at ASC").
		Find(&events).Error
	if err != nil {
		return nil, err
	}
	return events, nil
}

func (r *eventRepository) GetLastEventBeforeTimestamp(ctx context.Context, tx *gorm.DB, vulnID uuid.UUID, time time.Time) (models.VulnEvent, error) {
	var event models.VulnEvent
	err := r.Repository.GetDB(ctx, tx).Raw("SELECT * FROM vuln_events WHERE (dependency_vuln_id = ? OR first_party_vuln_id = ? OR license_risk_id = ?) AND type IN ('detected','accepted','fixed','reopened') AND created_at <= ? ORDER BY created_at DESC", vulnID, vulnID, vulnID, time).First(&event).Error
	if err != nil {
		return event, err
	}
	return event, nil
}

func (r *eventRepository) DeleteEventByID(ctx context.Context, tx *gorm.DB, eventID string) error {
	db := r.Repository.GetDB(ctx, tx).Where("id = ?", eventID)
	// VulnEvent has no project_id/organization_id column of its own, so scope through the
	// underlying vuln's asset's project instead - prevents deleting another tenant's event by ID,
	// even if a future caller reuses this method without going through EventMiddleware first.
	if ids, ok := shared.OwnershipScopeFromCtx(ctx); ok {
		db = db.Where(`
			dependency_vuln_id IN (SELECT id FROM dependency_vulns WHERE asset_id IN (SELECT id FROM assets WHERE project_id = ?))
			OR first_party_vuln_id IN (SELECT id FROM first_party_vulnerabilities WHERE asset_id IN (SELECT id FROM assets WHERE project_id = ?))
			OR license_risk_id IN (SELECT id FROM license_risks WHERE asset_id IN (SELECT id FROM assets WHERE project_id = ?))
		`, ids.ProjectID, ids.ProjectID, ids.ProjectID)
	}
	res := db.Delete(&models.VulnEvent{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

func (r *eventRepository) HasAccessToEvent(ctx context.Context, tx *gorm.DB, assetID uuid.UUID, eventID string) (bool, error) {
	var count int64
	err := r.GetDB(ctx, tx).Table("vuln_events AS ve").
		Joins("LEFT JOIN dependency_vulns dv ON ve.dependency_vuln_id = dv.id").
		Joins("LEFT JOIN first_party_vulnerabilities fv ON ve.first_party_vuln_id = fv.id").
		Joins("LEFT JOIN license_risks lv ON ve.license_risk_id = lv.id").
		Joins("LEFT JOIN compliance_postures cp ON ve.compliance_posture_id = cp.id").
		Where("ve.id = ? AND (dv.asset_id = ? OR fv.asset_id = ? OR lv.asset_id = ? OR cp.asset_id = ?)", eventID, assetID, assetID, assetID, assetID).
		Count(&count).Error
	if err != nil {
		return false, err
	}
	return count > 0, nil
}
