package repositories

import (
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
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

func (r *eventRepository) ReadAssetEventsByVulnID(vulnID string, vulnType dtos.VulnType) ([]models.VulnEventDetail, error) {
	if vulnType == dtos.VulnTypeDependencyVuln {
		return r.readDependencyVulnAssetEvents(vulnID)
	}
	return r.readFirstPartyVulnAssetEvents(vulnID)
}

func (r *eventRepository) readFirstPartyVulnAssetEvents(vulnID string) ([]models.VulnEventDetail, error) {
	var events []models.VulnEventDetail

	//get the dependency vuln to get the asset id and cve id
	var t models.FirstPartyVuln
	err := r.db.First(&t, "id = ?", vulnID).Error
	if err != nil {
		return nil, err
	}

	err = r.db.Table("vuln_events").
		Select("vuln_events.*, first_party_vulnerabilities.asset_version_name, first_party_vulnerabilities.asset_id, asset_versions.slug").
		Joins("LEFT JOIN first_party_vulnerabilities ON vuln_events.vuln_id = first_party_vulnerabilities.id").
		Joins("LEFT JOIN asset_versions ON first_party_vulnerabilities.asset_id = asset_versions.asset_id AND first_party_vulnerabilities.asset_version_name = asset_versions.name").
		Where("vuln_events.vuln_id IN (?)",
			r.db.Table("first_party_vulnerabilities").
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

func (r *eventRepository) readDependencyVulnAssetEvents(vulnID string) ([]models.VulnEventDetail, error) {
	var events []models.VulnEventDetail

	//get the dependency vuln to get the asset id and cve id
	var t models.DependencyVuln
	err := r.db.Preload("CVE.Weaknesses").Preload("CVE").Preload("CVE.Exploits").First(&t, "id = ?", vulnID).Error
	if err != nil {
		return nil, err
	}

	err = r.db.Table("vuln_events").
		Select("vuln_events.*, dependency_vulns.asset_version_name, dependency_vulns.asset_id, asset_versions.slug").
		Joins("LEFT JOIN dependency_vulns ON vuln_events.vuln_id = dependency_vulns.id").
		Joins("LEFT JOIN asset_versions ON dependency_vulns.asset_id = asset_versions.asset_id AND dependency_vulns.asset_version_name = asset_versions.name").
		Where("vuln_events.vuln_id IN (?)",
			r.db.Table("dependency_vulns").
				Select("id").
				Where("asset_id = ? AND cve_id = ? AND component_purl = ?", t.AssetID, t.CVEID, t.ComponentPurl),
		).
		Order("vuln_events.created_at ASC").
		Find(&events).Error

	if err != nil {
		return nil, err
	}

	return events, nil
}

func (r *eventRepository) ReadEventsByAssetIDAndAssetVersionName(assetID uuid.UUID, assetVersionName string, pageInfo shared.PageInfo, filter []shared.FilterQuery) (shared.Paged[models.VulnEventDetail], error) {

	var events []models.VulnEventDetail

	dependencyVulnSubQuery := r.db.
		Table("dependency_vulns").
		Select("id").
		Where("asset_id = ? AND asset_version_name = ?", assetID, assetVersionName)

	firstPartyVulnSubQuery := r.db.
		Table("first_party_vulnerabilities").
		Select("id").
		Where("asset_id = ? AND asset_version_name = ?", assetID, assetVersionName)

	q := r.db.
		Table("vuln_events AS e").
		Select("e.*, dv.cve_id, dv.component_purl, fv.uri").
		Joins("LEFT JOIN dependency_vulns dv ON e.vuln_id = dv.id").
		Joins("LEFT JOIN first_party_vulnerabilities fv ON e.vuln_id = fv.id").
		Where("(e.vuln_id IN (?) OR e.vuln_id IN (?))", dependencyVulnSubQuery, firstPartyVulnSubQuery).
		Order("e.created_at DESC").
		Find(&events)

	var count int64

	// apply filters
	for _, f := range filter {
		q = q.Where(f.SQL(), f.Value())
	}

	err := q.Count(&count).Error
	if err != nil {
		return shared.Paged[models.VulnEventDetail]{}, err
	}

	err = q.Limit(pageInfo.PageSize).Offset((pageInfo.Page - 1) * pageInfo.PageSize).Find(&events).Error

	return shared.NewPaged(pageInfo, count, events), err
}

func (r *eventRepository) GetSecurityRelevantEventsForVulnIDs(tx *gorm.DB, vulnIDs []string) ([]models.VulnEvent, error) {
	var events []models.VulnEvent
	err := r.Repository.GetDB(tx).Raw("SELECT * FROM vuln_events WHERE vuln_id IN (?) AND type IN ('detected','accepted','falsePositive','fixed','reopened') ORDER BY created_at ASC;", vulnIDs).Find(&events).Error
	if err != nil {
		return nil, err
	}
	return events, nil
}

func (r *eventRepository) GetLastEventBeforeTimestamp(tx *gorm.DB, vulnID string, time time.Time) (models.VulnEvent, error) {
	var event models.VulnEvent
	err := r.Repository.GetDB(tx).Raw("SELECT * FROM vuln_events WHERE vuln_id = ? AND type IN ('detected','accepted','fixed','reopened') AND created_at <= ? ORDER BY created_at DESC", vulnID, time).First(&event).Error
	if err != nil {
		return event, err
	}
	return event, nil
}

func (r *eventRepository) DeleteEventByID(tx shared.DB, eventID string) error {
	return r.Repository.GetDB(tx).Delete(&models.VulnEvent{}, "id = ?", eventID).Error
}

func (r *eventRepository) HasAccessToEvent(assetID uuid.UUID, eventID string) (bool, error) {
	var count int64
	err := r.db.Table("vuln_events AS ve").
		Joins("LEFT JOIN dependency_vulns dv ON ve.vuln_id = dv.id").
		Joins("LEFT JOIN first_party_vulnerabilities fv ON ve.vuln_id = fv.id").
		Joins("LEFT JOIN license_risks lv ON ve.vuln_id = lv.id").
		Where("ve.id = ? AND (dv.asset_id = ? OR fv.asset_id = ? OR lv.asset_id = ?)", eventID, assetID, assetID, assetID).
		Count(&count).Error
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// falsePositiveRuleRow is used for GORM scanning with the cve_id column tag.
type falsePositiveRuleRow struct {
	models.VulnEvent
	CVEID string `gorm:"column:cve_id"`
}

// GetFalsePositiveRulesForAsset returns all false positive events with path patterns for a given asset.
// These are used as rules that can be automatically applied to new or existing vulnerabilities
// whose path matches the pattern. Returns the CVE ID with each rule since path patterns only
// apply to the same CVE.
func (r *eventRepository) GetFalsePositiveRulesForAsset(tx *gorm.DB, assetID uuid.UUID) ([]shared.FalsePositiveRule, error) {
	var rows []falsePositiveRuleRow
	db := r.Repository.GetDB(tx)
	if tx == nil {
		db = r.db
	}

	// Find all false positive events that:
	// 1. Have a non-null path_pattern
	// 2. Are associated with dependency vulns in this asset
	// Also select the CVE ID from the dependency vuln
	err := db.Table("vuln_events AS ve").
		Select("ve.*, dv.cve_id").
		Joins("JOIN dependency_vulns dv ON ve.vuln_id = dv.id").
		Where("dv.asset_id = ? AND ve.type = ? AND ve.path_pattern IS NOT NULL", assetID, dtos.EventTypeFalsePositive).
		Find(&rows).Error

	if err != nil {
		return nil, err
	}

	// Convert to shared type
	rules := make([]shared.FalsePositiveRule, len(rows))
	for i, row := range rows {
		rules[i] = shared.FalsePositiveRule{
			VulnEvent: row.VulnEvent,
			CVEID:     row.CVEID,
		}
	}
	return rules, nil
}
