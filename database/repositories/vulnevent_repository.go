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

func (r *eventRepository) CreateBatchWithUnnest(tx *gorm.DB, events []models.VulnEvent) error {
	if len(events) == 0 {
		return nil
	}

	ids := make([]uuid.UUID, len(events))
	types := make([]dtos.VulnEventType, len(events))
	vulnIDs := make([]string, len(events))
	vulnTypes := make([]string, len(events))
	userIDs := make([]string, len(events))
	justifications := make([]*string, len(events))
	mechanicalJustifications := make([]string, len(events))
	arbitraryJSONData := make([]string, len(events))
	originalAssetVersionNames := make([]*string, len(events))
	upstreams := make([]int, len(events))

	for i := range events {
		// if there somehow already is an id present we keep that, otherwise generate a new one
		if events[i].ID == uuid.Nil {
			ids[i] = uuid.New()
		} else {
			ids[i] = events[i].ID
		}
		types[i] = events[i].Type
		vulnIDs[i] = events[i].VulnID
		vulnTypes[i] = string(events[i].VulnType)
		userIDs[i] = events[i].UserID
		justifications[i] = events[i].Justification
		mechanicalJustifications[i] = string(events[i].MechanicalJustification)
		arbitraryJSONData[i] = events[i].ArbitraryJSONData
		originalAssetVersionNames[i] = events[i].OriginalAssetVersionName
		upstreams[i] = int(events[i].Upstream)
	}

	query := `
        INSERT INTO vuln_events (id,type,vuln_id,vuln_type,user_id,justification,mechanical_justification,arbitrary_json_data,original_asset_version_name,upstream)
        SELECT
            unnest($1::uuid[]),
            unnest($2::text[]),
            unnest($3::text[]),
            unnest($4::text[]),
            unnest($5::text[]),
            unnest($6::text[]),
            unnest($7::text[]),
            unnest($8::text[]),
			unnest($9::text[]),
			unnest($10::int4[])`

	return r.GetDB(tx).Exec(query, ids, types, vulnIDs, vulnTypes, userIDs, justifications, mechanicalJustifications, arbitraryJSONData, originalAssetVersionNames, upstreams).Error
}
