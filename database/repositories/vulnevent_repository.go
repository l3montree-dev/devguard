package repositories

import (
	"context"
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
	err := r.GetDB(ctx, tx).First(&t, "id = ?", vulnID).Error
	if err != nil {
		return nil, err
	}

	err = r.GetDB(ctx, tx).Table("vuln_events").
		Select("vuln_events.*, first_party_vulnerabilities.asset_version_name, first_party_vulnerabilities.asset_id, asset_versions.slug").
		Joins("LEFT JOIN first_party_vulnerabilities ON vuln_events.first_party_vuln_id = first_party_vulnerabilities.id").
		Joins("LEFT JOIN asset_versions ON first_party_vulnerabilities.asset_id = asset_versions.asset_id AND first_party_vulnerabilities.asset_version_name = asset_versions.name").
		Where("vuln_events.first_party_vuln_id IN (?)",
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
	err := r.GetDB(ctx, tx).Preload("CVE.Weaknesses").Preload("CVE").Preload("CVE.Exploits").First(&t, "id = ?", vulnID).Error
	if err != nil {
		return nil, err
	}

	err = r.GetDB(ctx, tx).Table("vuln_events").
		Select("vuln_events.*, dependency_vulns.asset_version_name, dependency_vulns.asset_id, asset_versions.slug").
		Joins("LEFT JOIN dependency_vulns ON vuln_events.dependency_vuln_id = dependency_vulns.id").
		Joins("LEFT JOIN asset_versions ON dependency_vulns.asset_id = asset_versions.asset_id AND dependency_vulns.asset_version_name = asset_versions.name").
		Where("vuln_events.dependency_vuln_id IN (?)",
			r.GetDB(ctx, tx).Table("dependency_vulns").
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

func (r *eventRepository) ReadEventsByAssetIDAndAssetVersionName(ctx context.Context, tx *gorm.DB, assetID uuid.UUID, assetVersionName string, pageInfo shared.PageInfo, filter []shared.FilterQuery) (shared.Paged[models.VulnEventDetail], error) {

	var events []models.VulnEventDetail

	dependencyVulnSubQuery := r.GetDB(ctx, tx).
		Table("dependency_vulns").
		Select("id").
		Where("asset_id = ? AND asset_version_name = ?", assetID, assetVersionName)

	firstPartyVulnSubQuery := r.GetDB(ctx, tx).
		Table("first_party_vulnerabilities").
		Select("id").
		Where("asset_id = ? AND asset_version_name = ?", assetID, assetVersionName)

	q := r.GetDB(ctx, tx).
		Table("vuln_events AS e").
		Select("e.*, dv.cve_id, dv.component_purl, fv.uri").
		Joins("LEFT JOIN dependency_vulns dv ON e.dependency_vuln_id = dv.id").
		Joins("LEFT JOIN first_party_vulnerabilities fv ON e.first_party_vuln_id = fv.id").
		Where("(e.dependency_vuln_id IN (?) OR e.first_party_vuln_id IN (?))", dependencyVulnSubQuery, firstPartyVulnSubQuery).
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

func (r *eventRepository) GetSecurityRelevantEventsForVulnIDs(ctx context.Context, tx *gorm.DB, vulnIDs []uuid.UUID) ([]models.VulnEvent, error) {
	var events []models.VulnEvent
	err := r.Repository.GetDB(ctx, tx).Raw("SELECT * FROM vuln_events WHERE (dependency_vuln_id IN (?) OR first_party_vuln_id IN (?) OR license_risk_id IN (?)) AND type IN ('detected','accepted','falsePositive','fixed','reopened') ORDER BY created_at ASC;", vulnIDs, vulnIDs, vulnIDs).Find(&events).Error
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
	return r.Repository.GetDB(ctx, tx).Delete(&models.VulnEvent{}, "id = ?", eventID).Error
}

func (r *eventRepository) HasAccessToEvent(ctx context.Context, tx *gorm.DB, assetID uuid.UUID, eventID string) (bool, error) {
	var count int64
	err := r.GetDB(ctx, tx).Table("vuln_events AS ve").
		Joins("LEFT JOIN dependency_vulns dv ON ve.dependency_vuln_id = dv.id").
		Joins("LEFT JOIN first_party_vulnerabilities fv ON ve.first_party_vuln_id = fv.id").
		Joins("LEFT JOIN license_risks lv ON ve.license_risk_id = lv.id").
		Where("ve.id = ? AND (dv.asset_id = ? OR fv.asset_id = ? OR lv.asset_id = ?)", eventID, assetID, assetID, assetID).
		Count(&count).Error
	if err != nil {
		return false, err
	}
	return count > 0, nil
}
