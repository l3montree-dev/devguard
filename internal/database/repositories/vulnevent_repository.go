package repositories

import (
	"os"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
)

type eventRepository struct {
	db core.DB
	common.Repository[uuid.UUID, models.VulnEvent, core.DB]
}

func NewVulnEventRepository(db core.DB) *eventRepository {
	if os.Getenv("DISABLE_AUTOMIGRATE") != "true" {
		if err := db.AutoMigrate(&models.VulnEvent{}); err != nil {
			panic(err)
		}
	}
	return &eventRepository{
		db:         db,
		Repository: newGormRepository[uuid.UUID, models.VulnEvent](db),
	}
}

func (r *eventRepository) ReadAssetEventsByVulnID(vulnID string, vulnType models.VulnType) ([]models.VulnEventDetail, error) {
	if vulnType == models.VulnTypeDependencyVuln {
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

func (r *eventRepository) ReadEventsByAssetIDAndAssetVersionName(assetID uuid.UUID, assetVersionName string, pageInfo core.PageInfo, filter []core.FilterQuery) (core.Paged[models.VulnEventDetail], error) {

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
		return core.Paged[models.VulnEventDetail]{}, err
	}

	err = q.Limit(pageInfo.PageSize).Offset((pageInfo.Page - 1) * pageInfo.PageSize).Find(&events).Error

	return core.NewPaged(pageInfo, count, events), err
}
func (r *eventRepository) DeleteEventsWithNotExistingVulnID() error {

	err := r.db.Unscoped().
		Where(`NOT EXISTS (
		SELECT 1 FROM dependency_vulns UNION SELECT 1 FROM first_party_vulnerabilities)`).
		Delete(&models.VulnEvent{}).Error

	if err != nil {
		return err
	}

	return nil
}
