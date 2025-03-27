package repositories

import (
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
	if err := db.AutoMigrate(&models.VulnEvent{}); err != nil {
		panic(err)
	}
	return &eventRepository{
		db:         db,
		Repository: newGormRepository[uuid.UUID, models.VulnEvent](db),
	}
}

func (r *eventRepository) ReadAssetEventsByVulnID(vulnID string) ([]models.VulnEventDetail, error) {

	var events []models.VulnEventDetail

	//get the dependency vuln to get the asset id and cve id
	var t models.DependencyVuln
	err := r.db.Preload("CVE.Weaknesses").Preload("CVE").Preload("CVE.Exploits").First(&t, "id = ?", vulnID).Error
	if err != nil {
		return nil, err
	}

	err = r.db.Table("vuln_events").Debug().
		Select("vuln_events.*, dependency_vulns.asset_version_name, dependency_vulns.asset_id, asset_versions.slug").
		Joins("LEFT JOIN dependency_vulns ON vuln_events.vuln_id = dependency_vulns.id").
		Joins("LEFT JOIN asset_versions ON dependency_vulns.asset_id = asset_versions.asset_id AND dependency_vulns.asset_version_name = asset_versions.name").
		Where("vuln_events.vuln_id IN (?)",
			r.db.Table("dependency_vulns").
				Select("id").
				Where("asset_id = ? AND cve_id = ? AND component_purl = ? AND scanner_id = ?", t.AssetID, t.CVEID, t.ComponentPurl, t.ScannerID),
		).
		Order("vuln_events.created_at ASC").
		Find(&events).Error
	if err != nil {
		return nil, err
	}

	return events, nil
}
