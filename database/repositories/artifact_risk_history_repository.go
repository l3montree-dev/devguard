package repositories

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/utils"
	"gorm.io/gorm"
)

type artifactRiskHistoryRepository struct {
	db *gorm.DB
	utils.Repository[uint, models.ArtifactRiskHistory, *gorm.DB]
}

func NewArtifactRiskHistoryRepository(db *gorm.DB) *artifactRiskHistoryRepository {
	return &artifactRiskHistoryRepository{
		db:         db,
		Repository: newGormRepository[uint, models.ArtifactRiskHistory](db),
	}
}

func (r *artifactRiskHistoryRepository) GetRiskHistory(ctx context.Context, tx *gorm.DB, artifactName *string, assetVersionName string, assetID uuid.UUID, start, end time.Time) ([]models.ArtifactRiskHistory, error) {
	var assetRisk = []models.ArtifactRiskHistory{}
	db := r.GetDB(ctx, tx)

	// base query
	db = db.Where("asset_version_name = ? AND asset_id = ?", assetVersionName, assetID)

	// optional artifact filter
	if artifactName != nil {
		db = db.Where("artifact_name = ?", *artifactName)
	}

	if err := db.Where("day >= ? AND day <= ?", start, end).Order("day ASC").Find(&assetRisk).Error; err != nil {
		return nil, err
	}

	return assetRisk, nil
}

func (r *artifactRiskHistoryRepository) UpdateRiskAggregation(ctx context.Context, tx *gorm.DB, assetRisk *models.ArtifactRiskHistory) error {
	return r.Repository.GetDB(ctx, tx).Save(assetRisk).Error
}

func (r *artifactRiskHistoryRepository) GetRiskHistoryByRelease(ctx context.Context, tx *gorm.DB, releaseID uuid.UUID, start, end time.Time) ([]models.ArtifactRiskHistory, error) {
	var assetRisk = []models.ArtifactRiskHistory{}

	// Use a recursive CTE to collect the release tree (the release and all child releases)
	// then join release_items to artifact_risk_history to get all matching artifact histories.
	db := r.GetDB(ctx, tx)

	query := `
		WITH RECURSIVE release_tree AS (
			SELECT id
			FROM releases
			WHERE id = ?
			UNION ALL
			SELECT ri.child_release_id
			FROM release_items ri
			JOIN release_tree rt ON ri.release_id = rt.id
			WHERE ri.child_release_id IS NOT NULL
		),
		unique_release_items AS (
			SELECT DISTINCT asset_id, asset_version_name, artifact_name
			FROM release_items
			WHERE release_id IN (SELECT id FROM release_tree)
		)
		SELECT DISTINCT arh.artifact_name, arh.asset_version_name, arh.asset_id, arh.day, arh.sum_open_risk, arh.avg_open_risk, arh.max_open_risk, arh.min_open_risk,
		       arh.sum_closed_risk, arh.avg_closed_risk, arh.max_closed_risk, arh.min_closed_risk,
		       arh.open_dependency_vulns, arh.fixed_dependency_vulns,
		       arh.low, arh.medium, arh.high, arh.critical,
		       arh.fixable_low, arh.fixable_medium, arh.fixable_high, arh.fixable_critical,
			   arh.cve_purl_low, arh.cve_purl_medium, arh.cve_purl_high, arh.cve_purl_critical,
			   arh.cve_purl_fixable_low, arh.cve_purl_fixable_medium, arh.cve_purl_fixable_high, arh.cve_purl_fixable_critical,
		       arh.low_cvss, arh.medium_cvss, arh.high_cvss, arh.critical_cvss,
			   arh.cve_purl_low_cvss, arh.cve_purl_medium_cvss, arh.cve_purl_high_cvss, arh.cve_purl_critical_cvss
		FROM artifact_risk_history arh
		JOIN unique_release_items uri
		ON arh.asset_id = uri.asset_id
		AND arh.asset_version_name = uri.asset_version_name
		AND arh.artifact_name = uri.artifact_name
		AND arh.day >= ? AND arh.day <= ?
		ORDER BY arh.day ASC
	`

	if err := db.Raw(query, releaseID, start, end).Scan(&assetRisk).Error; err != nil {
		return nil, err
	}

	return assetRisk, nil
}

func (r *artifactRiskHistoryRepository) GetRiskHistoryForOrg(ctx context.Context, tx *gorm.DB, orgID uuid.UUID, start, end time.Time) ([]dtos.OrgRiskHistory, error) {
	history := []dtos.OrgRiskHistory{}
	err := r.GetDB(ctx, tx).Raw(`
	SELECT
		day,
		SUM(low) low, SUM(medium) medium, SUM(high) high, SUM(critical) critical,
		SUM(fixable_low) fixable_low, SUM(fixable_medium) fixable_medium, SUM(fixable_high) fixable_high, SUM(fixable_critical) fixable_critical,
		SUM(low_cvss) low_cvss, SUM(medium_cvss) medium_cvss, SUM(high_cvss) high_cvss, SUM(critical_cvss) critical_cvss,
		SUM(cve_purl_low) cve_purl_low, SUM(cve_purl_medium) cve_purl_medium, SUM(cve_purl_high) cve_purl_high, SUM(cve_purl_critical) cve_purl_critical,
		SUM(cve_purl_fixable_low) cve_purl_fixable_low, SUM(cve_purl_fixable_medium) cve_purl_fixable_medium, SUM(cve_purl_fixable_high) cve_purl_fixable_high, SUM(cve_purl_fixable_critical) cve_purl_fixable_critical,
		SUM(cve_purl_low_cvss) cve_purl_low_cvss, SUM(cve_purl_medium_cvss) cve_purl_medium_cvss, SUM(cve_purl_high_cvss) cve_purl_high_cvss, SUM(cve_purl_critical_cvss) cve_purl_critical_cvss
	FROM
		artifact_risk_history a
	LEFT JOIN
		assets b ON a.asset_id = b.id
	LEFT JOIN
		projects c ON b.project_id = c.id
	WHERE
		c.organization_id = ?
	AND
		a.day >= ?
	AND
		a.day <= ?
	GROUP BY day
	ORDER BY day ASC;`, orgID, start, end).Find(&history).Error
	return history, err
}
