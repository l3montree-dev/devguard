package repositories

import (
	"context"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/statemachine"
)

type statisticsRepository struct {
	db *gorm.DB
}

func NewStatisticsRepository(db *gorm.DB) *statisticsRepository {
	return &statisticsRepository{
		db: db,
	}
}

var _ shared.StatisticsRepository = (*statisticsRepository)(nil)

func (r *statisticsRepository) GetDB(ctx context.Context, tx *gorm.DB) *gorm.DB {
	if tx != nil {
		return tx
	}
	return r.db.WithContext(ctx)
}

// returns all dependencyVulns for the asset including the events, which were created before the given time
func (r *statisticsRepository) TimeTravelDependencyVulnState(ctx context.Context, tx *gorm.DB, artifactName *string, assetVersionName *string, assetID uuid.UUID, time time.Time) ([]models.DependencyVuln, error) {
	dependencyVulns := []models.DependencyVuln{}
	var err error
	if artifactName == nil && assetVersionName == nil {
		err = r.GetDB(ctx, tx).Model(&models.DependencyVuln{}).Select("dependency_vulns.*").Preload("CVE").Preload("Events", func(db *gorm.DB) *gorm.DB {
			return db.Where("created_at <= ?", time).Order("created_at ASC")
		}).
			Joins("JOIN artifact_dependency_vulns adv ON adv.dependency_vuln_id = dependency_vulns.id").
			Where("dependency_vulns.asset_id = ?", assetID).Where("created_at <= ?", time).
			Find(&dependencyVulns).Error
	} else if artifactName != nil {
		err = r.GetDB(ctx, tx).Model(&models.DependencyVuln{}).Select("dependency_vulns.*").Preload("CVE").Preload("Events", func(db *gorm.DB) *gorm.DB {
			return db.Where("created_at <= ?", time).Order("created_at ASC")
		}).
			Joins("JOIN artifact_dependency_vulns adv ON adv.dependency_vuln_id = dependency_vulns.id").
			Where("adv.artifact_asset_version_name = ?", *assetVersionName).Where("adv.artifact_asset_id = ?", assetID).Where("adv.artifact_artifact_name = ?", *artifactName).Where("created_at <= ?", time).
			Find(&dependencyVulns).Error
	} else {
		err = r.GetDB(ctx, tx).Model(&models.DependencyVuln{}).Select("dependency_vulns.*").Preload("CVE").Preload("Events", func(db *gorm.DB) *gorm.DB {
			return db.Where("created_at <= ?", time).Order("created_at ASC")
		}).
			Joins("JOIN artifact_dependency_vulns adv ON adv.dependency_vuln_id = dependency_vulns.id").
			Where("adv.artifact_asset_id = ?", assetID).Where("adv.artifact_artifact_name = ?", artifactName).Where("created_at <= ?", time).
			Find(&dependencyVulns).Error
	}
	if err != nil {
		return nil, err
	}

	return replayHistoricalEvents(dependencyVulns), nil
}

// replayHistoricalEvents reconstructs the historical state of each
// DependencyVuln by replaying its (already time-filtered) Events in order.
// The State field is reset to the zero value before replay so that
// EventTypeDetected can correctly set state to "open" even when the current
// persisted state is "fixed" (the statemachine guard that protects fixed /
// accepted vulns from being re-opened by detected events must not apply here).
func replayHistoricalEvents(dependencyVulns []models.DependencyVuln) []models.DependencyVuln {
	for i := range dependencyVulns {
		dependencyVulns[i].State = "" // start from neutral state for correct replay
		for _, event := range dependencyVulns[i].Events {
			statemachine.Apply(&dependencyVulns[i], event)
		}
	}
	return dependencyVulns
}

var fixedEvents = []dtos.VulnEventType{
	dtos.EventTypeAccepted,
	dtos.EventTypeFixed,
	dtos.EventTypeFalsePositive,
}

var openEvents = []dtos.VulnEventType{
	dtos.EventTypeDetected,
	dtos.EventTypeReopened,
}

func (r *statisticsRepository) AverageFixingTimes(ctx context.Context, artifactName *string, assetVersionName string, assetID uuid.UUID) (dtos.RemediationTimeAverages, error) {
	results := dtos.RemediationTimeAverages{}

	var err error

	if artifactName == nil {
		err = r.db.Raw(`
WITH events AS (
	SELECT
		dependency_vulns.raw_risk_assessment,
		c.cvss,
		fe.type,
		fe.created_at,
		LAG(fe.type)       OVER (PARTITION BY dependency_vulns.id ORDER BY fe.created_at) AS prev_type,
		LAG(fe.created_at) OVER (PARTITION BY dependency_vulns.id ORDER BY fe.created_at) AS prev_created_at
	FROM dependency_vulns
	JOIN vuln_events fe ON dependency_vulns.id = fe.dependency_vuln_id
	LEFT JOIN cves c ON dependency_vulns.cve_id = c.cve
	WHERE fe.type IN ?
	AND dependency_vulns.asset_version_name = ?
	AND dependency_vulns.asset_id = ?
)
SELECT
	COALESCE(EXTRACT(EPOCH FROM AVG(created_at - prev_created_at) FILTER (WHERE raw_risk_assessment >= 0  AND raw_risk_assessment <  4)),0)  AS risk_avg_low,
	COALESCE(EXTRACT(EPOCH FROM AVG(created_at - prev_created_at) FILTER (WHERE raw_risk_assessment >= 4  AND raw_risk_assessment <  7)),0)  AS risk_avg_medium,
	COALESCE(EXTRACT(EPOCH FROM AVG(created_at - prev_created_at) FILTER (WHERE raw_risk_assessment >= 7  AND raw_risk_assessment <  9)),0)  AS risk_avg_high,
	COALESCE(EXTRACT(EPOCH FROM AVG(created_at - prev_created_at) FILTER (WHERE raw_risk_assessment >= 9  AND raw_risk_assessment <= 10)),0) AS risk_avg_critical,

	COALESCE(EXTRACT(EPOCH FROM AVG(created_at - prev_created_at) FILTER (WHERE cvss >= 0  AND cvss <  4)),0)  AS cvss_avg_low,
	COALESCE(EXTRACT(EPOCH FROM AVG(created_at - prev_created_at) FILTER (WHERE cvss >= 4  AND cvss <  7)),0)  AS cvss_avg_medium,
	COALESCE(EXTRACT(EPOCH FROM AVG(created_at - prev_created_at) FILTER (WHERE cvss >= 7  AND cvss <  9)),0)  AS cvss_avg_high,
	COALESCE(EXTRACT(EPOCH FROM AVG(created_at - prev_created_at) FILTER (WHERE cvss >= 9  AND cvss <= 10)),0) AS cvss_avg_critical
FROM events
WHERE type IN ? AND prev_type IN ?;`, append(fixedEvents, openEvents...), assetVersionName, assetID, fixedEvents, openEvents).Find(&results).Error
	} else {
		err = r.db.Raw(`
WITH events AS (
	SELECT
		dependency_vulns.raw_risk_assessment,
		c.cvss,
		fe.type,
		fe.created_at,
		LAG(fe.type)       OVER (PARTITION BY dependency_vulns.id ORDER BY fe.created_at) AS prev_type,
		LAG(fe.created_at) OVER (PARTITION BY dependency_vulns.id ORDER BY fe.created_at) AS prev_created_at
	FROM dependency_vulns
	JOIN vuln_events fe ON dependency_vulns.id = fe.dependency_vuln_id
	LEFT JOIN cves c ON dependency_vulns.cve_id = c.cve
	JOIN (
		SELECT DISTINCT artifact_dependency_vulns.dependency_vuln_id
		FROM artifact_dependency_vulns
		WHERE artifact_artifact_name = ?
	) AS adv ON dependency_vulns.id = adv.dependency_vuln_id
	WHERE fe.type IN ?
	AND dependency_vulns.asset_version_name = ?
	AND dependency_vulns.asset_id = ?
)
SELECT
	COALESCE(EXTRACT(EPOCH FROM AVG(created_at - prev_created_at) FILTER (WHERE raw_risk_assessment >= 0  AND raw_risk_assessment <  4)),0)  AS risk_avg_low,
	COALESCE(EXTRACT(EPOCH FROM AVG(created_at - prev_created_at) FILTER (WHERE raw_risk_assessment >= 4  AND raw_risk_assessment <  7)),0)  AS risk_avg_medium,
	COALESCE(EXTRACT(EPOCH FROM AVG(created_at - prev_created_at) FILTER (WHERE raw_risk_assessment >= 7  AND raw_risk_assessment <  9)),0)  AS risk_avg_high,
	COALESCE(EXTRACT(EPOCH FROM AVG(created_at - prev_created_at) FILTER (WHERE raw_risk_assessment >= 9  AND raw_risk_assessment <= 10)),0) AS risk_avg_critical,

	COALESCE(EXTRACT(EPOCH FROM AVG(created_at - prev_created_at) FILTER (WHERE cvss >= 0  AND cvss <  4)),0)  AS cvss_avg_low,
	COALESCE(EXTRACT(EPOCH FROM AVG(created_at - prev_created_at) FILTER (WHERE cvss >= 4  AND cvss <  7)),0)  AS cvss_avg_medium,
	COALESCE(EXTRACT(EPOCH FROM AVG(created_at - prev_created_at) FILTER (WHERE cvss >= 7  AND cvss <  9)),0)  AS cvss_avg_high,
	COALESCE(EXTRACT(EPOCH FROM AVG(created_at - prev_created_at) FILTER (WHERE cvss >= 9  AND cvss <= 10)),0) AS cvss_avg_critical
FROM events
WHERE type IN ? AND prev_type IN ?;`, artifactName, append(fixedEvents, openEvents...), assetVersionName, assetID, fixedEvents, openEvents).Find(&results).Error
	}

	return results, err
}

func (r *statisticsRepository) AverageRemediationTimesForRelease(ctx context.Context, tx *gorm.DB, releaseID uuid.UUID) (dtos.RemediationTimeAverages, error) {
	results := dtos.RemediationTimeAverages{}
	err := r.GetDB(ctx, tx).Raw(`
WITH RECURSIVE release_tree AS (
	SELECT id FROM releases WHERE id = ?
	UNION ALL
	SELECT ri.child_release_id FROM release_items ri JOIN release_tree rt ON ri.release_id = rt.id WHERE ri.child_release_id IS NOT NULL
),
events AS (
	SELECT
		dv.raw_risk_assessment,
		c.cvss,
		fe.type,
		fe.created_at,
		LAG(fe.type)       OVER (PARTITION BY dv.id ORDER BY fe.created_at) AS prev_type,
		LAG(fe.created_at) OVER (PARTITION BY dv.id ORDER BY fe.created_at) AS prev_created_at
	FROM dependency_vulns dv
	JOIN vuln_events fe ON dv.id = fe.dependency_vuln_id
	JOIN release_items ri ON dv.asset_version_name = ri.asset_version_name AND dv.asset_id = ri.asset_id
	LEFT JOIN cves c ON dv.cve_id = c.cve
	WHERE ri.release_id IN (SELECT id FROM release_tree) AND fe.type IN ?
)
SELECT
	COALESCE(EXTRACT(EPOCH FROM AVG(created_at - prev_created_at) FILTER (WHERE raw_risk_assessment >= 0  AND raw_risk_assessment <  4)),0)  AS risk_avg_low,
	COALESCE(EXTRACT(EPOCH FROM AVG(created_at - prev_created_at) FILTER (WHERE raw_risk_assessment >= 4  AND raw_risk_assessment <  7)),0)  AS risk_avg_medium,
	COALESCE(EXTRACT(EPOCH FROM AVG(created_at - prev_created_at) FILTER (WHERE raw_risk_assessment >= 7  AND raw_risk_assessment <  9)),0)  AS risk_avg_high,
	COALESCE(EXTRACT(EPOCH FROM AVG(created_at - prev_created_at) FILTER (WHERE raw_risk_assessment >= 9  AND raw_risk_assessment <= 10)),0) AS risk_avg_critical,

	COALESCE(EXTRACT(EPOCH FROM AVG(created_at - prev_created_at) FILTER (WHERE cvss >= 0  AND cvss <  4)),0)  AS cvss_avg_low,
	COALESCE(EXTRACT(EPOCH FROM AVG(created_at - prev_created_at) FILTER (WHERE cvss >= 4  AND cvss <  7)),0)  AS cvss_avg_medium,
	COALESCE(EXTRACT(EPOCH FROM AVG(created_at - prev_created_at) FILTER (WHERE cvss >= 7  AND cvss <  9)),0)  AS cvss_avg_high,
	COALESCE(EXTRACT(EPOCH FROM AVG(created_at - prev_created_at) FILTER (WHERE cvss >= 9  AND cvss <= 10)),0) AS cvss_avg_critical
FROM events
WHERE type IN ? AND prev_type IN ?;`, releaseID, append(fixedEvents, openEvents...), fixedEvents, openEvents).Find(&results).Error
	return results, err
}

func (r *statisticsRepository) CVESWithKnownExploitsInAssetVersion(ctx context.Context, tx *gorm.DB, assetVersion models.AssetVersion) ([]models.CVE, error) {
	var cves []models.CVE

	//Query to find all CVE in the vulnerabilities for which an exploit exists
	err := r.GetDB(ctx, tx).Raw("SELECT c.* FROM dependency_vulns d JOIN cves c ON d.cve_id = c.cve WHERE  EXISTS (SELECT id FROM exploits e WHERE d.cve_id = e.cve_id) AND d.asset_version_name = ?  AND d.state = 'open'  AND d.asset_id = ?;", assetVersion.Name, assetVersion.AssetID).Find(&cves).Error
	if err != nil {
		return cves, err
	}

	return cves, nil
}

// TO-DO refactor to dtos

func (r *statisticsRepository) VulnClassificationByOrg(ctx context.Context, tx *gorm.DB, orgID uuid.UUID) (dtos.Distribution, error) {
	distribution := dtos.Distribution{}
	err := r.GetDB(ctx, tx).Raw(`
	SELECT
		COUNT(*) filter (where a.raw_risk_assessment < 4) as low,
		COUNT(*) filter (where a.raw_risk_assessment >= 4 AND a.raw_risk_assessment < 7) as medium,
		COUNT(*) filter (where a.raw_risk_assessment >= 7 AND a.raw_risk_assessment < 9) as high,
		COUNT(*) filter (where a.raw_risk_assessment >= 9 AND a.raw_risk_assessment <= 10) as critical,
		COUNT(*) filter (where d.cvss < 4) as low_cvss,
		COUNT(*) filter (where d.cvss >= 4 AND d.cvss < 7) as medium_cvss,
		COUNT(*) filter (where d.cvss >= 7 AND d.cvss < 9) as high_cvss,
		COUNT(*) filter (where d.cvss >= 9 AND d.cvss <= 10) as critical_cvss,
		COUNT(DISTINCT CASE WHEN a.raw_risk_assessment < 4 THEN a.cve_id || '|' || a.component_purl END) as cve_purl_low,
		COUNT(DISTINCT CASE WHEN a.raw_risk_assessment >= 4 AND a.raw_risk_assessment < 7 THEN a.cve_id || '|' || a.component_purl END) as cve_purl_medium,
		COUNT(DISTINCT CASE WHEN a.raw_risk_assessment >= 7 AND a.raw_risk_assessment < 9 THEN a.cve_id || '|' || a.component_purl END) as cve_purl_high,
		COUNT(DISTINCT CASE WHEN a.raw_risk_assessment >= 9 AND a.raw_risk_assessment <= 10 THEN a.cve_id || '|' || a.component_purl END) as cve_purl_critical,
		COUNT(DISTINCT CASE WHEN d.cvss < 4 THEN a.cve_id || '|' || a.component_purl END) as cve_purl_low_cvss,
		COUNT(DISTINCT CASE WHEN d.cvss >= 4 AND d.cvss < 7 THEN a.cve_id || '|' || a.component_purl END) as cve_purl_medium_cvss,
		COUNT(DISTINCT CASE WHEN d.cvss >= 7 AND d.cvss < 9 THEN a.cve_id || '|' || a.component_purl END) as cve_purl_high_cvss,
		COUNT(DISTINCT CASE WHEN d.cvss >= 9 AND d.cvss <= 10 THEN a.cve_id || '|' || a.component_purl END) as cve_purl_critical_cvss
	FROM dependency_vulns a
	LEFT JOIN assets b ON a.asset_id = b.id
	LEFT JOIN projects c ON b.project_id = c.id
	LEFT JOIN cves d ON a.cve_id = d.cve
	WHERE c.organization_id = ?
	AND a.state = 'open';`, orgID).Find(&distribution).Error
	if err != nil {
		return distribution, err
	}
	return distribution, nil
}

func (r *statisticsRepository) GetOrgStructureDistribution(ctx context.Context, tx *gorm.DB, orgID uuid.UUID) (dtos.OrgStructureDistribution, error) {
	structure := dtos.OrgStructureDistribution{}
	err := r.GetDB(ctx, tx).Raw(`
			SELECT 
				COUNT(DISTINCT(p.id)) as num_projects, 
				COUNT(DISTINCT(a.id)) as num_assets, 
				COUNT(DISTINCT(art.artifact_name, art.asset_version_name,art.asset_id)) as num_artifacts 
			FROM 
				projects p 
			LEFT JOIN 
				assets a ON p.id = a.project_id
			LEFT JOIN 
				artifacts art ON art.asset_id = a.id
			WHERE 
				p.organization_id = ?;`, orgID).Find(&structure).Error
	return structure, err
}

func (r *statisticsRepository) GetMostVulnerableProjectsInOrg(ctx context.Context, tx *gorm.DB, orgID uuid.UUID, limit int) ([]dtos.VulnDistributionInStructure, error) {
	projects := []dtos.VulnDistributionInStructure{}
	err := r.GetDB(ctx, tx).Raw(`SELECT c.name, c.slug,
			 COUNT(*) as total,
			 COUNT(*) filter (where a.raw_risk_assessment < 4) as low,
			 COUNT(*) filter (where a.raw_risk_assessment >= 4 AND a.raw_risk_assessment < 7) as medium,
			 COUNT(*) filter (where a.raw_risk_assessment >= 7 AND a.raw_risk_assessment < 9) as high,
			 COUNT(*) filter (where a.raw_risk_assessment >= 9 AND a.raw_risk_assessment <= 10) as critical,
			 COUNT(*) filter (where d.cvss < 4) as low_cvss,
			 COUNT(*) filter (where d.cvss >= 4 AND d.cvss < 7) as medium_cvss,
			 COUNT(*) filter (where d.cvss >= 7 AND d.cvss < 9) as high_cvss,
			 COUNT(*) filter (where d.cvss >= 9 AND d.cvss <= 10) as critical_cvss,
			 COUNT(DISTINCT CASE WHEN a.raw_risk_assessment < 4 THEN a.cve_id || '|' || a.component_purl END) as cve_purl_low,
			 COUNT(DISTINCT CASE WHEN a.raw_risk_assessment >= 4 AND a.raw_risk_assessment < 7 THEN a.cve_id || '|' || a.component_purl END) as cve_purl_medium,
			 COUNT(DISTINCT CASE WHEN a.raw_risk_assessment >= 7 AND a.raw_risk_assessment < 9 THEN a.cve_id || '|' || a.component_purl END) as cve_purl_high,
			 COUNT(DISTINCT CASE WHEN a.raw_risk_assessment >= 9 AND a.raw_risk_assessment <= 10 THEN a.cve_id || '|' || a.component_purl END) as cve_purl_critical,
			 COUNT(DISTINCT CASE WHEN d.cvss < 4 THEN a.cve_id || '|' || a.component_purl END) as cve_purl_low_cvss,
			 COUNT(DISTINCT CASE WHEN d.cvss >= 4 AND d.cvss < 7 THEN a.cve_id || '|' || a.component_purl END) as cve_purl_medium_cvss,
			 COUNT(DISTINCT CASE WHEN d.cvss >= 7 AND d.cvss < 9 THEN a.cve_id || '|' || a.component_purl END) as cve_purl_high_cvss,
			 COUNT(DISTINCT CASE WHEN d.cvss >= 9 AND d.cvss <= 10 THEN a.cve_id || '|' || a.component_purl END) as cve_purl_critical_cvss
			 FROM dependency_vulns a
			 LEFT JOIN assets b ON a.asset_id = b.id
			 LEFT JOIN projects c ON b.project_id = c.id
			 LEFT JOIN cves d ON a.cve_id = d.cve
			 WHERE c.organization_id = ?
			 AND a.state = 'open'
			 GROUP BY c.id, c.slug
			 ORDER BY total DESC LIMIT ?;`, orgID, limit).Find(&projects).Error
	return projects, err
}

func (r *statisticsRepository) GetMostVulnerableAssetsInOrg(ctx context.Context, tx *gorm.DB, orgID uuid.UUID, limit int) ([]dtos.VulnDistributionInStructure, error) {
	assets := []dtos.VulnDistributionInStructure{}
	err := r.GetDB(ctx, tx).Raw(`SELECT b.name, b.slug, c.slug as project_slug,
			 COUNT(*) as total,
			 COUNT(*) filter (where a.raw_risk_assessment < 4) as low,
			 COUNT(*) filter (where a.raw_risk_assessment >= 4 AND a.raw_risk_assessment < 7) as medium,
			 COUNT(*) filter (where a.raw_risk_assessment >= 7 AND a.raw_risk_assessment < 9) as high,
			 COUNT(*) filter (where a.raw_risk_assessment >= 9 AND a.raw_risk_assessment <= 10) as critical,
			 COUNT(*) filter (where d.cvss < 4) as low_cvss,
			 COUNT(*) filter (where d.cvss >= 4 AND d.cvss < 7) as medium_cvss,
			 COUNT(*) filter (where d.cvss >= 7 AND d.cvss < 9) as high_cvss,
			 COUNT(*) filter (where d.cvss >= 9 AND d.cvss <= 10) as critical_cvss,
			 COUNT(DISTINCT CASE WHEN a.raw_risk_assessment < 4 THEN a.cve_id || '|' || a.component_purl END) as cve_purl_low,
			 COUNT(DISTINCT CASE WHEN a.raw_risk_assessment >= 4 AND a.raw_risk_assessment < 7 THEN a.cve_id || '|' || a.component_purl END) as cve_purl_medium,
			 COUNT(DISTINCT CASE WHEN a.raw_risk_assessment >= 7 AND a.raw_risk_assessment < 9 THEN a.cve_id || '|' || a.component_purl END) as cve_purl_high,
			 COUNT(DISTINCT CASE WHEN a.raw_risk_assessment >= 9 AND a.raw_risk_assessment <= 10 THEN a.cve_id || '|' || a.component_purl END) as cve_purl_critical,
			 COUNT(DISTINCT CASE WHEN d.cvss < 4 THEN a.cve_id || '|' || a.component_purl END) as cve_purl_low_cvss,
			 COUNT(DISTINCT CASE WHEN d.cvss >= 4 AND d.cvss < 7 THEN a.cve_id || '|' || a.component_purl END) as cve_purl_medium_cvss,
			 COUNT(DISTINCT CASE WHEN d.cvss >= 7 AND d.cvss < 9 THEN a.cve_id || '|' || a.component_purl END) as cve_purl_high_cvss,
			 COUNT(DISTINCT CASE WHEN d.cvss >= 9 AND d.cvss <= 10 THEN a.cve_id || '|' || a.component_purl END) as cve_purl_critical_cvss
			 FROM dependency_vulns a
			 LEFT JOIN assets b ON a.asset_id = b.id
			 LEFT JOIN projects c ON b.project_id = c.id
			 LEFT JOIN cves d ON a.cve_id = d.cve
			 WHERE c.organization_id = ?
			 AND a.state = 'open'
			 GROUP BY b.id,b.slug, c.slug
			 ORDER BY total DESC LIMIT ?;`, orgID, limit).Find(&assets).Error
	return assets, err
}

func (r *statisticsRepository) GetMostVulnerableArtifactsInOrg(ctx context.Context, tx *gorm.DB, orgID uuid.UUID, limit int) ([]dtos.VulnDistributionInStructure, error) {
	artifacts := []dtos.VulnDistributionInStructure{}
	err := r.GetDB(ctx, tx).Raw(`
	SELECT
		art.artifact_artifact_name as name,
		art.artifact_artifact_name as slug,
		art.artifact_asset_version_name as asset_version_name,
		b.slug as asset_slug,
		c.slug as project_slug,
		COUNT(*) as total,
		COUNT(*) filter (where a.raw_risk_assessment < 4) as low,
		COUNT(*) filter (where a.raw_risk_assessment >= 4 AND a.raw_risk_assessment < 7) as medium,
		COUNT(*) filter (where a.raw_risk_assessment >= 7 AND a.raw_risk_assessment < 9) as high,
		COUNT(*) filter (where a.raw_risk_assessment >= 9 AND a.raw_risk_assessment <= 10) as critical,
		COUNT(*) filter (where d.cvss < 4) as low_cvss,
		COUNT(*) filter (where d.cvss >= 4 AND d.cvss < 7) as medium_cvss,
		COUNT(*) filter (where d.cvss >= 7 AND d.cvss < 9) as high_cvss,
		COUNT(*) filter (where d.cvss >= 9 AND d.cvss <= 10) as critical_cvss,
		COUNT(DISTINCT CASE WHEN a.raw_risk_assessment < 4 THEN a.cve_id || '|' || a.component_purl END) as cve_purl_low,
		COUNT(DISTINCT CASE WHEN a.raw_risk_assessment >= 4 AND a.raw_risk_assessment < 7 THEN a.cve_id || '|' || a.component_purl END) as cve_purl_medium,
		COUNT(DISTINCT CASE WHEN a.raw_risk_assessment >= 7 AND a.raw_risk_assessment < 9 THEN a.cve_id || '|' || a.component_purl END) as cve_purl_high,
		COUNT(DISTINCT CASE WHEN a.raw_risk_assessment >= 9 AND a.raw_risk_assessment <= 10 THEN a.cve_id || '|' || a.component_purl END) as cve_purl_critical,
		COUNT(DISTINCT CASE WHEN d.cvss < 4 THEN a.cve_id || '|' || a.component_purl END) as cve_purl_low_cvss,
		COUNT(DISTINCT CASE WHEN d.cvss >= 4 AND d.cvss < 7 THEN a.cve_id || '|' || a.component_purl END) as cve_purl_medium_cvss,
		COUNT(DISTINCT CASE WHEN d.cvss >= 7 AND d.cvss < 9 THEN a.cve_id || '|' || a.component_purl END) as cve_purl_high_cvss,
		COUNT(DISTINCT CASE WHEN d.cvss >= 9 AND d.cvss <= 10 THEN a.cve_id || '|' || a.component_purl END) as cve_purl_critical_cvss
	FROM
		dependency_vulns a
	LEFT JOIN
		artifact_dependency_vulns art ON a.id = art.dependency_vuln_id
	LEFT JOIN
		assets b ON a.asset_id = b.id
	LEFT JOIN
		projects c ON b.project_id = c.id
	LEFT JOIN
		cves d ON a.cve_id = d.cve
	WHERE
		c.organization_id = ?
	AND
		a.state = 'open'
	GROUP BY
		art.artifact_artifact_name,art.artifact_asset_version_name, c.slug, b.slug
	ORDER BY
		total DESC LIMIT ?;`, orgID, limit).Find(&artifacts).Error
	return artifacts, err
}

func (r *statisticsRepository) GetMostUsedComponentsInOrg(ctx context.Context, tx *gorm.DB, orgID uuid.UUID, limit int) ([]dtos.ComponentUsageAcrossOrg, error) {
	components := []dtos.ComponentUsageAcrossOrg{}
	err := r.GetDB(ctx, tx).Raw(`
	SELECT a.dependency_id as purl, 
	COUNT(DISTINCT (a.asset_id, a.asset_version_name)) AS total_amount
	FROM component_dependencies a
	LEFT JOIN assets b ON a.asset_id = b.id
	LEFT JOIN projects c ON b.project_id = c.id
	WHERE c.organization_id = ?
	GROUP BY a.dependency_id
	ORDER BY total_amount DESC
	LIMIT ?;`, orgID, limit).Find(&components).Error
	return components, err
}

func (r *statisticsRepository) GetMostCommonCVEsInOrg(ctx context.Context, tx *gorm.DB, orgID uuid.UUID, limit int) ([]dtos.CVEOccurrencesAcrossOrg, error) {
	topCVEs := []dtos.CVEOccurrencesAcrossOrg{}
	err := r.GetDB(ctx, tx).Raw(`
	SELECT a.cve_id, 
	cves.cvss,
	COUNT(DISTINCT (a.asset_id, a.asset_version_name)) AS total_amount
	FROM dependency_vulns a
	LEFT JOIN cves ON cves.cve = a.cve_id
	LEFT JOIN assets b ON a.asset_id = b.id
	LEFT JOIN projects c ON b.project_id = c.id
	WHERE c.organization_id = ?
	GROUP BY a.cve_id, cves.cvss
	ORDER BY total_amount DESC, cvss DESC
	LIMIT ?;`, orgID, limit).Find(&topCVEs).Error
	return topCVEs, err
}

func (r *statisticsRepository) GetWeeklyAveragePerVulnEventType(ctx context.Context, tx *gorm.DB, orgID uuid.UUID) ([]dtos.VulnEventAverage, error) {
	averageByType := []dtos.VulnEventAverage{}
	err := r.GetDB(ctx, tx).Raw(`
	SELECT 
		type, AVG(count) as weekly_average
	FROM(
	SELECT
		weeks.week,
		types.type,
		COALESCE(counts.count, 0) AS count
	FROM
		(SELECT DISTINCT date_trunc('week', created_at) AS week FROM vuln_events) weeks
		CROSS JOIN (SELECT DISTINCT type FROM vuln_events) types
		LEFT JOIN (
		SELECT date_trunc('week', a.created_at) AS week, a.type, COUNT(*)
		FROM vuln_events a
		LEFT JOIN dependency_vulns b ON a.dependency_vuln_id = b.id
		LEFT JOIN assets c ON b.asset_id = c.id
		LEFT JOIN projects d ON c.project_id = d.id
		WHERE d.organization_id = ?
		GROUP BY week, a.type
		) counts USING (week, type)
	) GROUP BY type;`, orgID).Find(&averageByType).Error
	return averageByType, err
}

func (r *statisticsRepository) GetAverageAmountOfOpenCodeRisksForProjectsInOrg(ctx context.Context, tx *gorm.DB, orgID uuid.UUID) (float32, error) {
	var average float32
	err := r.GetDB(ctx, tx).Raw(`
	SELECT 
		AVG(count) 
	FROM 
		(
			SELECT 
				c.id, 
				COUNT(b.id) 
			FROM 
				assets a 
			LEFT JOIN 
				first_party_vulnerabilities b ON a.id = b.asset_id 
			LEFT JOIN 
				projects c ON a.project_id = c.id
			WHERE 
				c.organization_id = ?
			GROUP BY c.id
		);`, orgID).Find(&average).Error
	return average, err
}

func (r *statisticsRepository) GetAverageAmountOfOpenVulnsPerProjectBySeverityInOrg(ctx context.Context, tx *gorm.DB, orgID uuid.UUID) (dtos.ProjectVulnCountAverageBySeverity, error) {
	projectAverage := dtos.ProjectVulnCountAverageBySeverity{}
	err := r.GetDB(ctx, tx).Raw(`
		SELECT 
			COALESCE(AVG(sub.risk_low), 0) risk_low_average, 
			COALESCE(AVG(sub.risk_medium), 0) risk_medium_average, 
			COALESCE(AVG(sub.risk_high), 0) risk_high_average, 
			COALESCE(AVG(sub.risk_critical), 0) risk_critical_average,
			COALESCE(AVG(sub.cvss_low), 0) cvss_low_average, 
			COALESCE(AVG(sub.cvss_medium), 0) cvss_medium_average, 
			COALESCE(AVG(sub.cvss_high), 0) cvss_high_average, 
			COALESCE(AVG(sub.cvss_critical), 0) cvss_critical_average
		FROM 
			(
				SELECT 
					b.project_id,
					COUNT(*) filter (where a.raw_risk_assessment < 4) as risk_low,
					COUNT(*) filter (where a.raw_risk_assessment >= 4 AND a.raw_risk_assessment < 7) as risk_medium,
					COUNT(*) filter (where a.raw_risk_assessment >= 7 AND a.raw_risk_assessment < 9) as risk_high,
					COUNT(*) filter (where a.raw_risk_assessment >= 9 AND a.raw_risk_assessment <= 10) as risk_critical ,
					COUNT(*) filter (where d.cvss < 4) as cvss_low,
					COUNT(*) filter (where d.cvss >= 4 AND d.cvss < 7) as cvss_medium,
					COUNT(*) filter (where d.cvss >= 7 AND d.cvss < 9) as cvss_high,
					COUNT(*) filter (where d.cvss >= 9 AND d.cvss <= 10) as cvss_critical
				FROM 
					dependency_vulns a 
				LEFT JOIN 
					assets b ON a.asset_id = b.id
				LEFT JOIN 
					projects c ON b.project_id = c.id
				LEFT JOIN 
					cves d ON a.cve_id = d.cve
				WHERE 
					a.state = 'open' 
				AND 
					c.organization_id = ?
				GROUP BY b.project_id
			) as sub;`, orgID).Find(&projectAverage).Error
	return projectAverage, err
}

func (r *statisticsRepository) GetComponentDistributionInOrg(ctx context.Context, tx *gorm.DB, orgID uuid.UUID) ([]dtos.ComponentOccurrenceCount, error) {
	distribution := []dtos.ComponentOccurrenceCount{}
	err := r.GetDB(ctx, tx).Raw(`
	SELECT 
    	a.dependency_id,
    	COUNT(DISTINCT (a.asset_id, a.asset_version_name))
	FROM 
		component_dependencies a
	LEFT JOIN 
		assets b ON a.asset_id = b.id
	LEFT JOIN 
		projects c ON b.project_id = c.id
	WHERE 
		c.organization_id = ?
	GROUP BY 
		a.dependency_id
	ORDER BY 
		count DESC;`, orgID).Find(&distribution).Error
	return distribution, err
}

func (r *statisticsRepository) FindMaliciousPackagesInOrg(ctx context.Context, tx *gorm.DB, orgID uuid.UUID) ([]dtos.MaliciousPackageInOrg, error) {
	packages := []dtos.MaliciousPackageInOrg{}
	err := r.GetDB(ctx, tx).Raw(`
	SELECT 
		a.malicious_package_id,
		b.dependency_id as component,
		d.name as project_name,
		c.name as asset_name,
		b.asset_version_name
	FROM 
		malicious_affected_components a
	JOIN 
		component_dependencies b ON b.dependency_id = a.purl
	JOIN 
		assets c ON b.asset_id = c.id
	JOIN 
		projects d ON c.project_id = d.id
	WHERE 
		d.organization_id = ?`, orgID).Find(&packages).Error

	return packages, err
}

func (r *statisticsRepository) GetAverageAgeOfDependenciesAcrossOrg(ctx context.Context, tx *gorm.DB, orgID uuid.UUID) (time.Duration, error) {
	var seconds float64
	err := r.GetDB(ctx, tx).Raw(`
	SELECT 
		COALESCE(EXTRACT(EPOCH FROM (AVG(NOW() - published))),0) as seconds
	FROM (
			SELECT 
				b.id, MAX(b.published) as published
			FROM 
				component_dependencies a 
			LEFT JOIN 
				components b ON a.dependency_id = b.id
			LEFT JOIN 
				assets ON assets.id = a.asset_id
			LEFT JOIN 
				projects ON projects.id = assets.project_id
			WHERE 
				projects.organization_id = ?
			GROUP BY b.id
		);`, orgID).Find(&seconds).Error
	return time.Duration(seconds), err
}

func (r *statisticsRepository) GetAverageRemediationTimesAcrossOrg(ctx context.Context, tx *gorm.DB, orgID uuid.UUID) (dtos.AverageRemediationTimes, error) {
	averages := dtos.AverageRemediationTimes{}
	err := r.GetDB(ctx, tx).Raw(`
	WITH events AS (
    SELECT
        dependency_vulns.id,
        dependency_vulns.component_purl,
        dependency_vulns.raw_risk_assessment,
        c.cvss,
        fe.type,
        fe.created_at,
        LAG(fe.type)       OVER (PARTITION BY dependency_vulns.id ORDER BY fe.created_at) AS prev_type,
        LAG(fe.created_at) OVER (PARTITION BY dependency_vulns.id ORDER BY fe.created_at) AS prev_created_at,
        LEAD(fe.type)      OVER (PARTITION BY dependency_vulns.id ORDER BY fe.created_at) AS next_type
    FROM
        dependency_vulns
    JOIN
        vuln_events fe ON dependency_vulns.id = fe.dependency_vuln_id
    LEFT JOIN
        cves c ON dependency_vulns.cve_id = c.cve
    LEFT JOIN
        assets ON assets.id = dependency_vulns.asset_id
    LEFT JOIN
        projects ON assets.project_id = projects.id
    WHERE
        fe.type IN ?
    AND
        projects.organization_id = ?
	),
	intervals AS (
		SELECT
			id,
			component_purl,
			raw_risk_assessment,
			cvss,
			COALESCE(next_type, type) AS type,
			prev_type,
			prev_created_at,
			CASE
				WHEN next_type IS NULL AND type IN ?
					THEN NOW() - created_at
				WHEN prev_type IN ?
					THEN created_at - prev_created_at
			END AS fixing_time
		FROM
			events
		WHERE
			(next_type IS NULL AND type IN ?)
			OR
			prev_type IN ?
	)
	SELECT
		COALESCE(EXTRACT(EPOCH FROM AVG(fixing_time) FILTER (WHERE raw_risk_assessment >= 0  AND raw_risk_assessment <  4)),0)  AS low_risk_average,
		COALESCE(EXTRACT(EPOCH FROM AVG(fixing_time) FILTER (WHERE raw_risk_assessment >= 4  AND raw_risk_assessment <  7)),0)  AS medium_risk_average,
		COALESCE(EXTRACT(EPOCH FROM AVG(fixing_time) FILTER (WHERE raw_risk_assessment >= 7  AND raw_risk_assessment <  9)),0)  AS high_risk_average,
		COALESCE(EXTRACT(EPOCH FROM AVG(fixing_time) FILTER (WHERE raw_risk_assessment >= 9  AND raw_risk_assessment <= 10)),0) AS critical_risk_average,

		COALESCE(EXTRACT(EPOCH FROM AVG(fixing_time) FILTER (WHERE cvss >= 0  AND cvss <  4)),0)  AS low_cvss_average,
		COALESCE(EXTRACT(EPOCH FROM AVG(fixing_time) FILTER (WHERE cvss >= 4  AND cvss <  7)),0)  AS medium_cvss_average,
		COALESCE(EXTRACT(EPOCH FROM AVG(fixing_time) FILTER (WHERE cvss >= 7  AND cvss <  9)),0)  AS high_cvss_average,
		COALESCE(EXTRACT(EPOCH FROM AVG(fixing_time) FILTER (WHERE cvss >= 9  AND cvss <= 10)),0) AS critical_cvss_average
	FROM
		intervals;`, append(fixedEvents, openEvents...), orgID, openEvents, openEvents, openEvents, openEvents).Find(&averages).Error
	return averages, err
}

func (r *statisticsRepository) GetRemediationTypeDistributionAcrossOrg(ctx context.Context, tx *gorm.DB, orgID uuid.UUID) ([]dtos.RemediationTypeDistributionRow, error) {
	rows := []dtos.RemediationTypeDistributionRow{}
	err := r.GetDB(ctx, tx).Raw(`
	SELECT 
		a.type, 
		COUNT(*) * 100.0 / SUM(COUNT(*)) OVER() as percentage
	FROM 
		vuln_events a
	LEFT JOIN 
		dependency_vulns b ON a.dependency_vuln_id = b.id
	LEFT JOIN 
		assets ON b.asset_id = assets.id
	LEFT JOIN 
		projects ON projects.id = assets.project_id
	WHERE 
		projects.organization_id = ?
	AND 
		a.type IN ?
	GROUP BY a.type;`, orgID, fixedEvents).Find(&rows).Error
	return rows, err
}
