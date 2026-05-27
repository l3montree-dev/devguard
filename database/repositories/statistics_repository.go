package repositories

import (
	"context"
	"fmt"
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
	} else if artifactName != nil && assetVersionName == nil {
		err = r.GetDB(ctx, tx).Model(&models.DependencyVuln{}).Select("dependency_vulns.*").Preload("CVE").Preload("Events", func(db *gorm.DB) *gorm.DB {
			return db.Where("created_at <= ?", time).Order("created_at ASC")
		}).
			Joins("JOIN artifact_dependency_vulns adv ON adv.dependency_vuln_id = dependency_vulns.id").Where("adv.artifact_asset_id = ?", assetID).Where("adv.artifact_artifact_name = ?", *artifactName).Where("created_at <= ?", time).
			Find(&dependencyVulns).Error
	} else if artifactName == nil && assetVersionName != nil {
		err = r.GetDB(ctx, tx).Model(&models.DependencyVuln{}).Select("dependency_vulns.*").Preload("CVE").Preload("Events", func(db *gorm.DB) *gorm.DB {
			return db.Where("created_at <= ?", time).Order("created_at ASC")
		}).
			Joins("JOIN artifact_dependency_vulns adv ON adv.dependency_vuln_id = dependency_vulns.id").Where("adv.artifact_asset_id = ?", assetID).Where("adv.artifact_asset_version_name = ?", *assetVersionName).Where("created_at <= ?", time).
			Find(&dependencyVulns).Error
	} else {
		// both defined
		err = r.GetDB(ctx, tx).Model(&models.DependencyVuln{}).Select("dependency_vulns.*").Preload("CVE").Preload("Events", func(db *gorm.DB) *gorm.DB {
			return db.Where("created_at <= ?", time).Order("created_at ASC")
		}).
			Joins("JOIN artifact_dependency_vulns adv ON adv.dependency_vuln_id = dependency_vulns.id").
			Where("adv.artifact_asset_id = ?", assetID).
			Where("adv.artifact_asset_version_name = ?", *assetVersionName).Where("adv.artifact_artifact_name = ?", *artifactName).Where("created_at <= ?", time).
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

var remediationEvents = []dtos.VulnEventType{
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
WHERE type IN ? AND prev_type IN ?;`, append(remediationEvents, openEvents...), assetVersionName, assetID, remediationEvents, openEvents).Find(&results).Error
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
WHERE type IN ? AND prev_type IN ?;`, artifactName, append(remediationEvents, openEvents...), assetVersionName, assetID, remediationEvents, openEvents).Find(&results).Error
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
WHERE type IN ? AND prev_type IN ?;`, releaseID, append(remediationEvents, openEvents...), remediationEvents, openEvents).Find(&results).Error
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

// queries the amount of open vulnerabilities in each severity class (count each component_purl + cve_id once -> take the highest risk score)
func (r *statisticsRepository) VulnClassificationByOrg(ctx context.Context, tx *gorm.DB, orgID uuid.UUID) (dtos.VulnSeverityDistribution, error) {
	distribution := dtos.VulnSeverityDistribution{}
	err := r.GetDB(ctx, tx).Raw(`
	SELECT 
		COUNT(*) FILTER (WHERE sub.raw_risk_assessment < 4) AS low_risk,
		COUNT(*) FILTER (WHERE sub.raw_risk_assessment >= 4 AND sub.raw_risk_assessment < 7) AS medium_risk,
		COUNT(*) FILTER (WHERE sub.raw_risk_assessment >= 7 AND sub.raw_risk_assessment < 9) AS high_risk,
		COUNT(*) FILTER (WHERE sub.raw_risk_assessment >= 9 AND sub.raw_risk_assessment <= 10) AS critical_risk,
		COUNT(*) FILTER (WHERE sub.cvss < 4) AS low_cvss,
		COUNT(*) FILTER (WHERE sub.cvss >= 4 AND sub.cvss < 7) AS medium_cvss,
		COUNT(*) FILTER (WHERE sub.cvss >= 7 AND sub.cvss < 9) AS high_cvss,
		COUNT(*) FILTER (WHERE sub.cvss >= 9 AND sub.cvss <= 10) AS critical_cvss
	FROM (
		SELECT DISTINCT ON (dv.component_purl, dv.cve_id)
			dv.raw_risk_assessment, cves.cvss
		FROM dependency_vulns dv
		JOIN cves ON cves.cve = dv.cve_id
		JOIN assets a ON dv.asset_id = a.id
		JOIN projects p ON a.project_id = p.id
		WHERE p.organization_id = ?
		AND dv.state = 'open'
		ORDER BY dv.component_purl, dv.cve_id, dv.raw_risk_assessment DESC
	) sub;`, orgID).Find(&distribution).Error
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

func (r *statisticsRepository) GetMostVulnerableProjectsInOrg(ctx context.Context, tx *gorm.DB, orgID uuid.UUID, limit int) ([]dtos.ProjectVulnDistribution, error) {
	projects := []dtos.ProjectVulnDistribution{}
	err := r.GetDB(ctx, tx).Raw(`
	SELECT sub.pslug, sub.pname,
		COUNT(*) as total,
		COUNT(*) FILTER (WHERE sub.raw_risk_assessment < 4) AS low_risk,
		COUNT(*) FILTER (WHERE sub.raw_risk_assessment >= 4 AND sub.raw_risk_assessment < 7) AS medium_risk,
		COUNT(*) FILTER (WHERE sub.raw_risk_assessment >= 7 AND sub.raw_risk_assessment < 9) AS high_risk,
		COUNT(*) FILTER (WHERE sub.raw_risk_assessment >= 9 AND sub.raw_risk_assessment <= 10) AS critical_risk,
		COUNT(*) FILTER (WHERE sub.cvss < 4) AS low_cvss,
		COUNT(*) FILTER (WHERE sub.cvss >= 4 AND sub.cvss < 7) AS medium_cvss,
		COUNT(*) FILTER (WHERE sub.cvss >= 7 AND sub.cvss < 9) AS high_cvss,
		COUNT(*) FILTER (WHERE sub.cvss >= 9 AND sub.cvss <= 10) AS critical_cvss
	FROM (
		SELECT DISTINCT ON (dv.component_purl, dv.cve_id, p.id)
			dv.raw_risk_assessment, cves.cvss, p.id as pid, p.name as pname, p.slug as pslug
		FROM dependency_vulns dv
		JOIN cves ON cves.cve = dv.cve_id
		JOIN assets a ON dv.asset_id = a.id
		JOIN projects p ON a.project_id = p.id
		WHERE p.organization_id = ?
		AND dv.state = 'open'
		ORDER BY p.id, dv.component_purl, dv.cve_id, dv.raw_risk_assessment DESC
	) sub
	GROUP BY sub.pid, sub.pslug,sub.pname
	ORDER BY total DESC
	LIMIT ?;`, orgID, limit).Find(&projects).Error
	return projects, err
}

func (r *statisticsRepository) GetMostVulnerableAssetsInOrg(ctx context.Context, tx *gorm.DB, orgID uuid.UUID, limit int) ([]dtos.AssetVulnDistribution, error) {
	assets := []dtos.AssetVulnDistribution{}
	err := r.GetDB(ctx, tx).Raw(`
	SELECT sub.aslug, sub.aname,
		COUNT(*) as total,
		COUNT(*) FILTER (WHERE sub.raw_risk_assessment < 4) AS low_risk,
		COUNT(*) FILTER (WHERE sub.raw_risk_assessment >= 4 AND sub.raw_risk_assessment < 7) AS medium_risk,
		COUNT(*) FILTER (WHERE sub.raw_risk_assessment >= 7 AND sub.raw_risk_assessment < 9) AS high_risk,
		COUNT(*) FILTER (WHERE sub.raw_risk_assessment >= 9 AND sub.raw_risk_assessment <= 10) AS critical_risk,
		COUNT(*) FILTER (WHERE sub.cvss < 4) AS low_cvss,
		COUNT(*) FILTER (WHERE sub.cvss >= 4 AND sub.cvss < 7) AS medium_cvss,
		COUNT(*) FILTER (WHERE sub.cvss >= 7 AND sub.cvss < 9) AS high_cvss,
		COUNT(*) FILTER (WHERE sub.cvss >= 9 AND sub.cvss <= 10) AS critical_cvss
	FROM (
		SELECT DISTINCT ON (dv.component_purl, dv.cve_id, a.id)
			dv.raw_risk_assessment, cves.cvss, a.id as aid, a.name as aname, a.slug as aslug
		FROM dependency_vulns dv
		JOIN cves ON cves.cve = dv.cve_id
		JOIN assets a ON dv.asset_id = a.id
		JOIN projects p ON a.project_id = p.id
		WHERE p.organization_id = ?
		AND dv.state = 'open'
		ORDER BY a.id, dv.component_purl, dv.cve_id, dv.raw_risk_assessment DESC
	) sub
	GROUP BY sub.aid, sub.aslug,sub.aname
	ORDER BY total DESC
	LIMIT ?;`, orgID, limit).Find(&assets).Error
	return assets, err
}

func (r *statisticsRepository) GetMostVulnerableArtifactsInOrg(ctx context.Context, tx *gorm.DB, orgID uuid.UUID, limit int) ([]dtos.ArtifactVulnDistribution, error) {
	artifacts := []dtos.ArtifactVulnDistribution{}
	err := r.GetDB(ctx, tx).Raw(`
	SELECT
		sub.artifact_name AS name,
		sub.project_slug,
		sub.asset_slug,
		sub.version_name AS asset_version_name,
		COUNT(*) AS total,
		COUNT(*) FILTER (WHERE sub.raw_risk_assessment < 4) AS low_risk,
		COUNT(*) FILTER (WHERE sub.raw_risk_assessment >= 4 AND sub.raw_risk_assessment < 7) AS medium_risk,
		COUNT(*) FILTER (WHERE sub.raw_risk_assessment >= 7 AND sub.raw_risk_assessment < 9) AS high_risk,
		COUNT(*) FILTER (WHERE sub.raw_risk_assessment >= 9 AND sub.raw_risk_assessment <= 10) AS critical_risk,
		COUNT(*) FILTER (WHERE sub.cvss < 4) AS low_cvss,
		COUNT(*) FILTER (WHERE sub.cvss >= 4 AND sub.cvss < 7) AS medium_cvss,
		COUNT(*) FILTER (WHERE sub.cvss >= 7 AND sub.cvss < 9) AS high_cvss,
		COUNT(*) FILTER (WHERE sub.cvss >= 9 AND sub.cvss <= 10) AS critical_cvss
	FROM (
		SELECT DISTINCT ON (adv.artifact_asset_id, adv.artifact_asset_version_name, adv.artifact_artifact_name, dv.component_purl, dv.cve_id)
			dv.raw_risk_assessment, cves.cvss,
			adv.artifact_artifact_name AS artifact_name,
			adv.artifact_asset_version_name AS version_name,
			p.slug AS project_slug,
			a.slug AS asset_slug
		FROM dependency_vulns dv
		JOIN cves ON cves.cve = dv.cve_id
		JOIN assets a ON dv.asset_id = a.id
		JOIN projects p ON a.project_id = p.id
		JOIN artifact_dependency_vulns adv ON adv.dependency_vuln_id = dv.id
		WHERE p.organization_id = ?
		AND dv.state = 'open'
		ORDER BY adv.artifact_asset_id, adv.artifact_asset_version_name, adv.artifact_artifact_name, dv.component_purl, dv.cve_id, dv.raw_risk_assessment DESC
	) sub
	GROUP BY sub.artifact_name, sub.version_name, sub.project_slug, sub.asset_slug
	ORDER BY total DESC
	LIMIT ?;`, orgID, limit).Find(&artifacts).Error
	return artifacts, err
}

func (r *statisticsRepository) GetMostUsedComponentsInOrg(ctx context.Context, tx *gorm.DB, orgID uuid.UUID, limit int) ([]dtos.ComponentUsageAcrossOrg, error) {
	components := []dtos.ComponentUsageAcrossOrg{}
	err := r.GetDB(ctx, tx).Raw(`
	SELECT a.dependency_id as purl, 
	COUNT(DISTINCT (a.asset_id)) AS total_amount
	FROM component_dependencies a
	JOIN assets b ON a.asset_id = b.id
	JOIN projects c ON b.project_id = c.id
	WHERE c.organization_id = ?
	GROUP BY a.dependency_id
	ORDER BY total_amount DESC, a.dependency_id ASC
	LIMIT ?;`, orgID, limit).Find(&components).Error
	return components, err
}

func (r *statisticsRepository) GetMostCommonCVEsInOrg(ctx context.Context, tx *gorm.DB, orgID uuid.UUID, limit int) ([]dtos.CVEOccurrencesAcrossOrg, error) {
	topCVEs := []dtos.CVEOccurrencesAcrossOrg{}
	err := r.GetDB(ctx, tx).Raw(`
	SELECT a.cve_id, 
	MAX(cves.cvss) as cvss,
	COUNT(DISTINCT (a.asset_id)) AS total_amount
	FROM dependency_vulns a
	JOIN cves ON cves.cve = a.cve_id
	JOIN assets b ON a.asset_id = b.id
	JOIN projects c ON b.project_id = c.id
	WHERE c.organization_id = ?
	GROUP BY a.cve_id
	ORDER BY total_amount DESC, cvss DESC
	LIMIT ?;`, orgID, limit).Find(&topCVEs).Error
	return topCVEs, err
}

// calculate the average amount of remediation events per week since the org was created (or 1 if younger than 1 week)
func (r *statisticsRepository) GetWeeklyAveragePerVulnEventType(ctx context.Context, tx *gorm.DB, orgID uuid.UUID) ([]dtos.VulnEventAverage, error) {
	averageByType := []dtos.VulnEventAverage{}
	err := r.GetDB(ctx, tx).Raw(`
	WITH org_weeks AS ( -- calculate the created at of the org once at the start
		SELECT GREATEST(EXTRACT(EPOCH FROM (NOW() - created_at)) / 604800, 1) AS weeks -- calculate all weeks since creation (or 1 if less than 1 week)
		FROM organizations
		WHERE id = ?
	)
	SELECT ve.type,
		COUNT(*)::float / ow.weeks AS average
	FROM org_weeks ow
	CROSS JOIN organizations org
	JOIN projects p ON p.organization_id = org.id
	JOIN assets a ON a.project_id = p.id
	JOIN dependency_vulns dv ON dv.asset_id = a.id
	JOIN vuln_events ve ON ve.dependency_vuln_id = dv.id
	WHERE org.id = ?
	AND ve.type IN ?
	GROUP BY ve.type, ow.weeks;`, orgID, orgID, remediationEvents).Find(&averageByType).Error
	return averageByType, err
}

func (r *statisticsRepository) GetAverageAmountOfOpenCodeRisksForProjectsInOrg(ctx context.Context, tx *gorm.DB, orgID uuid.UUID) (float32, error) {
	var average float32
	err := r.GetDB(ctx, tx).Raw(`
	SELECT
		COALESCE(AVG(count), 0)
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

// returns the relative and absolute amount of components per ecosystem inside an org
func (r *statisticsRepository) GetEcosystemDistributionInOrg(ctx context.Context, tx *gorm.DB, orgID uuid.UUID) ([]dtos.EcosystemUsage, error) {
	distribution := []dtos.EcosystemUsage{}
	err := r.GetDB(ctx, tx).Raw(`
	SELECT ecosystem, COUNT(*) as absolute, COUNT(*) * 100.0 / SUM(COUNT(*)) OVER () as percentage
	FROM (
		SELECT split_part(split_part(cd.dependency_id, ':', 2), '/', 1) AS ecosystem 	-- extract the ecosystem from the pURL
		FROM component_dependencies cd
		JOIN assets a ON cd.asset_id = a.id
		JOIN projects p ON a.project_id = p.id
		WHERE p.organization_id = ?
		AND cd.dependency_id LIKE 'pkg:%'	-- pre filter only for valid purls
	) sub
	WHERE ecosystem ~ '^[a-z][a-z0-9+-\.]+$' 	-- lastly filter out any invalid ecosystems (using the official regex)
	GROUP BY ecosystem
	ORDER BY count(*) DESC;`, orgID).Find(&distribution).Error
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
	SELECT COALESCE(EXTRACT(EPOCH FROM AVG(NOW() - published)), 0)
	FROM components JOIN (
		SELECT DISTINCT cd.dependency_id FROM projects p
		JOIN assets a ON a.project_id = p.id
		JOIN component_dependencies cd ON cd.asset_id = a.id
		WHERE p.organization_id = ?) as dep
	ON dep.dependency_id = components.id;`, orgID).Find(&seconds).Error
	return time.Duration(seconds), err
}

// calculate the average time between the time the vuln was created and the first remediation event
// also count all the not handled vulns
func (r *statisticsRepository) GetAverageRemediationTimesAcrossOrg(ctx context.Context, tx *gorm.DB, orgID uuid.UUID) (dtos.AverageRemediationTimes, error) {
	averages := dtos.AverageRemediationTimes{}
	err := r.GetDB(ctx, tx).Raw(`
	SELECT
		-- remediated averages
		COALESCE(EXTRACT(EPOCH FROM AVG(sub.created_at - dv.created_at) FILTER (WHERE sub.created_at IS NOT NULL AND dv.raw_risk_assessment < 4)), 0) AS low_risk_remediated,
		COALESCE(EXTRACT(EPOCH FROM AVG(sub.created_at - dv.created_at) FILTER (WHERE sub.created_at IS NOT NULL AND dv.raw_risk_assessment >= 4 AND dv.raw_risk_assessment < 7)), 0) AS medium_risk_remediated,
		COALESCE(EXTRACT(EPOCH FROM AVG(sub.created_at - dv.created_at) FILTER (WHERE sub.created_at IS NOT NULL AND dv.raw_risk_assessment >= 7 AND dv.raw_risk_assessment < 9)), 0) AS high_risk_remediated,
		COALESCE(EXTRACT(EPOCH FROM AVG(sub.created_at - dv.created_at) FILTER (WHERE sub.created_at IS NOT NULL AND dv.raw_risk_assessment >= 9 AND dv.raw_risk_assessment <= 10)), 0) AS critical_risk_remediated,
		COALESCE(EXTRACT(EPOCH FROM AVG(sub.created_at - dv.created_at) FILTER (WHERE sub.created_at IS NOT NULL AND dv.cvss < 4)), 0) AS low_cvss_remediated,
		COALESCE(EXTRACT(EPOCH FROM AVG(sub.created_at - dv.created_at) FILTER (WHERE sub.created_at IS NOT NULL AND dv.cvss >= 4 AND dv.cvss < 7)), 0) AS medium_cvss_remediated,
		COALESCE(EXTRACT(EPOCH FROM AVG(sub.created_at - dv.created_at) FILTER (WHERE sub.created_at IS NOT NULL AND dv.cvss >= 7 AND dv.cvss < 9)), 0) AS high_cvss_remediated,
		COALESCE(EXTRACT(EPOCH FROM AVG(sub.created_at - dv.created_at) FILTER (WHERE sub.created_at IS NOT NULL AND dv.cvss >= 9 AND dv.cvss <= 10)), 0) AS critical_cvss_remediated,
		-- non-remediated averages
		COALESCE(EXTRACT(EPOCH FROM AVG(now() - dv.created_at) FILTER (WHERE sub.created_at IS NULL AND dv.raw_risk_assessment < 4)), 0) AS low_risk_open,
		COALESCE(EXTRACT(EPOCH FROM AVG(now() - dv.created_at) FILTER (WHERE sub.created_at IS NULL AND dv.raw_risk_assessment >= 4 AND dv.raw_risk_assessment < 7)), 0) AS medium_risk_open,
		COALESCE(EXTRACT(EPOCH FROM AVG(now() - dv.created_at) FILTER (WHERE sub.created_at IS NULL AND dv.raw_risk_assessment >= 7 AND dv.raw_risk_assessment < 9)), 0) AS high_risk_open,
		COALESCE(EXTRACT(EPOCH FROM AVG(now() - dv.created_at) FILTER (WHERE sub.created_at IS NULL AND dv.raw_risk_assessment >= 9 AND dv.raw_risk_assessment <= 10)), 0) AS critical_risk_open,
		COALESCE(EXTRACT(EPOCH FROM AVG(now() - dv.created_at) FILTER (WHERE sub.created_at IS NULL AND dv.cvss < 4)), 0) AS low_cvss_open,
		COALESCE(EXTRACT(EPOCH FROM AVG(now() - dv.created_at) FILTER (WHERE sub.created_at IS NULL AND dv.cvss >= 4 AND dv.cvss < 7)), 0) AS medium_cvss_open,
		COALESCE(EXTRACT(EPOCH FROM AVG(now() - dv.created_at) FILTER (WHERE sub.created_at IS NULL AND dv.cvss >= 7 AND dv.cvss < 9)), 0) AS high_cvss_open,
		COALESCE(EXTRACT(EPOCH FROM AVG(now() - dv.created_at) FILTER (WHERE sub.created_at IS NULL AND dv.cvss >= 9 AND dv.cvss <= 10)), 0) AS critical_cvss_open
	FROM (
		SELECT DISTINCT ON (dv.cve_id, dv.component_purl)			--deduplicate based on cve_id and purl
			dv.id, dv.created_at, dv.raw_risk_assessment, cves.cvss
		FROM dependency_vulns dv
		JOIN assets a ON dv.asset_id = a.id
		JOIN projects p ON a.project_id = p.id
		LEFT JOIN cves ON cves.cve = dv.cve_id
		WHERE p.organization_id = ?
		ORDER BY dv.cve_id, dv.component_purl, dv.created_at ASC   	--ORDER for deterministic distinct
	) dv
	LEFT JOIN LATERAL (
		SELECT created_at
		FROM vuln_events ve
		WHERE ve.dependency_vuln_id = dv.id
		AND ve.type IN ?
		ORDER BY created_at ASC			--only get the earliest remediation event
		LIMIT 1
	) sub ON TRUE;`, orgID, remediationEvents).Find(&averages).Error
	return averages, err
}

// calculate the distribution of how dependency vulns are handled inside an org
// to achieve this, the query uses the latest (remediation) event per vuln
func (r *statisticsRepository) GetRemediationTypeDistributionAcrossOrg(ctx context.Context, tx *gorm.DB, orgID uuid.UUID) ([]dtos.RemediationTypeDistributionRow, error) {
	rows := []dtos.RemediationTypeDistributionRow{}
	err := r.GetDB(ctx, tx).Raw(`
	SELECT ve_filtered.type, 
	COUNT(*) * 100.0 / SUM(COUNT(*)) OVER() AS percentage
	FROM projects p
	JOIN assets a ON a.project_id = p.id
	JOIN dependency_vulns dv ON dv.asset_id = a.id
	JOIN LATERAL( 						-- lateral join the latest vuln event to each dependency vuln present in the org
		SELECT ve.type FROM vuln_events ve 
		WHERE ve.type IN ?
		AND ve.dependency_vuln_id = dv.id 
		ORDER BY ve.created_at DESC  	-- order by created_at + limit 1 to only get the latest
		LIMIT 1) as ve_filtered ON TRUE
	WHERE p.organization_id = ?
	GROUP BY ve_filtered.type;`, remediationEvents, orgID).Find(&rows).Error
	return rows, err
}

func (r *statisticsRepository) GetInstanceUsageStatistics(ctx context.Context, tx *gorm.DB) (dtos.InstanceUsageStatistics, error) {
	var instanceStatistics dtos.InstanceUsageStatistics
	var err error

	err = r.GetDB(ctx, tx).Raw(`
    SELECT
        (SELECT COUNT(*) FROM public.organizations) AS number_of_organizations,
        (SELECT COUNT(*) FROM public.projects
            WHERE EXISTS (SELECT FROM assets WHERE assets.project_id = projects.id)) AS number_of_projects,
        (SELECT COUNT(*) FROM public.asset_versions) AS number_of_asset_versions,
        (SELECT COUNT(*) FROM public.projects
            WHERE external_entity_id IS NOT NULL
            AND external_entity_provider_id IN ('gitlab','opencode')) AS number_of_projects_with_gitlab_integration
	`).First(&instanceStatistics).Error
	if err != nil {
		return instanceStatistics, fmt.Errorf("could not fetch instance usage statistics: %w", err)
	}

	instanceStatistics.NumberOfTicketSyncedProjects = instanceStatistics.NumberOfProjectsWithGitlabIntegration // not yet clear what that statistic should represent

	return instanceStatistics, nil
}
