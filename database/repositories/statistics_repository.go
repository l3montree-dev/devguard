package repositories

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
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

// returns all dependencyVulns for the asset including the events, which were created before the given time
func (r *statisticsRepository) TimeTravelDependencyVulnState(artifactName *string, assetVersionName *string, assetID uuid.UUID, time time.Time) ([]models.DependencyVuln, error) {
	dependencyVulns := []models.DependencyVuln{}
	var err error
	if artifactName == nil && assetVersionName == nil {
		err = r.db.Model(&models.DependencyVuln{}).Preload("CVE").Preload("Events", func(db *gorm.DB) *gorm.DB {
			return db.Where("created_at <= ?", time).Order("created_at ASC")
		}).
			Joins("JOIN artifact_dependency_vulns adv ON adv.dependency_vuln_id = dependency_vulns.id").
			Where("dependency_vulns.asset_id = ?", assetID).Where("created_at <= ?", time).
			Find(&dependencyVulns).Error
	} else if artifactName != nil {
		err = r.db.Model(&models.DependencyVuln{}).Preload("CVE").Preload("Events", func(db *gorm.DB) *gorm.DB {
			return db.Where("created_at <= ?", time).Order("created_at ASC")
		}).
			Joins("JOIN artifact_dependency_vulns adv ON adv.dependency_vuln_id = dependency_vulns.id").
			Where("adv.artifact_asset_version_name = ?", *assetVersionName).Where("adv.artifact_asset_id = ?", assetID).Where("adv.artifact_artifact_name = ?", artifactName).Where("created_at <= ?", time).
			Find(&dependencyVulns).Error
	} else {
		err = r.db.Model(&models.DependencyVuln{}).Preload("CVE").Preload("Events", func(db *gorm.DB) *gorm.DB {
			return db.Where("created_at <= ?", time).Order("created_at ASC")
		}).Where("adv.artifact_asset_id = ?", assetID).Where("adv.artifact_artifact_name = ?", artifactName).Where("created_at <= ?", time).
			Find(&dependencyVulns).Error
	}
	if err != nil {
		return nil, err
	}

	// now remove all events of the dependencyVulns, which were created after the given time
	for _, dependencyVuln := range dependencyVulns {
		// get the last event of the dependencyVuln based on the created_at timestamp.
		tmpDependencyVuln := dependencyVuln

		events := dependencyVuln.Events
		// iterate through all events and apply them
		for _, event := range events {
			statemachine.Apply(&tmpDependencyVuln, event)
		}
	}
	return dependencyVulns, nil
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

func (r *statisticsRepository) AverageFixingTime(artifactName *string, assetVersionName string, assetID uuid.UUID, riskIntervalStart, riskIntervalEnd float64) (time.Duration, error) {
	var results []struct {
		AvgFixingTime string `gorm:"column:avg"`
	}

	var err error

	if artifactName == nil {
		err = r.db.Raw(`
WITH events AS (
    SELECT
        dependency_vulns.id,
        dependency_vulns.component_purl,
        fe.type,
        fe.created_at,
        LAG(fe.type) OVER (PARTITION BY dependency_vulns.id ORDER BY fe.created_at) AS prev_type,
        LAG(fe.created_at) OVER (PARTITION BY dependency_vulns.id ORDER BY fe.created_at) AS prev_created_at,
        LEAD(fe.type) OVER (PARTITION BY dependency_vulns.id ORDER BY fe.created_at) AS next_type
    FROM
        dependency_vulns
    JOIN
        vuln_events fe ON dependency_vulns.id = fe.vuln_id
	JOIN artifact_dependency_vulns adv ON dependency_vulns.id = adv.dependency_vuln_id
    WHERE
        fe.type IN ? AND dependency_vulns.asset_version_name = ? AND dependency_vulns.asset_id = ? AND dependency_vulns.raw_risk_assessment >= ? AND dependency_vulns.raw_risk_assessment < ?
),
intervals AS (
   SELECT
        id,
        component_purl,
        COALESCE(next_type, type) AS type,
        prev_type,
        prev_created_at,
        CASE
            WHEN next_type IS NULL THEN NOW() - prev_created_at
            ELSE created_at - prev_created_at
        END AS fixing_time
    FROM
        events
    WHERE
        prev_type IN ? 
)
SELECT
   EXTRACT(EPOCH FROM AVG(fixing_time)) AS avg
FROM
    intervals`, append(fixedEvents, openEvents...), assetVersionName, assetID, riskIntervalStart, riskIntervalEnd, openEvents).Find(&results).Error
	} else {
		err = r.db.Raw(`
WITH events AS (
    SELECT
        dependency_vulns.id,
        dependency_vulns.component_purl,
        fe.type,
        fe.created_at,
        LAG(fe.type) OVER (PARTITION BY dependency_vulns.id ORDER BY fe.created_at) AS prev_type,
        LAG(fe.created_at) OVER (PARTITION BY dependency_vulns.id ORDER BY fe.created_at) AS prev_created_at,
        LEAD(fe.type) OVER (PARTITION BY dependency_vulns.id ORDER BY fe.created_at) AS next_type
    FROM
        dependency_vulns
    JOIN
        vuln_events fe ON dependency_vulns.id = fe.vuln_id
	JOIN artifact_dependency_vulns adv ON dependency_vulns.id = adv.dependency_vuln_id
    WHERE
        fe.type IN ? AND adv.artifact_artifact_name = ? AND dependency_vulns.asset_version_name = ? AND dependency_vulns.asset_id = ? AND dependency_vulns.raw_risk_assessment >= ? AND dependency_vulns.raw_risk_assessment < ?
),
intervals AS (
   SELECT
        id,
        component_purl,
        COALESCE(next_type, type) AS type,
        prev_type,
        prev_created_at,
        CASE
            WHEN next_type IS NULL THEN NOW() - prev_created_at
            ELSE created_at - prev_created_at
        END AS fixing_time
    FROM
        events
    WHERE
        prev_type IN ? 
)
SELECT
   EXTRACT(EPOCH FROM AVG(fixing_time)) AS avg
FROM
    intervals`, append(fixedEvents, openEvents...), artifactName, assetVersionName, assetID, riskIntervalStart, riskIntervalEnd, openEvents).Find(&results).Error
	}

	if err != nil {
		return 0, err
	}

	if len(results) == 0 {
		return 0, nil
	}

	fixingTimeStr := results[0].AvgFixingTime
	if fixingTimeStr == "" {
		return 0, nil
	}
	// parse it to float
	fixingTime, err := time.ParseDuration(fixingTimeStr + "s")
	if err != nil {
		return 0, err
	}

	return fixingTime, nil
}

func (r *statisticsRepository) AverageFixingTimeForRelease(releaseID uuid.UUID, riskIntervalStart, riskIntervalEnd float64) (time.Duration, error) {
	var results []struct {
		AvgFixingTime string `gorm:"column:avg"`
	}

	// This query mirrors AverageFixingTime but limits dependency_vulns to those matching artifacts
	// that are part of the release tree (release_items), using a recursive CTE to collect child releases.
	err := r.db.Raw(`
WITH RECURSIVE release_tree AS (
	SELECT id FROM releases WHERE id = ?
	UNION ALL
	SELECT ri.child_release_id FROM release_items ri JOIN release_tree rt ON ri.release_id = rt.id WHERE ri.child_release_id IS NOT NULL
),
events AS (
	SELECT
		dv.id,
		dv.component_purl,
		fe.type,
		fe.created_at,
		LAG(fe.type) OVER (PARTITION BY dv.id ORDER BY fe.created_at) AS prev_type,
		LAG(fe.created_at) OVER (PARTITION BY dv.id ORDER BY fe.created_at) AS prev_created_at,
		LEAD(fe.type) OVER (PARTITION BY dv.id ORDER BY fe.created_at) AS next_type
	FROM dependency_vulns dv
	JOIN vuln_events fe ON dv.id = fe.vuln_id
	JOIN release_items ri ON dv.asset_version_name = ri.asset_version_name AND dv.asset_id = ri.asset_id
	WHERE ri.release_id IN (SELECT id FROM release_tree) AND fe.type IN ? AND dv.raw_risk_assessment >= ? AND dv.raw_risk_assessment < ?
),
intervals AS (
   SELECT
		id,
		component_purl,
		COALESCE(next_type, type) AS type,
		prev_type,
		prev_created_at,
		CASE
			WHEN next_type IS NULL THEN NOW() - prev_created_at
			ELSE created_at - prev_created_at
		END AS fixing_time
	FROM
		events
	WHERE
		prev_type IN ?
)
SELECT
   EXTRACT(EPOCH FROM AVG(fixing_time)) AS avg
FROM
	intervals`, releaseID, append(fixedEvents, openEvents...), riskIntervalStart, riskIntervalEnd, openEvents).Find(&results).Error
	if err != nil {
		return 0, err
	}

	if len(results) == 0 {
		return 0, nil
	}

	fixingTimeStr := results[0].AvgFixingTime
	if fixingTimeStr == "" {
		return 0, nil
	}
	fixingTime, err := time.ParseDuration(fixingTimeStr + "s")
	if err != nil {
		return 0, err
	}

	return fixingTime, nil
}

func (r *statisticsRepository) AverageFixingTimeByCvss(artifactName *string, assetVersionName string, assetID uuid.UUID, cvssIntervalStart, cvssIntervalEnd float64) (time.Duration, error) {
	var results []struct {
		AvgFixingTime string `gorm:"column:avg"`
	}

	var err error

	if artifactName == nil {
		err = r.db.Raw(`
WITH events AS (
    SELECT
        dependency_vulns.id,
        dependency_vulns.component_purl,
        fe.type,
        fe.created_at,
        LAG(fe.type) OVER (PARTITION BY dependency_vulns.id ORDER BY fe.created_at) AS prev_type,
        LAG(fe.created_at) OVER (PARTITION BY dependency_vulns.id ORDER BY fe.created_at) AS prev_created_at,
        LEAD(fe.type) OVER (PARTITION BY dependency_vulns.id ORDER BY fe.created_at) AS next_type
    FROM
        dependency_vulns
    JOIN
        vuln_events fe ON dependency_vulns.id = fe.vuln_id
	JOIN artifact_dependency_vulns adv ON dependency_vulns.id = adv.dependency_vuln_id
	JOIN cves c ON dependency_vulns.cve_id = c.cve
    WHERE
        fe.type IN ? AND dependency_vulns.asset_version_name = ? AND dependency_vulns.asset_id = ? AND c.cvss >= ? AND c.cvss < ?
),
intervals AS (
   SELECT
        id,
        component_purl,
        COALESCE(next_type, type) AS type,
        prev_type,
        prev_created_at,
        CASE
            WHEN next_type IS NULL THEN NOW() - prev_created_at
            ELSE created_at - prev_created_at
        END AS fixing_time
    FROM
        events
    WHERE
        prev_type IN ? 
)
SELECT
   EXTRACT(EPOCH FROM AVG(fixing_time)) AS avg
FROM
    intervals`, append(fixedEvents, openEvents...), assetVersionName, assetID, cvssIntervalStart, cvssIntervalEnd, openEvents).Find(&results).Error
	} else {
		err = r.db.Raw(`
WITH events AS (
    SELECT
        dependency_vulns.id,
        dependency_vulns.component_purl,
        fe.type,
        fe.created_at,
        LAG(fe.type) OVER (PARTITION BY dependency_vulns.id ORDER BY fe.created_at) AS prev_type,
        LAG(fe.created_at) OVER (PARTITION BY dependency_vulns.id ORDER BY fe.created_at) AS prev_created_at,
        LEAD(fe.type) OVER (PARTITION BY dependency_vulns.id ORDER BY fe.created_at) AS next_type
    FROM
        dependency_vulns
    JOIN
        vuln_events fe ON dependency_vulns.id = fe.vuln_id
	JOIN artifact_dependency_vulns adv ON dependency_vulns.id = adv.dependency_vuln_id
	JOIN cves c ON dependency_vulns.cve_id = c.cve
    WHERE
        fe.type IN ? AND adv.artifact_artifact_name = ? AND dependency_vulns.asset_version_name = ? AND dependency_vulns.asset_id = ? AND c.cvss >= ? AND c.cvss < ?
),
intervals AS (
   SELECT
        id,
        component_purl,
        COALESCE(next_type, type) AS type,
        prev_type,
        prev_created_at,
        CASE
            WHEN next_type IS NULL THEN NOW() - prev_created_at
            ELSE created_at - prev_created_at
        END AS fixing_time
    FROM
        events
    WHERE
        prev_type IN ? 
)
SELECT
   EXTRACT(EPOCH FROM AVG(fixing_time)) AS avg
FROM
    intervals`, append(fixedEvents, openEvents...), artifactName, assetVersionName, assetID, cvssIntervalStart, cvssIntervalEnd, openEvents).Find(&results).Error
	}

	if err != nil {
		return 0, err
	}

	if len(results) == 0 {
		return 0, nil
	}

	fixingTimeStr := results[0].AvgFixingTime
	if fixingTimeStr == "" {
		return 0, nil
	}
	// parse it to float
	fixingTime, err := time.ParseDuration(fixingTimeStr + "s")
	if err != nil {
		return 0, err
	}

	return fixingTime, nil
}

func (r *statisticsRepository) AverageFixingTimeByCvssForRelease(releaseID uuid.UUID, cvssIntervalStart, cvssIntervalEnd float64) (time.Duration, error) {
	var results []struct {
		AvgFixingTime string `gorm:"column:avg"`
	}

	// This query mirrors AverageFixingTimeByCvss but limits dependency_vulns to those matching artifacts
	// that are part of the release tree (release_items), using a recursive CTE to collect child releases.
	err := r.db.Raw(`
WITH RECURSIVE release_tree AS (
	SELECT id FROM releases WHERE id = ?
	UNION ALL
	SELECT ri.child_release_id FROM release_items ri JOIN release_tree rt ON ri.release_id = rt.id WHERE ri.child_release_id IS NOT NULL
),
events AS (
	SELECT
		dv.id,
		dv.component_purl,
		fe.type,
		fe.created_at,
		LAG(fe.type) OVER (PARTITION BY dv.id ORDER BY fe.created_at) AS prev_type,
		LAG(fe.created_at) OVER (PARTITION BY dv.id ORDER BY fe.created_at) AS prev_created_at,
		LEAD(fe.type) OVER (PARTITION BY dv.id ORDER BY fe.created_at) AS next_type
	FROM dependency_vulns dv
	JOIN vuln_events fe ON dv.id = fe.vuln_id
	JOIN release_items ri ON dv.asset_version_name = ri.asset_version_name AND dv.asset_id = ri.asset_id
	JOIN cves c ON dv.cve_id = c.cve
	WHERE ri.release_id IN (SELECT id FROM release_tree) AND fe.type IN ? AND c.cvss >= ? AND c.cvss < ?
),
intervals AS (
   SELECT
		id,
		component_purl,
		COALESCE(next_type, type) AS type,
		prev_type,
		prev_created_at,
		CASE
			WHEN next_type IS NULL THEN NOW() - prev_created_at
			ELSE created_at - prev_created_at
		END AS fixing_time
	FROM
		events
	WHERE
		prev_type IN ?
)
SELECT
   EXTRACT(EPOCH FROM AVG(fixing_time)) AS avg
FROM
	intervals`, releaseID, append(fixedEvents, openEvents...), cvssIntervalStart, cvssIntervalEnd, openEvents).Find(&results).Error
	if err != nil {
		return 0, err
	}

	if len(results) == 0 {
		return 0, nil
	}

	fixingTimeStr := results[0].AvgFixingTime
	if fixingTimeStr == "" {
		return 0, nil
	}
	fixingTime, err := time.ParseDuration(fixingTimeStr + "s")
	if err != nil {
		return 0, err
	}

	return fixingTime, nil
}

func (r *statisticsRepository) CVESWithKnownExploitsInAssetVersion(assetVersion models.AssetVersion) ([]models.CVE, error) {
	var cves []models.CVE

	//Query to find all CVE in the vulnerabilities for which an exploit exists
	err := r.db.Raw("SELECT c.* FROM dependency_vulns d JOIN cves c ON d.cve_id = c.cve WHERE  EXISTS (SELECT id FROM exploits e WHERE d.cve_id = e.cve_id) AND d.asset_version_name = ?  AND d.state = 'open'  AND d.asset_id = ?;", assetVersion.Name, assetVersion.AssetID).Find(&cves).Error
	if err != nil {
		return cves, err
	}

	return cves, nil

}

// TO-DO refactor to dtos

func (r *statisticsRepository) VulnClassificationByOrg(orgID uuid.UUID) (dtos.VulnDistribution, error) {
	distribution := dtos.VulnDistribution{}
	err := r.db.Raw(`
	SELECT 
		COUNT(*) filter (where a.raw_risk_assessment < 4) as risk_low,
		COUNT(*) filter (where a.raw_risk_assessment >= 4 AND a.raw_risk_assessment < 7) as risk_medium,
       	COUNT(*) filter (where a.raw_risk_assessment >= 7 AND a.raw_risk_assessment < 9) as risk_high,
       	COUNT(*) filter (where a.raw_risk_assessment >= 9 AND a.raw_risk_assessment < 10) as risk_critical,
       	COUNT(*) filter (where d.cvss < 4) as cvss_low,
		COUNT(*) filter (where d.cvss >= 4 AND d.cvss < 7) as cvss_medium,
       	COUNT(*) filter (where d.cvss >= 7 AND d.cvss < 9) as cvss_high,
       	COUNT(*) filter (where d.cvss >= 9 AND d.cvss < 10) as cvss_critical
	FROM dependency_vulns a 
	LEFT JOIN assets b ON a.asset_id = b.id 
	LEFT JOIN projects c ON b.project_id = c.id
	LEFT JOIN cves d ON a.cve_id = d.cve 
	WHERE c.organization_id = ?;`, orgID).Find(&distribution).Error
	if err != nil {
		return distribution, err
	}
	return distribution, nil
}

func (r *statisticsRepository) GetOrgStructureDistribution(orgID uuid.UUID) (dtos.OrgStructureDistribution, error) {
	structure := dtos.OrgStructureDistribution{}
	err := r.db.Raw(`SELECT COUNT(DISTINCT(p.id)) as num_projects, 
			COUNT(DISTINCT(a.id)) as num_assets, 
			COUNT(DISTINCT CASE 
				WHEN 
					art.artifact_name IS NOT NULL OR art.asset_version_name IS NOT NULL 
				THEN 
					(art.artifact_name, art.asset_version_name) END) as num_artifacts 
			FROM projects p 
			LEFT JOIN assets a ON p.id = a.project_id
			LEFT JOIN artifacts art ON art.asset_id = a.id
			WHERE p.organization_id = ?;`, orgID).Find(&structure).Error
	return structure, err
}

func (r *statisticsRepository) GetMostVulnerableProjectsInOrg(orgID uuid.UUID, limit int) ([]dtos.VulnDistributionInStructure, error) {
	projects := []dtos.VulnDistributionInStructure{}
	err := r.db.Raw(`SELECT c.name, c.slug,
			 COUNT(*) as total,
			 COUNT(*) filter (where a.raw_risk_assessment < 4) as risk_low,
			 COUNT(*) filter (where a.raw_risk_assessment >= 4 AND a.raw_risk_assessment < 7) as risk_medium,
			 COUNT(*) filter (where a.raw_risk_assessment >= 7 AND a.raw_risk_assessment < 9) as risk_high,
			 COUNT(*) filter (where a.raw_risk_assessment >= 9 AND a.raw_risk_assessment < 10) as risk_critical,
			 COUNT(*) filter (where d.cvss < 4) as cvss_low,
			 COUNT(*) filter (where d.cvss >= 4 AND d.cvss < 7) as cvss_medium,
			 COUNT(*) filter (where d.cvss >= 7 AND d.cvss < 9) as cvss_high,
			 COUNT(*) filter (where d.cvss >= 9 AND d.cvss < 10) as cvss_critical
			 FROM dependency_vulns a
			 LEFT JOIN assets b ON a.asset_id = b.id 
			 LEFT JOIN projects c ON b.project_id = c.id
			 LEFT JOIN cves d ON a.cve_id = d.cve 
			 WHERE c.organization_id = ? GROUP BY c.id, c.slug
			 ORDER BY total DESC LIMIT ?;`, orgID, limit).Find(&projects).Error
	return projects, err
}

func (r *statisticsRepository) GetMostVulnerableAssetsInOrg(orgID uuid.UUID, limit int) ([]dtos.VulnDistributionInStructure, error) {
	assets := []dtos.VulnDistributionInStructure{}
	err := r.db.Raw(`SELECT b.name, b.slug, c.slug as project_slug,
			 COUNT(*) as total,
			 COUNT(*) filter (where a.raw_risk_assessment < 4) as risk_low,
			 COUNT(*) filter (where a.raw_risk_assessment >= 4 AND a.raw_risk_assessment < 7) as risk_medium,
			 COUNT(*) filter (where a.raw_risk_assessment >= 7 AND a.raw_risk_assessment < 9) as risk_high,
			 COUNT(*) filter (where a.raw_risk_assessment >= 9 AND a.raw_risk_assessment < 10) as risk_critical,
			 COUNT(*) filter (where d.cvss < 4) as cvss_low,
			 COUNT(*) filter (where d.cvss >= 4 AND d.cvss < 7) as cvss_medium,
			 COUNT(*) filter (where d.cvss >= 7 AND d.cvss < 9) as cvss_high,
			 COUNT(*) filter (where d.cvss >= 9 AND d.cvss < 10) as cvss_critical
			 FROM dependency_vulns a
			 LEFT JOIN assets b ON a.asset_id = b.id 
			 LEFT JOIN projects c ON b.project_id = c.id
			 LEFT JOIN cves d ON a.cve_id = d.cve 
			 WHERE c.organization_id = ? GROUP BY b.id,b.slug, c.slug 
			 ORDER BY total DESC LIMIT ?;`, orgID, limit).Find(&assets).Error
	return assets, err
}

func (r *statisticsRepository) GetMostVulnerableArtifactsInOrg(orgID uuid.UUID, limit int) ([]dtos.VulnDistributionInStructure, error) {
	artifacts := []dtos.VulnDistributionInStructure{}
	err := r.db.Raw(`SELECT e.artifact_name as name, e.artifact_name as slug, e.asset_version_name as asset_version_name,b.slug as asset_slug, c.slug as project_slug,
			 COUNT(*) as total,
			 COUNT(*) filter (where a.raw_risk_assessment < 4) as risk_low,
			 COUNT(*) filter (where a.raw_risk_assessment >= 4 AND a.raw_risk_assessment < 7) as risk_medium,
       		 COUNT(*) filter (where a.raw_risk_assessment >= 7 AND a.raw_risk_assessment < 9) as risk_high,
       		 COUNT(*) filter (where a.raw_risk_assessment >= 9 AND a.raw_risk_assessment < 10) as risk_critical,
			 COUNT(*) filter (where d.cvss < 4) as cvss_low,
			 COUNT(*) filter (where d.cvss >= 4 AND d.cvss < 7) as cvss_medium,
			 COUNT(*) filter (where d.cvss >= 7 AND d.cvss < 9) as cvss_high,
			 COUNT(*) filter (where d.cvss >= 9 AND d.cvss < 10) as cvss_critical
			 FROM dependency_vulns a
			 LEFT JOIN assets b ON a.asset_id = b.id 
			 LEFT JOIN projects c ON b.project_id = c.id
			 LEFT JOIN cves d ON a.cve_id = d.cve
			 LEFT JOIN artifacts e ON e.asset_id = b.id
			 WHERE c.organization_id = ?
			 GROUP BY e.artifact_name,e.asset_version_name, c.slug, b.slug
			 ORDER BY total DESC LIMIT ?;`, orgID, limit).Find(&artifacts).Error
	return artifacts, err
}
