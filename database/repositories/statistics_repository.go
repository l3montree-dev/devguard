package repositories

import (
	"context"
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
		err = r.GetDB(ctx, tx).Model(&models.DependencyVuln{}).Preload("CVE").Preload("Events", func(db *gorm.DB) *gorm.DB {
			return db.Where("created_at <= ?", time).Order("created_at ASC")
		}).
			Joins("JOIN artifact_dependency_vulns adv ON adv.dependency_vuln_id = dependency_vulns.id").
			Where("dependency_vulns.asset_id = ?", assetID).Where("created_at <= ?", time).
			Find(&dependencyVulns).Error
	} else if artifactName != nil {
		err = r.GetDB(ctx, tx).Model(&models.DependencyVuln{}).Preload("CVE").Preload("Events", func(db *gorm.DB) *gorm.DB {
			return db.Where("created_at <= ?", time).Order("created_at ASC")
		}).
			Joins("JOIN artifact_dependency_vulns adv ON adv.dependency_vuln_id = dependency_vulns.id").
			Where("adv.artifact_asset_version_name = ?", *assetVersionName).Where("adv.artifact_asset_id = ?", assetID).Where("adv.artifact_artifact_name = ?", artifactName).Where("created_at <= ?", time).
			Find(&dependencyVulns).Error
	} else {
		err = r.GetDB(ctx, tx).Model(&models.DependencyVuln{}).Preload("CVE").Preload("Events", func(db *gorm.DB) *gorm.DB {
			return db.Where("created_at <= ?", time).Order("created_at ASC")
		}).Where("adv.artifact_asset_id = ?", assetID).Where("adv.artifact_artifact_name = ?", artifactName).Where("created_at <= ?", time).
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
	JOIN vuln_events fe ON dependency_vulns.id = fe.vuln_id
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
	JOIN vuln_events fe ON dependency_vulns.id = fe.vuln_id
	LEFT JOIN cves c ON dependency_vulns.cve_id = c.cve
	JOIN (
		SELECT DISTINCT dependency_vuln_id
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
	JOIN vuln_events fe ON dv.id = fe.vuln_id
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
