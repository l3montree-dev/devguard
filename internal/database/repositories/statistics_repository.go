package repositories

import (
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database"

	"github.com/l3montree-dev/devguard/internal/database/models"
)

type statisticsRepository struct {
	db database.DB
}

func NewStatisticsRepository(db core.DB) *statisticsRepository {
	return &statisticsRepository{
		db: db,
	}
}

// returns all dependencyVulns for the asset including the events, which were created before the given time
func (r *statisticsRepository) TimeTravelDependencyVulnState(assetID uuid.UUID, time time.Time) ([]models.DependencyVulnerability, error) {
	dependencyVulns := []models.DependencyVulnerability{}

	err := r.db.Model(&models.DependencyVulnerability{}).Preload("Events", func(db core.DB) core.DB {
		return db.Where("created_at <= ?", time).Order("created_at ASC")
	}).
		Where("asset_id = ?", assetID).Where("created_at <= ?", time).
		Find(&dependencyVulns).Error

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
			event.Apply(&tmpDependencyVuln)
		}
	}
	return dependencyVulns, nil
}

func (r *statisticsRepository) GetDependencyVulnCountByScannerId(assetID uuid.UUID) (map[string]int, error) {
	var results []struct {
		ScannerID string `gorm:"column:scanner_id"`
		Count     int    `gorm:"column:count"`
	}

	err := r.db.Model(&models.DependencyVulnerability{}).
		Select("scanner_id , COUNT(*) as count").
		Group("scanner_id").
		Where("asset_id = ?", assetID).
		Find(&results).Error

	if err != nil {
		return nil, err
	}

	// convert to map
	counts := make(map[string]int)
	for _, r := range results {
		counts[r.ScannerID] = r.Count
	}

	return counts, nil
}

func (r *statisticsRepository) GetAssetRiskDistribution(assetID uuid.UUID, assetName string) (models.AssetRiskDistribution, error) {
	var results []struct {
		Severity string `gorm:"column:severity"`
		Count    int    `gorm:"column:count"`
	}

	err := r.db.Raw(`
        SELECT 
            CASE 
                WHEN raw_risk_assessment >= 0.0 AND raw_risk_assessment < 4.0 THEN 'LOW'
                WHEN raw_risk_assessment >= 4.0 AND raw_risk_assessment < 7 THEN 'MEDIUM'
                WHEN raw_risk_assessment >= 7 AND raw_risk_assessment < 9 THEN 'HIGH'
				WHEN raw_risk_assessment >= 9 AND raw_risk_assessment <= 10.0 THEN 'CRITICAL'
				ELSE 'unknown'
            END AS severity,
            COUNT(*) as count
        FROM dependencyVulns
        WHERE asset_id = ? AND state = 'open'
        GROUP BY severity
    `, assetID).Scan(&results).Error

	if err != nil {
		return models.AssetRiskDistribution{}, err
	}

	// convert to map
	counts := make(map[string]int)
	for _, r := range results {
		counts[r.Severity] = r.Count
	}

	return models.AssetRiskDistribution{
		ID:       assetID,
		Label:    assetName,
		Low:      counts["LOW"],
		Medium:   counts["MEDIUM"],
		High:     counts["HIGH"],
		Critical: counts["CRITICAL"],
	}, nil
}

var fixedEvents = []models.DependencyVulnEventType{
	models.EventTypeAccepted,
	models.EventTypeFixed,
	models.EventTypeFalsePositive,
}

var openEvents = []models.DependencyVulnEventType{
	models.EventTypeDetected,
	models.EventTypeReopened,
}

func (r *statisticsRepository) AverageFixingTime(assetID uuid.UUID, riskIntervalStart, riskIntervalEnd float64) (time.Duration, error) {
	var results []struct {
		AvgFixingTime string `gorm:"column:avg"`
	}
	err := r.db.Raw(`
WITH events AS (
    SELECT
        dependencyVulns.id,
        dependencyVulns.component_purl,
        fe.type,
        fe.created_at,
        LAG(fe.type) OVER (PARTITION BY dependencyVulns.id ORDER BY fe.created_at) AS prev_type,
        LAG(fe.created_at) OVER (PARTITION BY dependencyVulns.id ORDER BY fe.created_at) AS prev_created_at,
        LEAD(fe.type) OVER (PARTITION BY dependencyVulns.id ORDER BY fe.created_at) AS next_type
    FROM
        dependencyVulns
    JOIN
        dependencyVuln_events fe ON dependencyVulns.id = fe.dependencyVuln_id
    WHERE
        fe.type IN ? AND dependencyVulns.asset_id = ? AND dependencyVulns.raw_risk_assessment >= ? AND dependencyVulns.raw_risk_assessment <= ?
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
    intervals`, append(fixedEvents, openEvents...), assetID, riskIntervalStart, riskIntervalEnd, openEvents).Find(&results).Error
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
