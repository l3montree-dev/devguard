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

// returns all flaws for the asset including the events, which were created before the given time
func (r *statisticsRepository) TimeTravelFlawState(assetVersionName string, assetID uuid.UUID, time time.Time) ([]models.Flaw, error) {
	flaws := []models.Flaw{}

	err := r.db.Model(&models.Flaw{}).Preload("Events", func(db core.DB) core.DB {
		return db.Where("created_at <= ?", time).Order("created_at ASC")
	}).
		Where("asset_version_id = ?", assetVersionName).Where("asset_id = ?", assetID).Where("created_at <= ?", time).
		Find(&flaws).Error

	if err != nil {
		return nil, err
	}

	// now remove all events of the flaws, which were created after the given time
	for _, flaw := range flaws {
		// get the last event of the flaw based on the created_at timestamp.
		tmpFlaw := flaw

		events := flaw.Events
		// iterate through all events and apply them
		for _, event := range events {
			event.Apply(&tmpFlaw)
		}
	}
	return flaws, nil
}

func (r *statisticsRepository) GetFlawCountByScannerId(assetVersionName string, assetID uuid.UUID) (map[string]int, error) {
	var results []struct {
		ScannerID string `gorm:"column:scanner_id"`
		Count     int    `gorm:"column:count"`
	}

	err := r.db.Model(&models.Flaw{}).
		Select("scanner_id , COUNT(*) as count").
		Group("scanner_id").
		Where("asset_version_name = ?", assetVersionName).
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

func (r *statisticsRepository) GetAssetRiskDistribution(assetVersionName string, assetID uuid.UUID, assetName string) (models.AssetRiskDistribution, error) {
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
        FROM flaws
        WHERE asset_version_name = ? AND asset_id = ? AND state = 'open'
        GROUP BY severity
    `, assetVersionName, assetID).Scan(&results).Error

	if err != nil {
		return models.AssetRiskDistribution{}, err
	}

	// convert to map
	counts := make(map[string]int)
	for _, r := range results {
		counts[r.Severity] = r.Count
	}

	return models.AssetRiskDistribution{
		AssetID:          assetID,
		AssetVersionName: assetVersionName,
		Label:            assetName,
		Low:              counts["LOW"],
		Medium:           counts["MEDIUM"],
		High:             counts["HIGH"],
		Critical:         counts["CRITICAL"],
	}, nil
}

var fixedEvents = []models.FlawEventType{
	models.EventTypeAccepted,
	models.EventTypeFixed,
	models.EventTypeFalsePositive,
}

var openEvents = []models.FlawEventType{
	models.EventTypeDetected,
	models.EventTypeReopened,
}

func (r *statisticsRepository) AverageFixingTime(assetVersionName string, assetID uuid.UUID, riskIntervalStart, riskIntervalEnd float64) (time.Duration, error) {
	var results []struct {
		AvgFixingTime string `gorm:"column:avg"`
	}
	err := r.db.Raw(`
WITH events AS (
    SELECT
        flaws.id,
        flaws.component_purl,
        fe.type,
        fe.created_at,
        LAG(fe.type) OVER (PARTITION BY flaws.id ORDER BY fe.created_at) AS prev_type,
        LAG(fe.created_at) OVER (PARTITION BY flaws.id ORDER BY fe.created_at) AS prev_created_at,
        LEAD(fe.type) OVER (PARTITION BY flaws.id ORDER BY fe.created_at) AS next_type
    FROM
        flaws
    JOIN
        flaw_events fe ON flaws.id = fe.flaw_id
    WHERE
        fe.type IN ? AND flaws.asset_version_name = ? AND flaws.asset_id = ? AND flaws.raw_risk_assessment >= ? AND flaws.raw_risk_assessment <= ?
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
