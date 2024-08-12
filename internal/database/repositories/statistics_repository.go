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

func (g statisticsRepository) GetFlawDetailsByAssetId(assetID uuid.UUID) ([]models.Flaw, error) {
	var flaws []models.Flaw = []models.Flaw{}
	if err := g.db.Preload("Events").Find(&flaws, "asset_id = ?", assetID).Error; err != nil {
		return nil, err
	}
	return flaws, nil
}

func (r *statisticsRepository) GetRecentFlawsForAsset(assetID uuid.UUID, time time.Time) ([]models.FlawRisk, error) {
	var flawRisk []models.FlawRisk

	if err := r.db.Raw(`
		WITH RankedEvents AS (
			SELECT 
				flaw_events.flaw_id, 
				flaw_events.created_at,
				flaw_events.arbitrary_json_data,
				flaw_events.type,
				ROW_NUMBER() OVER (PARTITION BY flaw_events.flaw_id ORDER BY flaw_events.created_at DESC) AS rn
			FROM 
				flaw_events
			WHERE 
				flaw_events.created_at <= ?
				AND EXISTS (
					SELECT 1 
					FROM flaws 
					WHERE flaws.id = flaw_events.flaw_id 
					  AND flaws.asset_id = ?
				)
				AND flaw_events.type IN ('detected', 'rawRiskAssessmentUpdated')
		)
		SELECT 
			flaw_id, 
			created_at, 
			arbitrary_json_data,
			type
		FROM 
			RankedEvents
		WHERE 
			rn = 1
		ORDER BY 
			flaw_id;
	`, time, assetID).Scan(&flawRisk).Error; err != nil {

		return nil, err
	}

	return flawRisk, nil
}

func (r *statisticsRepository) GetRecentFlawsState(assetID uuid.UUID, time time.Time) ([]models.FlawRisk, error) {
	var flawRisk []models.FlawRisk

	if err := r.db.Raw(`
		WITH RankedEvents AS (
			SELECT 
				flaw_events.flaw_id, 
				flaw_events.created_at,
				flaw_events.arbitrary_json_data,
				flaw_events.type,
				ROW_NUMBER() OVER (PARTITION BY flaw_events.flaw_id ORDER BY flaw_events.created_at DESC) AS rn
			FROM 
				flaw_events
			WHERE 
				flaw_events.created_at <= ?
				AND EXISTS (
					SELECT 1 
					FROM flaws 
					WHERE flaws.id = flaw_events.flaw_id 
					  AND flaws.asset_id = ?
				)
				AND flaw_events.type IN ('detected', 'reopened', 'fixed', 'accepted', 'falsePositive')
		)
		SELECT 
			flaw_id, 
			created_at, 
			arbitrary_json_data,
			type
		FROM 
			RankedEvents
		WHERE 
			rn = 1
		ORDER BY 
			flaw_id;
	`, time, assetID).Scan(&flawRisk).Error; err != nil {

		return nil, err
	}

	return flawRisk, nil
}

func (r *statisticsRepository) GetAssetCriticalDependenciesGroupedByScanType(assetID uuid.UUID) ([]models.AssetDependencies, error) {
	var results []models.AssetDependencies
	err := r.db.Model(&models.Flaw{}).
		Select("scanner_id , COUNT(*) as count").
		Group("scanner_id").
		Where("asset_id = ?", assetID).
		Find(&results).Error

	if err != nil {
		return nil, err
	}

	return results, nil
}

func (r *statisticsRepository) GetAssetFlawsStatistics(assetID uuid.UUID) ([]models.AssetRiskSummary, error) {
	var results []models.AssetRiskSummary

	err := r.db.Model(&models.Flaw{}).
		Select("scanner_id , raw_risk_assessment,  COUNT(*) as count , AVG(raw_risk_assessment) as average, SUM(raw_risk_assessment) as sum").
		Group("scanner_id, raw_risk_assessment").
		Where("asset_id = ?", assetID).
		Find(&results).Error

	if err != nil {
		return nil, err
	}

	return results, nil
}

func (r *statisticsRepository) GetAssetRisksDistribution(assetID uuid.UUID) ([]models.AssetRiskDistribution, error) {
	var results []models.AssetRiskDistribution

	err := r.db.Raw(`
        SELECT 
            scanner_id,
            CASE 
                WHEN raw_risk_assessment >= 0.0 AND raw_risk_assessment < 2.0 THEN '0-2'
                WHEN raw_risk_assessment >= 2.0 AND raw_risk_assessment < 4.0 THEN '2-4'
                WHEN raw_risk_assessment >= 4.0 AND raw_risk_assessment < 6.0 THEN '4-6'
				WHEN raw_risk_assessment >= 6.0 AND raw_risk_assessment < 8.0 THEN '6-8'
				WHEN raw_risk_assessment >= 8.0 AND raw_risk_assessment <= 10.0 THEN '8-10'
				ELSE 'unknown'
            END AS risk_range,
            COUNT(*) as count
        FROM flaws
        WHERE asset_id = ?
        GROUP BY scanner_id, risk_range
    `, assetID).Scan(&results).Error

	if err != nil {
		return nil, err
	}

	return results, nil
}
