package repositories

import (
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"gorm.io/gorm"
)

type flawRepository struct {
	db core.DB
	Repository[string, models.Flaw, core.DB]
}

func NewFlawRepository(db core.DB) *flawRepository {
	if err := db.AutoMigrate(&models.Flaw{}); err != nil {
		panic(err)
	}
	return &flawRepository{
		db:         db,
		Repository: newGormRepository[string, models.Flaw](db),
	}
}

func (r *flawRepository) GetByAssetId(
	tx *gorm.DB,
	assetId uuid.UUID,
) ([]models.Flaw, error) {

	var flaws []models.Flaw = []models.Flaw{}
	// get all flaws of the asset
	if err := r.Repository.GetDB(tx).Where("asset_id = ?", assetId).Find(&flaws).Error; err != nil {
		return nil, err
	}
	return flaws, nil
}

func (r *flawRepository) ListByScanner(assetID uuid.UUID, scannerID string) ([]models.Flaw, error) {
	var flaws []models.Flaw = []models.Flaw{}
	if err := r.Repository.GetDB(r.db).Preload("CVE").Where("asset_id = ? AND scanner_id = ?", assetID, scannerID).Find(&flaws).Error; err != nil {
		return nil, err
	}
	return flaws, nil
}

func (r *flawRepository) GetByAssetIdPaged(tx core.DB, pageInfo core.PageInfo, filter []core.FilterQuery, sort []core.SortQuery, assetId uuid.UUID) (core.Paged[models.Flaw], error) {
	var count int64
	var flaws []models.Flaw = []models.Flaw{}

	q := r.Repository.GetDB(tx).Joins("CVE").Joins("Component").Where("flaws.asset_id = ?", assetId)

	// apply filters
	for _, f := range filter {
		q = q.Where(f.SQL(), f.Value())
	}
	q.Model(&models.Flaw{}).Count(&count)

	// get all flaws of the asset
	q = pageInfo.ApplyOnDB(r.Repository.GetDB(tx)).Joins("CVE").Joins("Component").Where("flaws.asset_id = ?", assetId)

	// apply filters
	for _, f := range filter {
		q = q.Where(f.SQL(), f.Value())
	}

	// apply sorting
	if len(sort) > 0 {
		for _, s := range sort {
			q = q.Order(s.SQL())
		}
	} else {
		q = q.Order("\"CVE\".\"cvss\" desc")
	}

	err := q.Find(&flaws).Error

	if err != nil {
		return core.Paged[models.Flaw]{}, err
	}

	return core.NewPaged(pageInfo, count, flaws), nil
}

func (r *flawRepository) GetAllFlawsByAssetID(tx core.DB, assetID uuid.UUID) ([]models.Flaw, error) {
	var flaws []models.Flaw = []models.Flaw{}
	if err := r.Repository.GetDB(tx).Where("asset_id = ?", assetID).Find(&flaws).Error; err != nil {
		return nil, err
	}
	return flaws, nil
}

func (g flawRepository) Read(id string) (models.Flaw, error) {
	var t models.Flaw
	err := g.db.Preload("CVE.Weaknesses").Preload("Events", func(db core.DB) core.DB {
		return db.Order("created_at ASC")
	}).Preload("CVE").Preload("CVE.Exploits").First(&t, "id = ?", id).Error

	return t, err
}

func (r *flawRepository) GetFlawsByPurlOrCpe(tx core.DB, purlOrCpe []string) ([]models.Flaw, error) {

	var flaws []models.Flaw = []models.Flaw{}
	if len(purlOrCpe) == 0 {
		return flaws, nil
	}

	if err := r.Repository.GetDB(tx).Where("component_purl_or_cpe IN ?", purlOrCpe).Find(&flaws).Error; err != nil {
		return nil, err
	}

	return flaws, nil
}

func (r *flawRepository) GetRecentFlawsForAsset(assetID uuid.UUID, time time.Time) ([]models.FlawRisk, error) {
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

func (r *flawRepository) GetAssetCriticalDependenciesGroupedByScanType(asset_ID string) ([]models.AssetCriticalDependencies, error) {
	var results []models.AssetCriticalDependencies
	err := r.db.Model(&models.Flaw{}).
		Select("scanner_id , COUNT(*) as count").
		Group("scanner_id").
		Where("asset_id = ?", asset_ID).
		Find(&results).Error

	if err != nil {
		return nil, err
	}

	return results, nil
}

func (r *flawRepository) GetAssetFlawsStatistics(asset_ID string) ([]models.AssetRiskSummary, error) {
	var results []models.AssetRiskSummary

	err := r.db.Model(&models.Flaw{}).
		Select("scanner_id , raw_risk_assessment,  COUNT(*) as count , AVG(raw_risk_assessment) as average, SUM(raw_risk_assessment) as sum").
		Group("scanner_id, raw_risk_assessment").
		Where("asset_id = ?", asset_ID).
		Find(&results).Error

	if err != nil {
		return nil, err
	}

	return results, nil
}

func (r *flawRepository) GetAssetRisksDistribution(asset_ID string) ([]models.AssetRiskDistribution, error) {
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
    `, asset_ID).Scan(&results).Error

	if err != nil {
		return nil, err
	}

	return results, nil
}
