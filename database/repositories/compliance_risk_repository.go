package repositories

import (
	"context"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/statemachine"
	"github.com/l3montree-dev/devguard/utils"
	"gorm.io/gorm"
)

type ComplianceRiskRepository struct {
	utils.Repository[uuid.UUID, models.ComplianceRisk, *gorm.DB]
	db *gorm.DB
}

func NewComplianceRiskRepository(db *gorm.DB) *ComplianceRiskRepository {
	return &ComplianceRiskRepository{
		db:         db,
		Repository: newGormRepository[uuid.UUID, models.ComplianceRisk](db),
	}
}

func (r *ComplianceRiskRepository) GetAllComplianceRisksForAssetVersion(ctx context.Context, tx *gorm.DB, assetID uuid.UUID, assetVersionName string) ([]models.ComplianceRisk, error) {
	var result []models.ComplianceRisk
	err := r.GetDB(ctx, tx).Preload("Artifacts").Where("asset_id = ? AND asset_version_name = ?", assetID, assetVersionName).Find(&result).Error
	return result, err
}

func (r *ComplianceRiskRepository) GetAllComplianceRisksForAssetVersionPaged(ctx context.Context, tx *gorm.DB, assetID uuid.UUID, assetVersionName string, pageInfo shared.PageInfo, search string, filter []shared.FilterQuery, sort []shared.SortQuery) (shared.Paged[models.ComplianceRisk], error) {
	var count int64
	var risks []models.ComplianceRisk

	q := r.GetDB(ctx, tx).Model(&models.ComplianceRisk{}).
		Preload("Artifacts").
		Joins("LEFT JOIN artifact_compliance_risks ON artifact_compliance_risks.compliance_risk_id = compliance_risks.id").
		Where("compliance_risks.asset_version_name = ?", assetVersionName).
		Where("compliance_risks.asset_id = ?", assetID).
		Distinct()

	for _, f := range filter {
		q = q.Where(f.SQL(), f.Value())
	}

	if len(search) > 2 {
		q = q.Where("compliance_risks.policy_id ILIKE ?", "%"+search+"%")
	}

	if err := q.Session(&gorm.Session{}).Distinct("compliance_risks.id").Count(&count).Error; err != nil {
		return shared.Paged[models.ComplianceRisk]{}, err
	}

	err := q.Limit(pageInfo.PageSize).Offset((pageInfo.Page - 1) * pageInfo.PageSize).Find(&risks).Error
	if err != nil {
		return shared.Paged[models.ComplianceRisk]{}, err
	}
	return shared.NewPaged(pageInfo, count, risks), nil
}

func (r *ComplianceRiskRepository) Read(ctx context.Context, tx *gorm.DB, id uuid.UUID) (models.ComplianceRisk, error) {
	var risk models.ComplianceRisk
	err := r.GetDB(ctx, tx).Where("id = ?", id).
		Preload("Artifacts").
		Preload("Events", func(db *gorm.DB) *gorm.DB {
			return db.Order("created_at ASC")
		}).
		First(&risk).Error
	return risk, err
}

func (r *ComplianceRiskRepository) ApplyAndSave(ctx context.Context, tx *gorm.DB, risk *models.ComplianceRisk, ev *models.VulnEvent) error {
	if tx == nil {
		return r.Transaction(ctx, func(d *gorm.DB) error {
			return r.applyAndSave(ctx, d, risk, ev)
		})
	}
	return r.applyAndSave(ctx, tx, risk, ev)
}

func (r *ComplianceRiskRepository) applyAndSave(ctx context.Context, tx *gorm.DB, risk *models.ComplianceRisk, ev *models.VulnEvent) error {
	statemachine.Apply(risk, *ev)
	if err := r.Save(ctx, tx, risk); err != nil {
		return err
	}
	if err := r.GetDB(ctx, tx).Save(ev).Error; err != nil {
		return err
	}
	risk.Events = append(risk.Events, *ev)
	return nil
}

func (r *ComplianceRiskRepository) GetComplianceRisksByOtherAssetVersions(ctx context.Context, tx *gorm.DB, assetVersionName string, assetID uuid.UUID) ([]models.ComplianceRisk, error) {
	var risks []models.ComplianceRisk
	q := r.GetDB(ctx, tx).
		Preload("Events", func(db *gorm.DB) *gorm.DB {
			return db.Order("created_at ASC")
		}).
		Preload("Artifacts").
		Where("compliance_risks.asset_version_name != ? AND compliance_risks.asset_id = ?", assetVersionName, assetID)
	if err := q.Find(&risks).Error; err != nil {
		return nil, err
	}
	return risks, nil
}

func (r *ComplianceRiskRepository) GetDistinctFrameworksForAssetVersion(ctx context.Context, tx *gorm.DB, assetID uuid.UUID, assetVersionName string) ([]string, error) {
	type result struct {
		Framework string
	}
	var rows []result
	err := r.GetDB(ctx, tx).Raw(`
		SELECT DISTINCT elem->>'framework' AS framework
		FROM compliance_risks,
		     jsonb_array_elements("policyFrameworks") AS elem
		WHERE asset_id = ? AND asset_version_name = ?
		  AND elem->>'framework' IS NOT NULL
		ORDER BY framework
	`, assetID, assetVersionName).Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	frameworks := make([]string, len(rows))
	for i, row := range rows {
		frameworks[i] = row.Framework
	}
	return frameworks, nil
}

func (r *ComplianceRiskRepository) SaveBatch(ctx context.Context, tx *gorm.DB, risks []models.ComplianceRisk) error {
	if len(risks) == 0 {
		return nil
	}
	return r.GetDB(ctx, tx).Save(&risks).Error
}
