package repositories

import (
	"context"
	"strings"

	"github.com/l3montree-dev/devguard/database/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type upstreamVEXRuleRepository struct {
	db *gorm.DB
}

func NewUpstreamVEXRuleRepository(db *gorm.DB) *upstreamVEXRuleRepository {
	return &upstreamVEXRuleRepository{
		db: db,
	}
}

func (r *upstreamVEXRuleRepository) All(ctx context.Context, tx *gorm.DB) ([]models.UpstreamVEXRule, error) {
	var result []models.UpstreamVEXRule

	err := r.GetDB(ctx, tx).Preload("CVE.Relationships").Find(&result).Error
	return result, err
}

func (r *upstreamVEXRuleRepository) GetDB(ctx context.Context, tx *gorm.DB) *gorm.DB {
	if tx != nil {
		return tx
	}
	return r.db.WithContext(ctx)
}

func (r *upstreamVEXRuleRepository) FindByCVE(ctx context.Context, tx *gorm.DB, cveID string) ([]models.UpstreamVEXRule, error) {
	var rules []models.UpstreamVEXRule
	err := r.GetDB(ctx, tx).Preload("CVE").Where("LOWER(cve_id) = LOWER(?)", cveID).Find(&rules).Error
	return rules, err
}

func (r *upstreamVEXRuleRepository) FindByCVEBatch(ctx context.Context, tx *gorm.DB, cveIDs []string) ([]models.UpstreamVEXRule, error) {
	var rules []models.UpstreamVEXRule
	var lowercaseCVEs []string
	for _, cve := range cveIDs {
		lowercaseCVEs = append(lowercaseCVEs, strings.ToLower(cve))
	}
	err := r.GetDB(ctx, tx).Preload("CVE").Where("LOWER(cve_id) IN ?", lowercaseCVEs).Find(&rules).Error
	return rules, err
}

func (r *upstreamVEXRuleRepository) UpsertBatch(ctx context.Context, tx *gorm.DB, rules []models.UpstreamVEXRule) error {
	if len(rules) == 0 {
		return nil
	}
	// Ensure IDs are calculated
	for i := range rules {
		rules[i].EnsureID()
	}
	return r.GetDB(ctx, tx).Clauses(clause.OnConflict{
		UpdateAll: true,
	}).CreateInBatches(&rules, 1000).Error
}
