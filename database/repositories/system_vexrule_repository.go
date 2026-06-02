package repositories

import (
	"context"

	"github.com/l3montree-dev/devguard/database/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type systemVEXRuleRepository struct {
	db *gorm.DB
}

func NewSystemVEXRuleRepository(db *gorm.DB) *systemVEXRuleRepository {
	return &systemVEXRuleRepository{
		db: db,
	}
}

func (r *systemVEXRuleRepository) GetDB(ctx context.Context, tx *gorm.DB) *gorm.DB {
	if tx != nil {
		return tx
	}
	return r.db.WithContext(ctx)
}

func (r *systemVEXRuleRepository) UpsertBatch(ctx context.Context, tx *gorm.DB, rules []models.SystemVEXRule) error {
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
