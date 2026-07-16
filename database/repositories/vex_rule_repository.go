// Copyright (C) 2026 l3montree GmbH
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package repositories

import (
	"context"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/shared"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type vexRuleRepository struct {
	db *gorm.DB
}

func NewVEXRuleRepository(db *gorm.DB) *vexRuleRepository {
	return &vexRuleRepository{
		db: db,
	}
}

var _ shared.VEXRuleRepository = (*vexRuleRepository)(nil)

func (r *vexRuleRepository) GetDB(ctx context.Context, tx *gorm.DB) *gorm.DB {
	if tx != nil {
		return tx
	}
	return r.db.WithContext(ctx)
}

func (r *vexRuleRepository) Begin(ctx context.Context) shared.DB {
	return r.GetDB(ctx, nil).Begin()
}

func (r *vexRuleRepository) All(ctx context.Context, tx *gorm.DB) ([]models.VEXRule, error) {
	var result []models.VEXRule

	err := r.GetDB(ctx, tx).Model(models.VEXRule{}).Find(&result).Error
	return result, err
}

func (r *vexRuleRepository) FindByCVE(ctx context.Context, tx *gorm.DB, cveID string) ([]models.VEXRule, error) {
	var rules []models.VEXRule
	err := r.GetDB(ctx, tx).Preload("Asset").Where("LOWER(cve_id) = LOWER(?) AND enabled = ?", cveID, true).Find(&rules).Error
	return rules, err
}

func (r *vexRuleRepository) FindByAssetID(ctx context.Context, tx *gorm.DB, assetID uuid.UUID) ([]models.VEXRule, error) {
	var rules []models.VEXRule
	err := r.GetDB(ctx, tx).Where("asset_id = ?", assetID).Order("created_at DESC").Find(&rules).Error
	return rules, err
}

func (r *vexRuleRepository) FindByAssetIDAndCVE(ctx context.Context, tx *gorm.DB, assetID uuid.UUID, cveID string) ([]models.VEXRule, error) {
	var rules []models.VEXRule
	err := r.GetDB(ctx, tx).Where("asset_id = ? AND LOWER(cve_id) = LOWER(?)", assetID, cveID).Order("created_at DESC").Find(&rules).Error
	return rules, err
}

func (r *vexRuleRepository) FindByAssetIDPaged(ctx context.Context, tx *gorm.DB, assetID uuid.UUID, pageInfo shared.PageInfo, search string, filterQuery []shared.FilterQuery, sortQuery []shared.SortQuery) (shared.Paged[models.VEXRule], error) {
	var rules []models.VEXRule
	var total int64

	query := r.GetDB(ctx, tx).Model(&models.VEXRule{}).Where("asset_id = ? ", assetID)

	// Apply search filter
	if search != "" {
		searchPattern := "%" + search + "%"
		query = query.Where("cve_id ILIKE ? OR justification ILIKE ?", searchPattern, searchPattern)
	}

	// Apply filter queries
	for _, filter := range filterQuery {
		query = query.Where(filter.SQL(), filter.Value())
	}

	// Count total before pagination
	if err := query.Count(&total).Error; err != nil {
		return shared.Paged[models.VEXRule]{}, err
	}

	// Apply sorting
	if len(sortQuery) > 0 {
		for _, sort := range sortQuery {
			query = query.Order(sort.SQL())
		}
	} else {
		query = query.Order("created_at DESC")
	}

	// Apply pagination
	query = pageInfo.ApplyOnDB(query)

	if err := query.Find(&rules).Error; err != nil {
		return shared.Paged[models.VEXRule]{}, err
	}

	return shared.NewPaged(pageInfo, total, rules), nil
}

func (r *vexRuleRepository) FindByID(ctx context.Context, tx *gorm.DB, id string) (models.VEXRule, error) {
	var rule models.VEXRule
	db := withOwnershipScope(ctx, r.GetDB(ctx, tx).Where("id = ?", id), rule)
	err := db.First(&rule).Error
	return rule, err
}

func (r *vexRuleRepository) Create(ctx context.Context, tx *gorm.DB, rule *models.VEXRule) error {
	// Ensure the ID is calculated
	rule.EnsureID()
	return r.GetDB(ctx, tx).Create(rule).Error
}

func (r *vexRuleRepository) Upsert(ctx context.Context, tx *gorm.DB, rule *models.VEXRule) error {
	// Ensure the ID is calculated
	rule.EnsureID()
	return r.GetDB(ctx, tx).Clauses(clause.OnConflict{
		UpdateAll: true,
	}).Create(rule).Error
}

func (r *vexRuleRepository) Update(ctx context.Context, tx *gorm.DB, rule *models.VEXRule) error {
	// Recalculate ID if path pattern changed
	rule.EnsureID()
	return r.GetDB(ctx, tx).Save(rule).Error
}

func (r *vexRuleRepository) Delete(ctx context.Context, tx *gorm.DB, rule models.VEXRule) error {
	return r.GetDB(ctx, tx).Delete(&rule).Error
}

func (r *vexRuleRepository) DeleteByAssetID(ctx context.Context, tx *gorm.DB, assetID uuid.UUID) error {
	return r.GetDB(ctx, tx).Where("asset_id = ?", assetID).Delete(&models.VEXRule{}).Error
}

func (r *vexRuleRepository) FindByAssetAndVexSource(ctx context.Context, tx *gorm.DB, assetID uuid.UUID, vexSource string) ([]models.VEXRule, error) {
	var rules []models.VEXRule
	err := r.GetDB(ctx, tx).Where("asset_id = ? AND vex_source = ?", assetID, vexSource).Find(&rules).Error
	return rules, err
}

func (r *vexRuleRepository) UpsertBatch(ctx context.Context, tx *gorm.DB, rules []models.VEXRule) error {
	if len(rules) == 0 {
		return nil
	}
	// Ensure IDs are calculated
	for i := range rules {
		rules[i].EnsureID()
	}

	// Deduplicate by ID - postgres cannot affect the same row twice within a single
	// INSERT ... ON CONFLICT DO UPDATE statement (SQLSTATE 21000).
	deduped := make([]models.VEXRule, 0, len(rules))
	seen := make(map[string]struct{}, len(rules))
	for _, rule := range rules {
		if _, ok := seen[rule.ID]; ok {
			continue
		}
		seen[rule.ID] = struct{}{}
		deduped = append(deduped, rule)
	}

	return r.GetDB(ctx, tx).Clauses(clause.OnConflict{
		UpdateAll: true,
	}).Create(&deduped).Error
}

func (r *vexRuleRepository) DeleteBatch(ctx context.Context, tx *gorm.DB, rules []models.VEXRule) error {
	if len(rules) == 0 {
		return nil
	}
	// Delete by ID
	tx = r.GetDB(ctx, tx)
	for _, rule := range rules {
		if err := tx.Delete(&rule).Error; err != nil {
			return err
		}
	}
	return nil
}
