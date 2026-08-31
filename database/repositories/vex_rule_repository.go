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
	"errors"
	"iter"

	"fmt"
	"github.com/google/uuid"

	"github.com/l3montree-dev/devguard/database"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/lib/pq"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type upstreamVEXRuleRepository struct {
	utils.Repository[string, models.UpstreamVEXRule, shared.DB]
}

var errStopIteration = errors.New("stop iteration")

func (r *upstreamVEXRuleRepository) ByCveScopes(ctx context.Context, tx *gorm.DB, cveIDs []string, batchSize int) iter.Seq2[[]models.UpstreamVEXRule, error] {
	return func(yield func([]models.UpstreamVEXRule, error) bool) {
		var rules []models.UpstreamVEXRule
		err := r.GetDB(ctx, tx).Where("cve_scope = ANY (?)", pq.Array(cveIDs)).FindInBatches(&rules, batchSize, func(_ *gorm.DB, _ int) error {
			if !yield(rules, nil) {
				return errStopIteration
			}
			return nil
		}).Error

		if err != nil && !errors.Is(err, errStopIteration) {
			yield(nil, err)
		}
	}
}

var _ shared.UpstreamVEXRuleRepository = (*upstreamVEXRuleRepository)(nil)

func NewUpstreamVEXRuleRepository(db *gorm.DB) *upstreamVEXRuleRepository {
	return &upstreamVEXRuleRepository{
		Repository: newGormRepository[string, models.UpstreamVEXRule](db),
	}
}

type vexRuleRecommendationRepository struct {
	utils.Repository[string, models.VEXRuleRecommendation, shared.DB]
}

var _ shared.VEXRuleRecommendationRepository = (*vexRuleRecommendationRepository)(nil)

func NewVEXRuleRecommendationRepository(db *gorm.DB) *vexRuleRecommendationRepository {
	return &vexRuleRecommendationRepository{
		Repository: newGormRepository[string, models.VEXRuleRecommendation](db),
	}
}

func (r *vexRuleRecommendationRepository) FindByDependencyVulnIDs(ctx context.Context, tx *gorm.DB, dependencyVulnIDs []uuid.UUID) (map[uuid.UUID]models.VEXRuleRecommendation, error) {
	if len(dependencyVulnIDs) == 0 {
		return nil, nil
	}

	var recommendations []models.VEXRuleRecommendation
	err := r.GetDB(ctx, tx).
		Preload("VEXRule").
		Preload("UpstreamVEXRule").
		Where("dependency_vuln_id = ANY (?)", pq.Array(dependencyVulnIDs)).
		Find(&recommendations).Error
	if err != nil {
		return nil, err
	}

	result := make(map[uuid.UUID]models.VEXRuleRecommendation, len(recommendations))
	for _, recommendation := range recommendations {
		result[recommendation.DependencyVulnID] = recommendation
	}
	return result, nil
}

func (r *vexRuleRecommendationRepository) DeleteAll(ctx context.Context, tx *gorm.DB) error {
	return r.GetDB(ctx, tx).Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&models.VEXRuleRecommendation{}).Error
}

func (r *vexRuleRecommendationRepository) CreateBatch(ctx context.Context, tx *gorm.DB, recommendations []models.VEXRuleRecommendation) error {
	if len(recommendations) == 0 {
		return nil
	}
	return r.GetDB(ctx, tx).CreateInBatches(recommendations, 500).Error
}

type vexRuleRepository struct {
	db              *gorm.DB
	createBatchSize int
}

func NewVEXRuleRepository(db *gorm.DB) *vexRuleRepository {
	batchSize, err := database.CalcBatchSize(db, &models.VEXRule{})
	if err != nil {
		panic(fmt.Errorf("error calculating batch size: %w", err))
	}
	return &vexRuleRepository{
		db:              db,
		createBatchSize: batchSize,
	}
}

var _ shared.VEXRuleRepository = (*vexRuleRepository)(nil)

func (r *vexRuleRepository) GetDB(ctx context.Context, tx *gorm.DB) *gorm.DB {
	if tx != nil {
		return tx.Session(&gorm.Session{CreateBatchSize: r.createBatchSize})
	}
	return r.db.Session(&gorm.Session{Context: ctx, CreateBatchSize: r.createBatchSize})
}

func (r *vexRuleRepository) Begin(ctx context.Context) shared.DB {
	return r.GetDB(ctx, nil).Begin()
}

func (r *vexRuleRepository) All(ctx context.Context, tx *gorm.DB) ([]models.VEXRule, error) {
	var result []models.VEXRule

	err := r.GetDB(ctx, tx).Model(models.VEXRule{}).Preload("Asset").Find(&result).Error
	return result, err
}

func (r *vexRuleRepository) FindByAssetID(ctx context.Context, tx *gorm.DB, assetID uuid.UUID) ([]models.VEXRule, error) {
	var rules []models.VEXRule
	err := r.GetDB(ctx, tx).Where("asset_id = ?", assetID).Order("created_at DESC").Find(&rules).Error
	return rules, err
}

func (r *vexRuleRepository) FindByAssetIDs(ctx context.Context, tx *gorm.DB, assetIDs []uuid.UUID) ([]models.VEXRule, error) {
	if len(assetIDs) == 0 {
		return nil, nil
	}
	var rules []models.VEXRule
	err := r.GetDB(ctx, tx).Where("asset_id = ANY (?)", pq.Array(assetIDs)).Order("created_at DESC").Find(&rules).Error
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
