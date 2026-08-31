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

func (r *vexRuleRecommendationRepository) FindByDependencyVulnID(ctx context.Context, tx *gorm.DB, dependencyVulnID uuid.UUID) (models.VEXRuleRecommendation, error) {

	var recommendation models.VEXRuleRecommendation
	err := r.GetDB(ctx, tx).
		Preload("VEXRule").
		Preload("UpstreamVEXRule").
		Where("dependency_vuln_id = ?", dependencyVulnID).
		First(&recommendation).Error
	if err != nil {
		return models.VEXRuleRecommendation{}, err
	}

	return recommendation, nil
}

func (r *vexRuleRecommendationRepository) FindByDependencyVulnIDsAndVexRuleIDsPaged(ctx context.Context, tx *gorm.DB, dependencyVulnIDs []uuid.UUID, vexRuleIDs []string, pageInfo shared.PageInfo, search string, filterQuery []shared.FilterQuery, sortQuery []shared.SortQuery) (shared.Paged[models.VEXRuleRecommendation], error) {
	if len(dependencyVulnIDs) == 0 && len(vexRuleIDs) == 0 {
		return shared.NewPaged(pageInfo, 0, []models.VEXRuleRecommendation{}), nil
	}

	db := r.GetDB(ctx, tx)

	const ruleColumns = `title, justification, mechanical_justification, event_type,
		cve_scope, vex_source`

	byVuln := db.Model(&models.VEXRuleRecommendation{}).
		Select(`vex_rule_recommendations.dependency_vuln_id,
			vex_rule_recommendations.vex_rule_id,
			vex_rule_recommendations.upstream_vex_rule_id,
			vex_rule_recommendations.verified_votes,
			vex_rule_recommendations.total_votes,
			vex_rule_recommendations.confidence,
			vex_rule_recommendations.dependency_vuln_signature,
			COALESCE(vex_rules.title, upstream_vex_rules.title) AS title,
			COALESCE(vex_rules.justification, upstream_vex_rules.justification) AS justification,
			COALESCE(vex_rules.mechanical_justification, upstream_vex_rules.mechanical_justification) AS mechanical_justification,
			COALESCE(vex_rules.event_type, upstream_vex_rules.event_type) AS event_type,
			COALESCE(vex_rules.cve_scope, upstream_vex_rules.cve_scope) AS cve_scope,
			COALESCE(vex_rules.vex_source, upstream_vex_rules.vex_source) AS vex_source`).
		Joins("LEFT JOIN vex_rules ON vex_rules.id = vex_rule_recommendations.vex_rule_id").
		Joins("LEFT JOIN upstream_vex_rules ON upstream_vex_rules.id = vex_rule_recommendations.upstream_vex_rule_id").
		Where("vex_rule_recommendations.dependency_vuln_id = ANY (?)", pq.Array(dependencyVulnIDs))

	byRule := db.Table("vex_rules").
		Select(`'00000000-0000-0000-0000-000000000000'::uuid AS dependency_vuln_id,
			id AS vex_rule_id,
			NULL::text AS upstream_vex_rule_id,
			0 AS verified_votes,
			0 AS total_votes,
			1 AS confidence,
			0 AS dependency_vuln_signature,
			`+ruleColumns).
		Where("id = ANY (?)", pq.Array(vexRuleIDs))

	var union *gorm.DB
	switch {
	case len(vexRuleIDs) == 0:
		union = byVuln
	case len(dependencyVulnIDs) == 0:
		union = byRule
	default:
		union = db.Raw("? UNION ?", byVuln, byRule)
	}

	var recommendations []models.VEXRuleRecommendation
	var total int64

	query := db.Model(&models.VEXRuleRecommendation{}).Table("(?) AS vex_rule_recommendations", union)

	if search != "" {
		searchPattern := "%" + search + "%"
		query = query.Where("cve_scope ILIKE ? OR title ILIKE ? OR justification ILIKE ?",
			searchPattern, searchPattern, searchPattern)
	}

	// Apply filter queries
	for _, filter := range filterQuery {
		query = filter.Where(query)
	}

	// Count total before pagination
	if err := query.Count(&total).Error; err != nil {
		return shared.Paged[models.VEXRuleRecommendation]{}, err
	}

	// Apply sorting
	if len(sortQuery) > 0 {
		for _, sort := range sortQuery {
			query = sort.Order(query)
		}
	} else {
		query = query.Order("confidence DESC")
	}

	// Apply pagination
	query = pageInfo.ApplyOnDB(query)

	if err := query.Preload("VEXRule").Preload("UpstreamVEXRule").Find(&recommendations).Error; err != nil {
		return shared.Paged[models.VEXRuleRecommendation]{}, err
	}

	return shared.NewPaged(pageInfo, total, recommendations), nil
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
		query = query.Where("cve_scope ILIKE ? OR title ILIKE ? OR justification ILIKE ?", searchPattern, searchPattern, searchPattern)
	}

	// Apply filter queries
	for _, filter := range filterQuery {
		query = filter.Where(query)
	}

	// Count total before pagination
	if err := query.Count(&total).Error; err != nil {
		return shared.Paged[models.VEXRule]{}, err
	}

	// Apply sorting
	if len(sortQuery) > 0 {
		for _, sort := range sortQuery {
			query = sort.Order(query)
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
