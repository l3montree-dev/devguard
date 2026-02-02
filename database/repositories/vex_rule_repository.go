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
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
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

func (r *vexRuleRepository) GetDB(db *gorm.DB) *gorm.DB {
	if db != nil {
		return db
	}
	return r.db
}

func (r *vexRuleRepository) FindByAssetID(db *gorm.DB, assetID uuid.UUID) ([]models.VEXRule, error) {
	var rules []models.VEXRule
	err := r.GetDB(db).Where("asset_id = ?", assetID).Order("created_at DESC").Find(&rules).Error
	return rules, err
}

func (r *vexRuleRepository) FindByCompositeKey(db *gorm.DB, assetID uuid.UUID, cveID, pathPatternHash, vexSource string) (models.VEXRule, error) {
	var rule models.VEXRule
	err := r.GetDB(db).
		Where("asset_id = ? AND cve_id = ? AND path_pattern_hash = ? AND vex_source = ?",
			assetID, cveID, pathPatternHash, vexSource).
		First(&rule).Error
	return rule, err
}

func (r *vexRuleRepository) Create(db *gorm.DB, rule *models.VEXRule) error {
	// Ensure the hash is computed
	if rule.PathPatternHash == "" {
		rule.SetPathPattern(rule.PathPattern)
	}
	return r.GetDB(db).Create(rule).Error
}

func (r *vexRuleRepository) Upsert(db *gorm.DB, rule *models.VEXRule) error {
	// Ensure the hash is computed
	if rule.PathPatternHash == "" {
		rule.SetPathPattern(rule.PathPattern)
	}
	return r.GetDB(db).Clauses(clause.OnConflict{
		Columns: []clause.Column{
			{Name: "asset_id"},
			{Name: "cve_id"},
			{Name: "path_pattern_hash"},
			{Name: "vex_source"},
		},
		DoUpdates: clause.AssignmentColumns([]string{
			"justification",
			"mechanical_justification",
			"event_type",
			"path_pattern",
			"created_by_id",
			"updated_at",
		}),
	}).Create(rule).Error
}

func (r *vexRuleRepository) Update(db *gorm.DB, rule *models.VEXRule) error {
	// Ensure the hash is computed
	if rule.PathPatternHash == "" {
		rule.SetPathPattern(rule.PathPattern)
	}
	return r.GetDB(db).Save(rule).Error
}

func (r *vexRuleRepository) Delete(db *gorm.DB, rule models.VEXRule) error {
	return r.GetDB(db).
		Where("asset_id = ? AND cve_id = ? AND path_pattern_hash = ? AND vex_source = ?",
			rule.AssetID, rule.CVEID, rule.PathPatternHash, rule.VexSource).
		Delete(&models.VEXRule{}).Error
}

func (r *vexRuleRepository) DeleteByAssetID(db *gorm.DB, assetID uuid.UUID) error {
	return r.GetDB(db).Where("asset_id = ?", assetID).Delete(&models.VEXRule{}).Error
}

func (r *vexRuleRepository) FindByAssetAndVexSource(db *gorm.DB, assetID uuid.UUID, vexSource string) ([]models.VEXRule, error) {
	var rules []models.VEXRule
	err := r.GetDB(db).Where("asset_id = ? AND vex_source = ?", assetID, vexSource).Find(&rules).Error
	return rules, err
}

func (r *vexRuleRepository) UpsertBatch(db *gorm.DB, rules []models.VEXRule) error {
	if len(rules) == 0 {
		return nil
	}
	// Ensure hashes are computed
	for i := range rules {
		if rules[i].PathPatternHash == "" {
			rules[i].SetPathPattern(rules[i].PathPattern)
		}
	}
	return r.GetDB(db).Clauses(clause.OnConflict{
		Columns: []clause.Column{
			{Name: "asset_id"},
			{Name: "cve_id"},
			{Name: "path_pattern_hash"},
			{Name: "vex_source"},
		},
		DoUpdates: clause.AssignmentColumns([]string{
			"justification",
			"mechanical_justification",
			"event_type",
			"path_pattern",
			"created_by_id",
			"updated_at",
		}),
	}).Create(&rules).Error
}

func (r *vexRuleRepository) DeleteBatch(db *gorm.DB, rules []models.VEXRule) error {
	if len(rules) == 0 {
		return nil
	}
	// Delete by composite key for each rule
	tx := r.GetDB(db)
	for _, rule := range rules {
		if err := tx.Where("asset_id = ? AND cve_id = ? AND path_pattern_hash = ? AND vex_source = ?",
			rule.AssetID, rule.CVEID, rule.PathPatternHash, rule.VexSource).
			Delete(&models.VEXRule{}).Error; err != nil {
			return err
		}
	}
	return nil
}
