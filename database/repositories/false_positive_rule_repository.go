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
	"github.com/l3montree-dev/devguard/utils"
	"gorm.io/gorm"
)

type falsePositiveRuleRepository struct {
	db *gorm.DB
	utils.Repository[uuid.UUID, models.FalsePositiveRule, *gorm.DB]
}

func NewFalsePositiveRuleRepository(db *gorm.DB) *falsePositiveRuleRepository {
	return &falsePositiveRuleRepository{
		db:         db,
		Repository: newGormRepository[uuid.UUID, models.FalsePositiveRule](db),
	}
}

func (r *falsePositiveRuleRepository) FindByAssetID(db *gorm.DB, assetID uuid.UUID) ([]models.FalsePositiveRule, error) {
	var rules []models.FalsePositiveRule
	err := r.GetDB(db).Where("asset_id = ?", assetID).Order("created_at DESC").Find(&rules).Error
	return rules, err
}

func (r *falsePositiveRuleRepository) Create(db *gorm.DB, rule *models.FalsePositiveRule) error {
	return r.GetDB(db).Create(rule).Error
}

func (r *falsePositiveRuleRepository) Update(db *gorm.DB, rule *models.FalsePositiveRule) error {
	return r.GetDB(db).Save(rule).Error
}

func (r *falsePositiveRuleRepository) Delete(db *gorm.DB, id uuid.UUID) error {
	return r.GetDB(db).Delete(&models.FalsePositiveRule{}, id).Error
}
