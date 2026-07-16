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
	"github.com/l3montree-dev/devguard/utils"
	"gorm.io/gorm"
)

type FrameworkControlRepository struct {
	db *gorm.DB
	utils.Repository[uuid.UUID, models.FrameworkControl, *gorm.DB]
}

func NewFrameworkControlRepository(db *gorm.DB) *FrameworkControlRepository {
	return &FrameworkControlRepository{
		db:         db,
		Repository: newGormRepository[uuid.UUID, models.FrameworkControl](db),
	}
}

func (r *FrameworkControlRepository) GetAll(ctx context.Context, tx *gorm.DB, framework *string) ([]models.FrameworkControl, error) {
	var frameworkControls []models.FrameworkControl
	query := r.GetDB(ctx, tx).Preload("MappedControls")
	if framework != nil {
		query = query.Where("framework = ?", *framework).Or("framework_control_id IN (SELECT framework_control_id FROM mapped_controls WHERE related_framework = ?)", *framework)
	}
	if err := query.Find(&frameworkControls).Error; err != nil {
		return nil, err
	}
	return frameworkControls, nil
}

// ListFrameworkControls returns the unique set of framework names
func (r *FrameworkControlRepository) ListFrameworkControls(ctx context.Context, tx *gorm.DB) ([]string, error) {
	var frameworks []string
	query := r.GetDB(ctx, tx).Raw(`
		SELECT DISTINCT framework FROM frameworks_controls
		UNION
		SELECT DISTINCT related_framework FROM mapped_controls
		ORDER BY framework
	`)
	if err := query.Scan(&frameworks).Error; err != nil {
		return nil, err
	}
	return frameworks, nil
}
