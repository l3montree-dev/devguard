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
	"github.com/lib/pq"
	"gorm.io/gorm"
)

type FrameworkControlRepository struct {
	db *gorm.DB
	utils.Repository[string, models.FrameworkControl, *gorm.DB]
}

func NewFrameworkControlRepository(db *gorm.DB) *FrameworkControlRepository {
	return &FrameworkControlRepository{
		db:         db,
		Repository: newGormRepository[string, models.FrameworkControl](db),
	}
}

func (r *FrameworkControlRepository) SaveScopeFramework(ctx context.Context, tx *gorm.DB, scopeFramework *models.ScopeFramework) error {
	return r.GetDB(ctx, tx).Transaction(func(tx *gorm.DB) error {
		var existing models.ScopeFramework
		result := tx.Where("org_id = ? AND project_id IS NOT DISTINCT FROM ? AND asset_id IS NOT DISTINCT FROM ? AND framework = ?", scopeFramework.OrgID, scopeFramework.ProjectID, scopeFramework.AssetID, scopeFramework.Framework).
			Limit(1).Find(&existing)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 0 {
			return tx.Create(scopeFramework).Error
		}

		previousHashes, err := linkedControlHashes(tx, existing.ID)
		if err != nil {
			return err
		}

		scopeFramework.ID = existing.ID
		if err := tx.Model(&existing).Association("Controls").Replace(scopeFramework.Controls); err != nil {
			return err
		}
		return deleteOrphanedControls(tx, previousHashes)
	})
}

func (r *FrameworkControlRepository) DeleteScopeFramework(ctx context.Context, tx *gorm.DB, orgID uuid.UUID, projectID *uuid.UUID, assetID *uuid.UUID, framework string) (bool, error) {
	deleted := false
	err := r.GetDB(ctx, tx).Transaction(func(tx *gorm.DB) error {
		var scopeFramework models.ScopeFramework
		result := tx.Where("org_id = ? AND project_id IS NOT DISTINCT FROM ? AND asset_id IS NOT DISTINCT FROM ? AND framework = ?", orgID, projectID, assetID, framework).
			Limit(1).Find(&scopeFramework)
		if result.Error != nil || result.RowsAffected == 0 {
			return result.Error
		}

		hashes, err := linkedControlHashes(tx, scopeFramework.ID)
		if err != nil {
			return err
		}

		// the links to the controls are removed by the database (cascade)
		if err := tx.Delete(&scopeFramework).Error; err != nil {
			return err
		}
		if err := deleteOrphanedControls(tx, hashes); err != nil {
			return err
		}

		deleted = true
		return nil
	})
	return deleted, err
}

func linkedControlHashes(tx *gorm.DB, scopeFrameworkID uuid.UUID) ([]string, error) {
	var hashes []string
	err := tx.Raw("SELECT control_hash FROM scope_framework_controls WHERE scope_framework_id = ?", scopeFrameworkID).Scan(&hashes).Error
	return hashes, err
}

func deleteOrphanedControls(tx *gorm.DB, hashes []string) error {
	if len(hashes) == 0 {
		return nil
	}

	var orphanedHashes []string
	if err := tx.Raw(`
		SELECT control_hash FROM compliance_controls cc
		WHERE cc.control_hash = ANY(?)
			AND NOT EXISTS (SELECT 1 FROM scope_framework_controls sfc WHERE sfc.control_hash = cc.control_hash)`,
		pq.Array(hashes),
	).Scan(&orphanedHashes).Error; err != nil {
		return err
	}
	if len(orphanedHashes) == 0 {
		return nil
	}

	if err := tx.Where("control_hash = ANY(?)", pq.Array(orphanedHashes)).Delete(&models.CompliancePosture{}).Error; err != nil {
		return err
	}
	return tx.Where("control_hash = ANY(?)", pq.Array(orphanedHashes)).Delete(&models.FrameworkControl{}).Error
}

func (r *FrameworkControlRepository) GetEffectiveScopeFrameworks(ctx context.Context, tx *gorm.DB, orgID uuid.UUID, projectID *uuid.UUID, assetID *uuid.UUID) ([]models.ScopeFramework, error) {
	var scopeFrameworks []models.ScopeFramework
	err := r.GetDB(ctx, tx).Raw(`
		WITH RECURSIVE project_chain AS (
			SELECT id, parent_id, 0 AS depth FROM projects WHERE id = @projectID
			UNION ALL
			SELECT p.id, p.parent_id, pc.depth + 1 FROM projects p JOIN project_chain pc ON p.id = pc.parent_id
		)
		SELECT DISTINCT ON (sf.framework) sf.*
		FROM scope_frameworks sf
		LEFT JOIN project_chain pc ON sf.project_id = pc.id
		WHERE sf.org_id = @orgID
			AND (
				(sf.project_id IS NULL AND sf.asset_id IS NULL)
				OR (sf.asset_id IS NULL AND pc.id IS NOT NULL)
				OR sf.asset_id = @assetID
			)
		ORDER BY sf.framework, sf.asset_id IS NULL, pc.depth ASC NULLS LAST`,
		map[string]any{"orgID": orgID, "projectID": projectID, "assetID": assetID},
	).Scan(&scopeFrameworks).Error
	return scopeFrameworks, err
}
