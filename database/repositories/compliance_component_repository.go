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
	"fmt"

	"github.com/google/uuid"

	"github.com/l3montree-dev/devguard/database"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/shared"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// scopeStatementToTenant restricts a statements query to the caller's org
// (and project/asset, when the request is scoped that granularly) by joining
// through compliance_postures, which is where the tenant columns actually
// live for this table.
func scopeStatementToTenant(ctx context.Context, db *gorm.DB) *gorm.DB {
	db = db.Joins("JOIN compliance_postures ON compliance_postures.id = compliance_component_implements_control_statements.compliance_posture_id")
	ids, ok := shared.OwnershipScopeFromCtx(ctx)
	if !ok {
		return db
	}
	db = db.Where("compliance_postures.org_id = ?", ids.OrgID)
	if ids.ProjectID != uuid.Nil {
		db = db.Where("compliance_postures.project_id = ?", ids.ProjectID)
	}
	if ids.AssetID != uuid.Nil {
		db = db.Where("compliance_postures.asset_id = ?", ids.AssetID)
	}
	return db
}

type ComplianceComponentRepository struct {
	db              *gorm.DB
	createBatchSize int
}

func NewComplianceComponentRepository(db *gorm.DB) *ComplianceComponentRepository {
	batchSize, err := database.CalcBatchSize(db, &models.ComplianceComponentImplementsControlStatement{})
	if err != nil {
		panic(fmt.Errorf("error calculating batch size: %w", err))
	}
	return &ComplianceComponentRepository{db: db, createBatchSize: batchSize}
}

func (r *ComplianceComponentRepository) GetDB(ctx context.Context, tx *gorm.DB) *gorm.DB {
	if tx != nil {
		return tx.Session(&gorm.Session{CreateBatchSize: r.createBatchSize})
	}
	return r.db.Session(&gorm.Session{Context: ctx, CreateBatchSize: r.createBatchSize})
}

const effectiveComponentsQuery = `
	WITH RECURSIVE project_chain AS (
		SELECT id, parent_id, 0 AS depth FROM projects WHERE id = @projectID
		UNION ALL
		SELECT p.id, p.parent_id, pc.depth + 1 FROM projects p JOIN project_chain pc ON p.id = pc.parent_id
	), effective_definitions AS (
		SELECT DISTINCT ON (cc.component_definition) cc.component_definition, cc.org_id, cc.project_id, cc.asset_id
		FROM compliance_components cc
		LEFT JOIN project_chain pc ON cc.project_id = pc.id
		WHERE cc.org_id = @orgID
			AND (
				(cc.project_id IS NULL AND cc.asset_id IS NULL)
				OR (cc.asset_id IS NULL AND pc.id IS NOT NULL)
				OR cc.asset_id = @assetID
			)
		ORDER BY cc.component_definition, cc.asset_id IS NULL, pc.depth ASC NULLS LAST
	)
	SELECT cc.id FROM compliance_components cc
	JOIN effective_definitions ed ON cc.component_definition = ed.component_definition
		AND cc.org_id = ed.org_id
		AND cc.project_id IS NOT DISTINCT FROM ed.project_id
		AND cc.asset_id IS NOT DISTINCT FROM ed.asset_id`

func (r *ComplianceComponentRepository) ListAll(ctx context.Context, tx *gorm.DB, orgID uuid.UUID, projectID *uuid.UUID, assetID *uuid.UUID, filter []shared.FilterQuery) ([]models.ComplianceComponent, error) {
	db := r.GetDB(ctx, tx).Where("id IN ("+effectiveComponentsQuery+")", map[string]any{"orgID": orgID, "projectID": projectID, "assetID": assetID})

	for _, f := range filter {
		switch {
		case f.Field == "frameworkControlId" && f.Operator == "is":
			db = db.Where("id IN (SELECT compliance_component_id FROM compliance_component_implements_controls WHERE framework_control_id = ?)", f.FieldValue)
		}
	}

	var components []models.ComplianceComponent
	err := db.Preload("ImplementedControls").Preload("ImplementedControls.ComplianceComponent").Find(&components).Error
	return components, err
}

func (r *ComplianceComponentRepository) GetDetails(ctx context.Context, tx *gorm.DB, orgID uuid.UUID, projectID *uuid.UUID, assetID *uuid.UUID, id uuid.UUID) (*models.ComplianceComponent, error) {
	var component models.ComplianceComponent
	err := r.GetDB(ctx, tx).
		Preload("ImplementedControls").
		Preload("ImplementedControls.ComplianceComponent").
		Where("id IN ("+effectiveComponentsQuery+")", map[string]any{"orgID": orgID, "projectID": projectID, "assetID": assetID}).
		Where("id = ?", id).
		First(&component).Error
	if err != nil {
		return nil, err
	}
	return &component, nil
}

func (r *ComplianceComponentRepository) SaveComponentDefinition(ctx context.Context, tx *gorm.DB, orgID uuid.UUID, projectID *uuid.UUID, assetID *uuid.UUID, componentDefinition string, components []models.ComplianceComponent) error {
	return r.GetDB(ctx, tx).Transaction(func(tx *gorm.DB) error {
		var existing []models.ComplianceComponent
		if err := tx.Where("org_id = ? AND project_id IS NOT DISTINCT FROM ? AND asset_id IS NOT DISTINCT FROM ? AND component_definition = ?", orgID, projectID, assetID, componentDefinition).
			Find(&existing).Error; err != nil {
			return err
		}
		existingByUUID := make(map[uuid.UUID]models.ComplianceComponent, len(existing))
		for _, c := range existing {
			existingByUUID[c.UUID] = c
		}

		keep := make([]uuid.UUID, 0, len(components))
		for _, component := range components {
			component.OrgID = &orgID
			component.ProjectID = projectID
			component.AssetID = assetID
			component.ComponentDefinition = &componentDefinition

			implementedControls := component.ImplementedControls
			component.ImplementedControls = nil

			if old, ok := existingByUUID[component.UUID]; ok {
				component.ID = old.ID
				if err := tx.Model(&component).Select("title", "description").Updates(&component).Error; err != nil {
					return err
				}
			} else if err := tx.Create(&component).Error; err != nil {
				return err
			}
			keep = append(keep, component.UUID)

			frameworkControlIDs := make([]string, 0, len(implementedControls))
			for i := range implementedControls {
				implementedControls[i].ComplianceComponentID = component.ID
				frameworkControlIDs = append(frameworkControlIDs, implementedControls[i].FrameworkControlID)
			}

			removedControls := tx.Where("compliance_component_id = ?", component.ID)
			if len(frameworkControlIDs) > 0 {
				removedControls = removedControls.Where("framework_control_id NOT IN ?", frameworkControlIDs)
			}
			if err := removedControls.Delete(&models.ComplianceComponentImplementsControl{}).Error; err != nil {
				return err
			}

			if len(implementedControls) > 0 {
				if err := tx.Clauses(clause.OnConflict{
					Columns:   []clause.Column{{Name: "framework_control_id"}, {Name: "compliance_component_id"}},
					DoUpdates: clause.AssignmentColumns([]string{"description"}),
				}).Create(&implementedControls).Error; err != nil {
					return err
				}
			}
		}

		removedComponents := tx.Where("org_id = ? AND project_id IS NOT DISTINCT FROM ? AND asset_id IS NOT DISTINCT FROM ? AND component_definition = ?", orgID, projectID, assetID, componentDefinition)
		if len(keep) > 0 {
			removedComponents = removedComponents.Where("uuid NOT IN ?", keep)
		}
		return removedComponents.Delete(&models.ComplianceComponent{}).Error
	})
}

func (r *ComplianceComponentRepository) DeleteComponentDefinition(ctx context.Context, tx *gorm.DB, orgID uuid.UUID, projectID *uuid.UUID, assetID *uuid.UUID, componentDefinition string) (bool, error) {
	result := r.GetDB(ctx, tx).
		Where("org_id = ? AND project_id IS NOT DISTINCT FROM ? AND asset_id IS NOT DISTINCT FROM ? AND component_definition = ?", orgID, projectID, assetID, componentDefinition).
		Delete(&models.ComplianceComponent{})
	return result.RowsAffected > 0, result.Error
}

func (r *ComplianceComponentRepository) CreateStatement(ctx context.Context, tx *gorm.DB, statement models.ComplianceComponentImplementsControlStatement) (*models.ComplianceComponentImplementsControlStatement, error) {
	db := r.GetDB(ctx, tx)
	if err := db.Create(&statement).Error; err != nil {
		return nil, err
	}
	if err := scopeStatementToTenant(ctx, db).
		Preload("ComplianceComponentImplementsControl.ComplianceComponent").
		Where("compliance_component_implements_control_statements.id = ?", statement.ID).
		First(&statement).Error; err != nil {
		return nil, err
	}
	return &statement, nil
}

func (r *ComplianceComponentRepository) UpdateStatement(ctx context.Context, tx *gorm.DB, statementID uuid.UUID, implementationStatus string, description string) (*models.ComplianceComponentImplementsControlStatement, error) {
	var statement models.ComplianceComponentImplementsControlStatement
	db := r.GetDB(ctx, tx)
	if err := scopeStatementToTenant(ctx, db).
		Preload("ComplianceComponentImplementsControl.ComplianceComponent").
		Where("compliance_component_implements_control_statements.id = ?", statementID).
		First(&statement).Error; err != nil {
		return nil, err
	}

	statement.ImplementationStatus = implementationStatus
	statement.Description = description

	if err := db.Save(&statement).Error; err != nil {
		return nil, err
	}
	return &statement, nil
}

func (r *ComplianceComponentRepository) DeleteStatement(ctx context.Context, tx *gorm.DB, statementID uuid.UUID) (*models.ComplianceComponentImplementsControlStatement, error) {
	db := r.GetDB(ctx, tx)

	var statement models.ComplianceComponentImplementsControlStatement
	if err := scopeStatementToTenant(ctx, db).
		Where("compliance_component_implements_control_statements.id = ?", statementID).
		First(&statement).Error; err != nil {
		return nil, err
	}

	if err := db.Delete(&statement).Error; err != nil {
		return nil, err
	}
	return &statement, nil
}
