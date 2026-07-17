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
	db *gorm.DB
}

func NewComplianceComponentRepository(db *gorm.DB) *ComplianceComponentRepository {
	return &ComplianceComponentRepository{db: db}
}

func (r *ComplianceComponentRepository) GetDB(ctx context.Context, tx *gorm.DB) *gorm.DB {
	if tx != nil {
		return tx
	}
	return r.db.WithContext(ctx)
}

func (r *ComplianceComponentRepository) ListAll(ctx context.Context, tx *gorm.DB, filter []shared.FilterQuery) ([]models.ComplianceComponent, error) {
	db := r.GetDB(ctx, tx)

	for _, f := range filter {
		switch {
		case f.Field == "frameworkControlId" && f.Operator == "is":
			db = db.Where("uuid IN (SELECT compliance_component_id FROM compliance_component_implements_controls WHERE framework_control_id = ?)", f.Value())
		}
	}

	var components []models.ComplianceComponent
	err := db.Preload("ImplementedControls").Preload("ImplementedControls.ComplianceComponent").Find(&components).Error
	return components, err
}

func (r *ComplianceComponentRepository) GetDetails(ctx context.Context, tx *gorm.DB, id uuid.UUID) (*models.ComplianceComponent, error) {
	var component models.ComplianceComponent
	err := r.GetDB(ctx, tx).
		Preload("ImplementedControls").
		Preload("ImplementedControls.ComplianceComponent").
		Where("uuid = ?", id).
		First(&component).Error
	if err != nil {
		return nil, err
	}
	return &component, nil
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
		Preload("ComplianceComponentImplementsControl.ComplianceComponent").
		Where("compliance_component_implements_control_statements.id = ?", statementID).
		First(&statement).Error; err != nil {
		return nil, err
	}

	if err := db.Delete(&statement).Error; err != nil {
		return nil, err
	}
	return &statement, nil
}
