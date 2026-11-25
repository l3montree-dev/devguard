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
	"fmt"
	"reflect"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/statemachine"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/lib/pq"
	"gorm.io/gorm"
)

type CompliancePostureRepository struct {
	db *gorm.DB
	utils.Repository[uuid.UUID, models.CompliancePosture, *gorm.DB]
}

type frameworkControlPostureRow struct {
	models.FrameworkControl
	Frameworks          pq.StringArray                                         `gorm:"column:frameworks;type:text[]"`
	FrameworkControlIDs pq.StringArray                                         `gorm:"column:framework_control_ids;type:text[]"`
	CompliancePostureID *uuid.UUID                                             `gorm:"column:id"`
	State               dtos.VulnState                                         `gorm:"column:state"`
	OrgID               *uuid.UUID                                             `gorm:"column:org_id"`
	ProjectID           *uuid.UUID                                             `gorm:"column:project_id"`
	AssetID             *uuid.UUID                                             `gorm:"column:asset_id"`
	AssetVersionName    *string                                                `gorm:"column:asset_version_name"`
	Events              []models.VulnEvent                                     `gorm:"foreignKey:CompliancePostureID;references:CompliancePostureID"`
	ByComponents        []models.ComplianceComponentImplementsControlStatement `gorm:"foreignKey:CompliancePostureID;references:CompliancePostureID"`
}

// nosemgrep: repo-method-missing-ctx, repo-method-missing-ctx-empty-params
func (row frameworkControlPostureRow) compliancePostureIDString() string {
	if row.CompliancePostureID == nil {
		return ""
	}
	return row.CompliancePostureID.String()
}

// nosemgrep: repo-method-missing-ctx, repo-method-missing-ctx-empty-params
func (row frameworkControlPostureRow) toDTO() dtos.CompliancePostureWithControl {
	return dtos.CompliancePostureWithControl{
		ControlHash:         row.ControlHash,
		FrameworkControlIDs: row.FrameworkControlIDs,
		Frameworks:          row.Frameworks,
		ControlID:           row.ControlID,
		Title:               row.Title,
		Description:         row.Description,
		Importance:          row.Importance,
		SecurityLevel:       row.SecurityLevel,
		Class:               row.Class,
		Additional:          row.Additional,
		ParentControlID:     row.ParentControlID,
		CompliancePostureID: row.compliancePostureIDString(),
		State:               row.State,
		OrgID:               row.OrgID,
		ProjectID:           row.ProjectID,
		AssetID:             row.AssetID,
		AssetVersionName:    row.AssetVersionName,
	}
}

// nosemgrep: repo-method-missing-ctx, repo-method-missing-ctx-empty-params
func (row frameworkControlPostureRow) toDetailsDTO() dtos.CompliancePostureWithDetails {
	dto := dtos.CompliancePostureWithDetails{
		CompliancePostureWithControl: row.toDTO(),
	}
	for _, ev := range row.Events {
		dto.Events = append(dto.Events, transformer.ConvertVulnEventToDto(ev))
	}
	for _, bc := range row.ByComponents {
		dto.ByComponents = append(dto.ByComponents, transformer.ComplianceComponentImplementsControlStatementToDTO(bc))
	}
	return dto
}

func NewCompliancePostureRepository(db *gorm.DB) *CompliancePostureRepository {
	return &CompliancePostureRepository{
		db:         db,
		Repository: newGormRepository[uuid.UUID, models.CompliancePosture](db),
	}
}

func (r *CompliancePostureRepository) controlPostureQuery(ctx context.Context, tx *gorm.DB, scopeFrameworkIDs []uuid.UUID, assetVersionID *uuid.UUID, assetID *uuid.UUID, projectID *uuid.UUID, orgID uuid.UUID) *gorm.DB {
	frameworksByControl := r.GetDB(ctx, tx).Table("scope_framework_controls sfc").
		Select("sfc.control_hash, array_agg(DISTINCT sf.framework ORDER BY sf.framework) AS frameworks").
		Joins("JOIN scope_frameworks sf ON sf.id = sfc.scope_framework_id").
		Where("sfc.scope_framework_id = ANY(?)", pq.Array(scopeFrameworkIDs)).
		Group("sfc.control_hash")

	return r.GetDB(ctx, tx).Table("(?) AS fw", frameworksByControl).
		Select(`cc.control_hash,
			cc.title,
			cc.description,
			cc.importance,
			cc.security_level,
			cc.class,
			cc.additional,
			cc.parent_control_id,
			cc.control_id,
			fw.frameworks,
			ARRAY(SELECT f || ':' || cc.control_id FROM unnest(fw.frameworks) AS f) AS framework_control_ids,
			COALESCE(cp_asset.id, cp_project.id, cp_org.id) AS id,
			COALESCE(cp_asset.state, cp_project.state, cp_org.state) AS state,
			COALESCE(cp_asset.org_id, cp_project.org_id, cp_org.org_id) AS org_id,
			COALESCE(cp_asset.project_id, cp_project.project_id, cp_org.project_id) AS project_id,
			COALESCE(cp_asset.asset_id, cp_project.asset_id, cp_org.asset_id) AS asset_id,
			COALESCE(cp_asset.asset_version_name, cp_project.asset_version_name, cp_org.asset_version_name) AS asset_version_name`).
		Joins("JOIN compliance_controls cc ON cc.control_hash = fw.control_hash").
		Joins(`LEFT JOIN compliance_postures cp_asset
			ON cc.control_hash = cp_asset.control_hash
			AND cp_asset.org_id = ?
			AND cp_asset.project_id IS NOT DISTINCT FROM ?
			AND cp_asset.asset_id IS NOT DISTINCT FROM ?
			AND cp_asset.asset_version_id IS NOT DISTINCT FROM ?`, orgID, projectID, assetID, assetVersionID).
		Joins(`LEFT JOIN compliance_postures cp_project
			ON cc.control_hash = cp_project.control_hash
			AND cp_project.org_id = ?
			AND cp_project.project_id IS NOT DISTINCT FROM ?
			AND cp_project.asset_id IS NULL
			AND cp_project.asset_version_id IS NULL`, orgID, projectID).
		Joins(`LEFT JOIN compliance_postures cp_org
			ON cc.control_hash = cp_org.control_hash
			AND cp_org.org_id = ?
			AND cp_org.project_id IS NULL
			AND cp_org.asset_id IS NULL
			AND cp_org.asset_version_id IS NULL`, orgID)
}

func frameworkFilterCondition(f shared.FilterQuery) (string, any) {
	if f.Operator == "ilike" {
		return "EXISTS (SELECT 1 FROM unnest(frameworks) AS framework WHERE framework ILIKE ?)", f.FieldValue
	}

	values := pq.Array([]any{f.FieldValue})
	if v := reflect.ValueOf(f.FieldValue); v.IsValid() && v.Kind() == reflect.Slice {
		values = pq.Array(f.FieldValue)
	}
	if f.Operator == "is not" {
		return "NOT (frameworks && ?::text[])", values
	}
	return "frameworks && ?::text[]", values
}

func componentCoverageCondition(orgID uuid.UUID, projectID *uuid.UUID, assetID *uuid.UUID) (string, map[string]any) {
	return `EXISTS (SELECT 1 FROM compliance_component_implements_controls cic
			WHERE cic.framework_control_id = ANY (sub.framework_control_ids)
				AND cic.compliance_component_id IN (` + effectiveComponentsQuery + `))`,
		map[string]any{"orgID": orgID, "projectID": projectID, "assetID": assetID}
}

func (r *CompliancePostureRepository) FindOrCreate(ctx context.Context, tx *gorm.DB, posture models.CompliancePosture) (*models.CompliancePosture, error) {
	var existingPosture models.CompliancePosture
	db := withOwnershipScope(ctx, r.GetDB(ctx, tx).Where("id = ?", posture.ID), existingPosture)
	if err := db.Preload("FrameworkControl").
		Preload("ByComponents.ComplianceComponentImplementsControl.ComplianceComponent").
		First(&existingPosture).Error; err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("failed to query compliance posture: %w", err)
		}
		newPosture := models.CompliancePosture{
			Vulnerability:    models.Vulnerability{ID: posture.ID, State: posture.State},
			ControlHash:      posture.ControlHash,
			OrgID:            posture.OrgID,
			ProjectID:        posture.ProjectID,
			AssetID:          posture.AssetID,
			AssetVersionID:   posture.AssetVersionID,
			AssetVersionName: posture.AssetVersionName,
		}
		if err := r.GetDB(ctx, tx).Create(&newPosture).Error; err != nil {
			return nil, fmt.Errorf("failed to create compliance posture: %w", err)
		}
		if err := r.GetDB(ctx, tx).Where("control_hash = ?", newPosture.ControlHash).First(&newPosture.FrameworkControl).Error; err != nil {
			return nil, fmt.Errorf("failed to load framework control for new compliance posture: %w", err)
		}
		return &newPosture, nil
	}
	return &existingPosture, nil
}

func (r *CompliancePostureRepository) ApplyAndSave(ctx context.Context, tx *gorm.DB, posture *models.CompliancePosture, ev *models.VulnEvent) error {
	if tx == nil {
		return r.Transaction(ctx, func(d *gorm.DB) error {
			return r.applyAndSave(ctx, d, posture, ev)
		})
	}
	return r.applyAndSave(ctx, tx, posture, ev)
}

func (r *CompliancePostureRepository) applyAndSave(ctx context.Context, tx *gorm.DB, posture *models.CompliancePosture, ev *models.VulnEvent) error {
	statemachine.Apply(posture, *ev)
	if err := r.Save(ctx, tx, posture); err != nil {
		return err
	}
	if err := r.GetDB(ctx, tx).Save(ev).Error; err != nil {
		return err
	}
	posture.Events = append(posture.Events, *ev)
	return nil
}

func (r *CompliancePostureRepository) GetForAllControlsPaged(ctx context.Context, tx *gorm.DB, scopeFrameworkIDs []uuid.UUID, assetVersionID *uuid.UUID, assetID *uuid.UUID, projectID *uuid.UUID, orgID uuid.UUID, pageInfo shared.PageInfo, search string, filter []shared.FilterQuery, sort []shared.SortQuery) (shared.Paged[dtos.CompliancePostureWithControl], error) {
	var postures []dtos.CompliancePostureWithControl
	var count int64

	query := r.controlPostureQuery(ctx, tx, scopeFrameworkIDs, assetVersionID, assetID, projectID, orgID)

	if search != "" {
		query = query.Where("(cc.title ILIKE ? OR cc.control_id ILIKE ? OR array_to_string(fw.frameworks, ',') ILIKE ?)", "%"+search+"%", "%"+search+"%", "%"+search+"%")
	}

	subquery := r.GetDB(ctx, tx).Table("(?) AS sub", query)

	for _, f := range filter {
		group := r.GetDB(ctx, tx)
		switch {
		case f.Field == "state" && f.FieldValue == "open" && f.Operator == "is":
			subquery = subquery.Where(f.Where(group).Or("state IS NULL"))
		case f.Field == "state" && f.FieldValue == "open" && f.Operator == "is not":
			subquery = f.Where(subquery).Where("state IS NOT NULL")
		case f.Field == "framework":
			condition, values := frameworkFilterCondition(f)
			subquery = subquery.Where(condition, values)
		case f.Field == "has_component_coverage" && f.Operator == "is":
			condition, args := componentCoverageCondition(orgID, projectID, assetID)
			if fmt.Sprint(f.FieldValue) == "true" {
				subquery = subquery.Where(condition, args)
			} else {
				subquery = subquery.Where("NOT "+condition, args)
			}
		default:
			subquery = f.Where(subquery)
		}
	}

	for _, s := range sort {
		subquery = s.Order(subquery)
	}

	if err := subquery.Count(&count).Error; err != nil {
		return shared.Paged[dtos.CompliancePostureWithControl]{}, err
	}

	var rows []frameworkControlPostureRow
	if err := subquery.Model(&frameworkControlPostureRow{}).
		Offset((pageInfo.Page - 1) * pageInfo.PageSize).
		Limit(pageInfo.PageSize).
		Find(&rows).Error; err != nil {
		return shared.Paged[dtos.CompliancePostureWithControl]{}, err
	}

	postures = make([]dtos.CompliancePostureWithControl, len(rows))

	for i, row := range rows {
		postures[i] = row.toDTO()
	}

	return shared.NewPaged(pageInfo, count, postures), nil
}

func (r *CompliancePostureRepository) GetAllControls(ctx context.Context, tx *gorm.DB, scopeFrameworkIDs []uuid.UUID, assetVersionID *uuid.UUID, assetID *uuid.UUID, projectID *uuid.UUID, orgID uuid.UUID, search string, filter []shared.FilterQuery, sort []shared.SortQuery) ([]dtos.CompliancePostureWithDetails, error) {
	var postures []dtos.CompliancePostureWithDetails

	query := r.controlPostureQuery(ctx, tx, scopeFrameworkIDs, assetVersionID, assetID, projectID, orgID)

	if search != "" {
		query = query.Where("(cc.title ILIKE ? OR cc.control_id ILIKE ? OR array_to_string(fw.frameworks, ',') ILIKE ?)", "%"+search+"%", "%"+search+"%", "%"+search+"%")
	}

	subquery := r.GetDB(ctx, tx).Table("(?) AS sub", query)

	for _, f := range filter {
		group := r.GetDB(ctx, tx)
		switch {
		case f.Field == "state" && f.FieldValue == "open" && f.Operator == "is":
			subquery = subquery.Where(f.Where(group).Or("state IS NULL"))
		case f.Field == "state" && f.FieldValue == "open" && f.Operator == "is not":
			subquery = f.Where(subquery).Where("state IS NOT NULL")
		case f.Field == "framework":
			condition, values := frameworkFilterCondition(f)
			subquery = subquery.Where(condition, values)
		case f.Field == "has_component_coverage" && f.Operator == "is":
			condition, args := componentCoverageCondition(orgID, projectID, assetID)
			if fmt.Sprint(f.FieldValue) == "true" {
				subquery = subquery.Where(condition, args)
			} else {
				subquery = subquery.Where("NOT "+condition, args)
			}
		default:
			subquery = f.Where(subquery)
		}
	}

	for _, s := range sort {
		subquery = s.Order(subquery)
	}

	var rows []frameworkControlPostureRow
	if err := subquery.Model(&frameworkControlPostureRow{}).
		Preload("Events").
		Preload("ByComponents.ComplianceComponentImplementsControl.ComplianceComponent").
		Find(&rows).Error; err != nil {
		return nil, err
	}

	postures = make([]dtos.CompliancePostureWithDetails, len(rows))
	for i, row := range rows {
		postures[i] = row.toDetailsDTO()
	}

	return postures, nil
}

func (r *CompliancePostureRepository) GetStatsForAllControls(ctx context.Context, tx *gorm.DB, scopeFrameworkIDs []uuid.UUID, assetVersionID *uuid.UUID, assetID *uuid.UUID, projectID *uuid.UUID, orgID uuid.UUID, filter []shared.FilterQuery) (dtos.CompliancePostureStats, error) {
	type row struct {
		State *string `gorm:"column:state"`
		Count int64   `gorm:"column:count"`
	}
	var rows []row

	query := r.controlPostureQuery(ctx, tx, scopeFrameworkIDs, assetVersionID, assetID, projectID, orgID)

	subquery := r.GetDB(ctx, tx).Table("(?) AS sub", query)
	// Only the "framework" filter applies here (if present)
	for _, f := range filter {
		if f.Field == "framework" {
			condition, values := frameworkFilterCondition(f)
			subquery = subquery.Where(condition, values)
		}
	}

	if err := subquery.Select("state, COUNT(*) AS count").Group("state").Scan(&rows).Error; err != nil {
		return dtos.CompliancePostureStats{}, err
	}

	var stats dtos.CompliancePostureStats
	for _, row := range rows {
		switch {
		case row.State == nil:
			stats.Open += row.Count
		case *row.State == string(dtos.VulnStateOpen):
			stats.Open += row.Count
		case *row.State == string(dtos.VulnStateImplemented):
			stats.Implemented = row.Count
		case *row.State == string(dtos.VulnStateNotApplicable):
			stats.NotApplicable = row.Count
		}
	}
	return stats, nil
}

func (r *CompliancePostureRepository) GetForControl(ctx context.Context, tx *gorm.DB, scopeFrameworkIDs []uuid.UUID, controlHash string, assetVersionID *uuid.UUID, assetID *uuid.UUID, projectID *uuid.UUID, orgID uuid.UUID) (*models.CompliancePosture, error) {
	type row struct {
		ID *uuid.UUID `gorm:"column:id"`
	}
	var result row

	err := r.GetDB(ctx, tx).Model(&models.FrameworkControl{}).
		Select(`COALESCE(cp_asset.id, cp_project.id, cp_org.id) AS id`).
		Joins(`LEFT JOIN compliance_postures cp_asset
			ON compliance_controls.control_hash = cp_asset.control_hash
			AND cp_asset.org_id = ?
			AND cp_asset.project_id IS NOT DISTINCT FROM ?
			AND cp_asset.asset_id IS NOT DISTINCT FROM ?
			AND cp_asset.asset_version_id IS NOT DISTINCT FROM ?`, orgID, projectID, assetID, assetVersionID).
		Joins(`LEFT JOIN compliance_postures cp_project
			ON compliance_controls.control_hash = cp_project.control_hash
			AND cp_project.org_id = ?
			AND cp_project.project_id IS NOT DISTINCT FROM ?
			AND cp_project.asset_id IS NULL
			AND cp_project.asset_version_id IS NULL`, orgID, projectID).
		Joins(`LEFT JOIN compliance_postures cp_org
			ON compliance_controls.control_hash = cp_org.control_hash
			AND cp_org.org_id = ?
			AND cp_org.project_id IS NULL
			AND cp_org.asset_id IS NULL
			AND cp_org.asset_version_id IS NULL`, orgID).
		Where("compliance_controls.control_hash = ?", controlHash).
		Scan(&result).Error
	if err != nil {
		return nil, err
	}

	var posture models.CompliancePosture
	if result.ID != nil {
		if err := r.GetDB(ctx, tx).
			Preload("FrameworkControl.ScopeFrameworks", "scope_frameworks.id = ANY(?)", pq.Array(scopeFrameworkIDs)).
			Preload("Events").
			Preload("ByComponents.ComplianceComponentImplementsControl.ComplianceComponent").
			Where("compliance_postures.id = ?", result.ID).
			First(&posture).Error; err != nil {
			return nil, err
		}
	} else {
		// No posture exists at any scope — return an empty posture with just the control loaded.
		posture.ControlHash = controlHash
		if err := r.GetDB(ctx, tx).
			Preload("ScopeFrameworks", "scope_frameworks.id = ANY(?)", pq.Array(scopeFrameworkIDs)).
			Where("control_hash = ?", controlHash).
			First(&posture.FrameworkControl).Error; err != nil {
			return nil, err
		}
	}

	if len(posture.FrameworkControl.ScopeFrameworks) == 0 {
		return nil, gorm.ErrRecordNotFound
	}
	return &posture, nil
}
