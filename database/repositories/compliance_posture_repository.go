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

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/statemachine"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/l3montree-dev/devguard/utils"
	"gorm.io/gorm"
)

type CompliancePostureRepository struct {
	db *gorm.DB
	utils.Repository[uuid.UUID, models.CompliancePosture, *gorm.DB]
}

type frameworkControlPostureRow struct {
	models.FrameworkControl
	CompliancePostureID *uuid.UUID         `gorm:"column:id"`
	State               dtos.VulnState     `gorm:"column:state"`
	OrgID               *uuid.UUID         `gorm:"column:org_id"`
	ProjectID           *uuid.UUID         `gorm:"column:project_id"`
	AssetID             *uuid.UUID         `gorm:"column:asset_id"`
	AssetVersionName    *string            `gorm:"column:asset_version_name"`
	Events              []models.VulnEvent `gorm:"foreignKey:CompliancePostureID;references:CompliancePostureID"`
}

// nosemgrep: repo-method-missing-ctx, repo-method-missing-ctx-empty-params
func (row frameworkControlPostureRow) compliancePostureIDString() string {
	if row.CompliancePostureID == nil {
		return ""
	}
	return row.CompliancePostureID.String()
}

// nosemgrep: repo-method-missing-ctx, repo-method-missing-ctx-empty-params
func (row frameworkControlPostureRow) toDTO() dtos.CompliancePostureWithControlDTO {
	mappedControls := make([]dtos.MappedControlDTO, len(row.MappedControls))
	for i, mc := range row.MappedControls {
		mappedControls[i] = dtos.MappedControlDTO{
			FrameworkControlID: mc.FrameworkControlID,
			RelatedFramework:   mc.RelatedFramework,
			RelatedControlID:   mc.RelatedControlID,
		}
	}

	return dtos.CompliancePostureWithControlDTO{
		FrameworkControlID:       row.FrameworkControlID,
		Framework:                row.Framework,
		ControlID:                row.ControlID,
		Title:                    row.Title,
		Description:              row.Description,
		Importance:               row.Importance,
		Class:                    row.Class,
		Additional:               row.Additional,
		ParentFrameworkControlID: row.ParentFrameworkControlID,
		CompliancePostureID:      row.compliancePostureIDString(),
		State:                    row.State,
		OrgID:                    row.OrgID,
		ProjectID:                row.ProjectID,
		AssetID:                  row.AssetID,
		AssetVersionName:         row.AssetVersionName,
		MappedControls:           mappedControls,
	}
}

// nosemgrep: repo-method-missing-ctx, repo-method-missing-ctx-empty-params
func (row frameworkControlPostureRow) toDetailsDTO() dtos.CompliancePostureWithDetailsDTO {
	dto := dtos.CompliancePostureWithDetailsDTO{
		CompliancePostureWithControlDTO: row.toDTO(),
	}
	for _, ev := range row.Events {
		dto.Events = append(dto.Events, transformer.ConvertVulnEventToDto(ev))
	}
	return dto
}

func NewCompliancePostureRepository(db *gorm.DB) *CompliancePostureRepository {
	return &CompliancePostureRepository{
		db:         db,
		Repository: newGormRepository[uuid.UUID, models.CompliancePosture](db),
	}
}

func (r *CompliancePostureRepository) FindOrCreate(ctx context.Context, tx *gorm.DB, posture models.CompliancePosture) (*models.CompliancePosture, error) {
	var existingPosture models.CompliancePosture
	db := withOwnershipScope(ctx, r.GetDB(ctx, tx).Where("id = ?", posture.ID), existingPosture)
	if err := db.Preload("FrameworkControl").First(&existingPosture).Error; err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("failed to query compliance posture: %w", err)
		}
		newPosture := models.CompliancePosture{
			Vulnerability:      models.Vulnerability{ID: posture.ID, State: posture.State},
			FrameworkControlID: posture.FrameworkControlID,
			OrgID:              posture.OrgID,
			ProjectID:          posture.ProjectID,
			AssetID:            posture.AssetID,
			AssetVersionName:   posture.AssetVersionName,
		}
		if err := r.GetDB(ctx, tx).Create(&newPosture).Error; err != nil {
			return nil, fmt.Errorf("failed to create compliance posture: %w", err)
		}
		if err := r.GetDB(ctx, tx).Where("framework_control_id = ?", newPosture.FrameworkControlID).First(&newPosture.FrameworkControl).Error; err != nil {
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

func (r *CompliancePostureRepository) GetForAllControlsPaged(ctx context.Context, tx *gorm.DB, assetVersionName *string, assetID *uuid.UUID, projectID *uuid.UUID, orgID uuid.UUID, pageInfo shared.PageInfo, search string, filter []shared.FilterQuery, sort []shared.SortQuery) (shared.Paged[dtos.CompliancePostureWithControlDTO], error) {
	var postures []dtos.CompliancePostureWithControlDTO
	var count int64

	query := r.GetDB(ctx, tx).Model(&models.FrameworkControl{}).
		Select(`frameworks_controls.framework_control_id,
			frameworks_controls.title,
			frameworks_controls.description,
			frameworks_controls.importance,
			frameworks_controls.class,
			frameworks_controls.additional,
			frameworks_controls.parent_framework_control_id,
			frameworks_controls.framework,
			frameworks_controls.control_id,
			COALESCE(cp_asset.id, cp_project.id, cp_org.id) AS id,
			COALESCE(cp_asset.state, cp_project.state, cp_org.state) AS state,
			COALESCE(cp_asset.org_id, cp_project.org_id, cp_org.org_id) AS org_id,
			COALESCE(cp_asset.project_id, cp_project.project_id, cp_org.project_id) AS project_id,
			COALESCE(cp_asset.asset_id, cp_project.asset_id, cp_org.asset_id) AS asset_id,
			COALESCE(cp_asset.asset_version_name, cp_project.asset_version_name, cp_org.asset_version_name) AS asset_version_name`).
		Joins(`LEFT JOIN compliance_postures cp_asset
			ON frameworks_controls.framework_control_id = cp_asset.framework_control_id
			AND cp_asset.org_id = ?
			AND cp_asset.project_id IS NOT DISTINCT FROM ?
			AND cp_asset.asset_id IS NOT DISTINCT FROM ?
			AND cp_asset.asset_version_name IS NOT DISTINCT FROM ?`, orgID, projectID, assetID, assetVersionName).
		Joins(`LEFT JOIN compliance_postures cp_project
			ON frameworks_controls.framework_control_id = cp_project.framework_control_id
			AND cp_project.org_id = ?
			AND cp_project.project_id IS NOT DISTINCT FROM ?
			AND cp_project.asset_id IS NULL
			AND cp_project.asset_version_name IS NULL`, orgID, projectID).
		Joins(`LEFT JOIN compliance_postures cp_org
			ON frameworks_controls.framework_control_id = cp_org.framework_control_id
			AND cp_org.org_id = ?
			AND cp_org.project_id IS NULL
			AND cp_org.asset_id IS NULL
			AND cp_org.asset_version_name IS NULL`, orgID)

	if search != "" {
		query = query.Where("(frameworks_controls.title ILIKE ? OR frameworks_controls.control_id ILIKE ? OR frameworks_controls.framework ILIKE ?)", "%"+search+"%", "%"+search+"%", "%"+search+"%")
	}

	subquery := r.GetDB(ctx, tx).Table("(?) AS sub", query)

	for _, f := range filter {
		group := r.GetDB(ctx, tx)
		switch {
		case f.Field == "state" && f.FieldValue == "open" && f.Operator == "is":
			subquery = subquery.Where(group.Where(f.SQL(), f.Value()).Or("state IS NULL"))
		case f.Field == "state" && f.FieldValue == "open" && f.Operator == "is not":
			subquery = subquery.Where(f.SQL(), f.Value()).Where("state IS NOT NULL")
		case f.Field == "framework" && f.Operator == "is":
			subquery = subquery.Where(group.Where(f.SQL(), f.Value()).
				Or("framework_control_id IN (SELECT framework_control_id FROM mapped_controls WHERE related_framework = ?)", f.Value()))
		case f.Field == "framework" && f.Operator == "in":
			subquery = subquery.Where(group.Where(f.SQL(), f.Value()).
				Or("framework_control_id IN (SELECT framework_control_id FROM mapped_controls WHERE related_framework IN (?))", f.Value()))
		default:
			subquery = subquery.Where(f.SQL(), f.Value())
		}
	}

	for _, s := range sort {
		subquery = subquery.Order(s.SQL())
	}

	if err := subquery.Count(&count).Error; err != nil {
		return shared.Paged[dtos.CompliancePostureWithControlDTO]{}, err
	}

	var rows []frameworkControlPostureRow
	if err := subquery.Model(&frameworkControlPostureRow{}).
		Preload("MappedControls").
		Offset((pageInfo.Page - 1) * pageInfo.PageSize).
		Limit(pageInfo.PageSize).
		Find(&rows).Error; err != nil {
		return shared.Paged[dtos.CompliancePostureWithControlDTO]{}, err
	}

	postures = make([]dtos.CompliancePostureWithControlDTO, len(rows))

	for i, row := range rows {
		postures[i] = row.toDTO()
	}

	return shared.NewPaged(pageInfo, count, postures), nil
}

func (r *CompliancePostureRepository) GetAllControls(ctx context.Context, tx *gorm.DB, assetVersionName *string, assetID *uuid.UUID, projectID *uuid.UUID, orgID uuid.UUID, search string, filter []shared.FilterQuery, sort []shared.SortQuery) ([]dtos.CompliancePostureWithDetailsDTO, error) {
	var postures []dtos.CompliancePostureWithDetailsDTO

	query := r.GetDB(ctx, tx).Model(&models.FrameworkControl{}).
		Select(`frameworks_controls.framework_control_id,
			frameworks_controls.title,
			frameworks_controls.description,
			frameworks_controls.importance,
			frameworks_controls.class,
			frameworks_controls.additional,
			frameworks_controls.parent_framework_control_id,
			frameworks_controls.framework,
			frameworks_controls.control_id,
			COALESCE(cp_asset.id, cp_project.id, cp_org.id) AS id,
			COALESCE(cp_asset.state, cp_project.state, cp_org.state) AS state,
			COALESCE(cp_asset.org_id, cp_project.org_id, cp_org.org_id) AS org_id,
			COALESCE(cp_asset.project_id, cp_project.project_id, cp_org.project_id) AS project_id,
			COALESCE(cp_asset.asset_id, cp_project.asset_id, cp_org.asset_id) AS asset_id,
			COALESCE(cp_asset.asset_version_name, cp_project.asset_version_name, cp_org.asset_version_name) AS asset_version_name`).
		Joins(`LEFT JOIN compliance_postures cp_asset
			ON frameworks_controls.framework_control_id = cp_asset.framework_control_id
			AND cp_asset.org_id = ?
			AND cp_asset.project_id IS NOT DISTINCT FROM ?
			AND cp_asset.asset_id IS NOT DISTINCT FROM ?
			AND cp_asset.asset_version_name IS NOT DISTINCT FROM ?`, orgID, projectID, assetID, assetVersionName).
		Joins(`LEFT JOIN compliance_postures cp_project
			ON frameworks_controls.framework_control_id = cp_project.framework_control_id
			AND cp_project.org_id = ?
			AND cp_project.project_id IS NOT DISTINCT FROM ?
			AND cp_project.asset_id IS NULL
			AND cp_project.asset_version_name IS NULL`, orgID, projectID).
		Joins(`LEFT JOIN compliance_postures cp_org
			ON frameworks_controls.framework_control_id = cp_org.framework_control_id
			AND cp_org.org_id = ?
			AND cp_org.project_id IS NULL
			AND cp_org.asset_id IS NULL
			AND cp_org.asset_version_name IS NULL`, orgID)

	if search != "" {
		query = query.Where("(frameworks_controls.title ILIKE ? OR frameworks_controls.control_id ILIKE ? OR frameworks_controls.framework ILIKE ?)", "%"+search+"%", "%"+search+"%", "%"+search+"%")
	}

	subquery := r.GetDB(ctx, tx).Table("(?) AS sub", query)

	for _, f := range filter {
		group := r.GetDB(ctx, tx)
		switch {
		case f.Field == "state" && f.FieldValue == "open" && f.Operator == "is":
			subquery = subquery.Where(group.Where(f.SQL(), f.Value()).Or("state IS NULL"))
		case f.Field == "state" && f.FieldValue == "open" && f.Operator == "is not":
			subquery = subquery.Where(f.SQL(), f.Value()).Where("state IS NOT NULL")
		case f.Field == "framework" && f.Operator == "is":
			subquery = subquery.Where(group.Where(f.SQL(), f.Value()).
				Or("framework_control_id IN (SELECT framework_control_id FROM mapped_controls WHERE related_framework = ?)", f.Value()))
		case f.Field == "framework" && f.Operator == "in":
			subquery = subquery.Where(group.Where(f.SQL(), f.Value()).
				Or("framework_control_id IN (SELECT framework_control_id FROM mapped_controls WHERE related_framework IN (?))", f.Value()))
		default:
			subquery = subquery.Where(f.SQL(), f.Value())
		}
	}

	for _, s := range sort {
		subquery = subquery.Order(s.SQL())
	}

	var rows []frameworkControlPostureRow
	if err := subquery.Model(&frameworkControlPostureRow{}).
		Preload("MappedControls").
		Preload("Events").
		Find(&rows).Error; err != nil {
		return nil, err
	}

	postures = make([]dtos.CompliancePostureWithDetailsDTO, len(rows))
	for i, row := range rows {
		postures[i] = row.toDetailsDTO()
	}

	return postures, nil
}

func (r *CompliancePostureRepository) GetStatsForAllControls(ctx context.Context, tx *gorm.DB, assetVersionName *string, assetID *uuid.UUID, projectID *uuid.UUID, orgID uuid.UUID, filter []shared.FilterQuery) (dtos.CompliancePostureStatsDTO, error) {
	type row struct {
		State *string `gorm:"column:state"`
		Count int64   `gorm:"column:count"`
	}
	var rows []row

	query := r.GetDB(ctx, tx).Model(&models.FrameworkControl{}).
		Select(`frameworks_controls.framework_control_id,
			frameworks_controls.framework,
			COALESCE(cp_asset.state, cp_project.state, cp_org.state) AS state`).
		Joins(`LEFT JOIN compliance_postures cp_asset
			ON frameworks_controls.framework_control_id = cp_asset.framework_control_id
			AND cp_asset.org_id = ?
			AND cp_asset.project_id IS NOT DISTINCT FROM ?
			AND cp_asset.asset_id IS NOT DISTINCT FROM ?
			AND cp_asset.asset_version_name IS NOT DISTINCT FROM ?`, orgID, projectID, assetID, assetVersionName).
		Joins(`LEFT JOIN compliance_postures cp_project
			ON frameworks_controls.framework_control_id = cp_project.framework_control_id
			AND cp_project.org_id = ?
			AND cp_project.project_id IS NOT DISTINCT FROM ?
			AND cp_project.asset_id IS NULL
			AND cp_project.asset_version_name IS NULL`, orgID, projectID).
		Joins(`LEFT JOIN compliance_postures cp_org
			ON frameworks_controls.framework_control_id = cp_org.framework_control_id
			AND cp_org.org_id = ?
			AND cp_org.project_id IS NULL
			AND cp_org.asset_id IS NULL
			AND cp_org.asset_version_name IS NULL`, orgID)

	subquery := r.GetDB(ctx, tx).Table("(?) AS sub", query)
	// Only the "framework" filter applies here (if present)
	for _, f := range filter {
		group := r.GetDB(ctx, tx)
		switch {
		case f.Field == "framework" && f.Operator == "is":
			subquery = subquery.Where(group.Where(f.SQL(), f.Value()).
				Or("framework_control_id IN (SELECT framework_control_id FROM mapped_controls WHERE related_framework = ?)", f.Value()))
		case f.Field == "framework" && f.Operator == "in":
			subquery = subquery.Where(group.Where(f.SQL(), f.Value()).
				Or("framework_control_id IN (SELECT framework_control_id FROM mapped_controls WHERE related_framework IN (?))", f.Value()))
		}
	}

	if err := subquery.Select("state, COUNT(*) AS count").Group("state").Scan(&rows).Error; err != nil {
		return dtos.CompliancePostureStatsDTO{}, err
	}

	var stats dtos.CompliancePostureStatsDTO
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

func (r *CompliancePostureRepository) GetForControl(ctx context.Context, tx *gorm.DB, controlID string, assetVersionName *string, assetID *uuid.UUID, projectID *uuid.UUID, orgID uuid.UUID) (*models.CompliancePosture, error) {

	type row struct {
		ID *uuid.UUID `gorm:"column:id"`
	}
	var result row

	err := r.GetDB(ctx, tx).Model(&models.FrameworkControl{}).
		Select(`COALESCE(cp_asset.id, cp_project.id, cp_org.id) AS id`).
		Joins(`LEFT JOIN compliance_postures cp_asset
			ON frameworks_controls.framework_control_id = cp_asset.framework_control_id
			AND cp_asset.org_id = ?
			AND cp_asset.project_id IS NOT DISTINCT FROM ?
			AND cp_asset.asset_id IS NOT DISTINCT FROM ?
			AND cp_asset.asset_version_name IS NOT DISTINCT FROM ?`, orgID, projectID, assetID, assetVersionName).
		Joins(`LEFT JOIN compliance_postures cp_project
			ON frameworks_controls.framework_control_id = cp_project.framework_control_id
			AND cp_project.org_id = ?
			AND cp_project.project_id IS NOT DISTINCT FROM ?
			AND cp_project.asset_id IS NULL
			AND cp_project.asset_version_name IS NULL`, orgID, projectID).
		Joins(`LEFT JOIN compliance_postures cp_org
			ON frameworks_controls.framework_control_id = cp_org.framework_control_id
			AND cp_org.org_id = ?
			AND cp_org.project_id IS NULL
			AND cp_org.asset_id IS NULL
			AND cp_org.asset_version_name IS NULL`, orgID).
		Where("frameworks_controls.framework_control_id = ?", controlID).
		Scan(&result).Error

	if err != nil {
		return nil, err
	}

	var posture models.CompliancePosture

	if result.ID != nil {
		if err := r.GetDB(ctx, tx).
			Joins("FrameworkControl").
			Preload("FrameworkControl.MappedControls").
			Preload("Events").
			Where("compliance_postures.id = ?", result.ID).
			First(&posture).Error; err != nil {
			return nil, err
		}
		return &posture, nil
	}

	// No posture exists at any scope — return an empty posture with just the control loaded.
	posture.FrameworkControlID = controlID
	if err := r.GetDB(ctx, tx).Preload("MappedControls").Where("framework_control_id = ?", controlID).First(&posture.FrameworkControl).Error; err != nil {
		return nil, err
	}
	return &posture, nil
}
