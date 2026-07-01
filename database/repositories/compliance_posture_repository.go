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
	"github.com/l3montree-dev/devguard/utils"
	"gorm.io/gorm"
)

type CompliancePostureRepository struct {
	db *gorm.DB
	utils.Repository[uuid.UUID, models.CompliancePosture, *gorm.DB]
}

func NewCompliancePostureRepository(db *gorm.DB) *CompliancePostureRepository {
	return &CompliancePostureRepository{
		db:         db,
		Repository: newGormRepository[uuid.UUID, models.CompliancePosture](db),
	}
}

func (r *CompliancePostureRepository) FindOrCreate(ctx context.Context, tx *gorm.DB, posture models.CompliancePosture) (*models.CompliancePosture, error) {
	var existingPosture models.CompliancePosture
	if err := r.GetDB(ctx, tx).Preload("FrameworkControl").Where("id = ?", posture.ID).First(&existingPosture).Error; err != nil {
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
	// Three LEFT JOINs at decreasing specificity; COALESCE picks the most specific match.
	// cp_asset: exact match on org+project+asset+assetVersion
	// cp_project: match on org+project, asset fields NULL in DB
	// cp_org: match on org only, all scope fields NULL in DB
	query := r.GetDB(ctx, tx).Model(&models.FrameworkControl{}).
		Select(`frameworks_controls.framework_control_id,
			frameworks_controls.title,
			frameworks_controls.description,
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

	// Wrap in a subquery so that filter/sort can reference the aliased columns
	// (e.g. "state" from COALESCE) without ambiguity.
	subquery := r.GetDB(ctx, tx).Table("(?) AS sub", query)

	for _, f := range filter {
		subquery = subquery.Where(f.SQL(), f.Value())
		if f.Field == "state" && f.FieldValue == "open" && f.Operator == "is" {
			subquery = subquery.Or("state IS NULL")
		} else if f.Field == "state" && f.FieldValue == "open" && f.Operator == "is not" {
			subquery = subquery.Where("state IS NOT NULL")
		}
	}

	for _, s := range sort {
		subquery = subquery.Order(s.SQL())
	}

	if err := subquery.Count(&count).Error; err != nil {
		return shared.Paged[dtos.CompliancePostureWithControlDTO]{}, err
	}

	if err := subquery.Offset((pageInfo.Page - 1) * pageInfo.PageSize).Limit(pageInfo.PageSize).Find(&postures).Error; err != nil {
		return shared.Paged[dtos.CompliancePostureWithControlDTO]{}, err
	}

	return shared.NewPaged(pageInfo, count, postures), nil
}

func (r *CompliancePostureRepository) GetStatsForAllControls(ctx context.Context, tx *gorm.DB, assetVersionName *string, assetID *uuid.UUID, projectID *uuid.UUID, orgID uuid.UUID) (dtos.CompliancePostureStatsDTO, error) {
	type row struct {
		State *string `gorm:"column:state"`
		Count int64   `gorm:"column:count"`
	}
	var rows []row

	query := r.GetDB(ctx, tx).Model(&models.FrameworkControl{}).
		Select(`COALESCE(cp_asset.state, cp_project.state, cp_org.state) AS state, COUNT(*) AS count`).
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
		Group("COALESCE(cp_asset.state, cp_project.state, cp_org.state)")

	if err := query.Scan(&rows).Error; err != nil {
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
			Preload("Events").
			Where("compliance_postures.id = ?", result.ID).
			First(&posture).Error; err != nil {
			return nil, err
		}
		return &posture, nil
	}

	// No posture exists at any scope — return an empty posture with just the control loaded.
	posture.FrameworkControlID = controlID
	if err := r.GetDB(ctx, tx).Where("framework_control_id = ?", controlID).First(&posture.FrameworkControl).Error; err != nil {
		return nil, err
	}
	return &posture, nil
}
