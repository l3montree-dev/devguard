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
package controllers

import (
	"encoding/json"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/compliance"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/transformer"

	"github.com/labstack/echo/v4"
)

type CompliancePostureController struct {
	CompliancePostureRepository shared.CompliancePostureRepository
	CompliancePostureService    shared.CompliancePostureService
	FrameworkControlRepository  shared.FrameworkControlRepository
}

func NewCompliancePostureController(compliancePostureRepository shared.CompliancePostureRepository, compliancePostureService shared.CompliancePostureService, frameworkControlRepository shared.FrameworkControlRepository) *CompliancePostureController {
	return &CompliancePostureController{
		CompliancePostureRepository: compliancePostureRepository,
		CompliancePostureService:    compliancePostureService,
		FrameworkControlRepository:  frameworkControlRepository,
	}
}

func (c *CompliancePostureController) Read(ctx shared.Context) error {
	frameworkControlID := ctx.Param("frameworkControlID")
	if frameworkControlID == "" {
		return echo.NewHTTPError(400, "frameworkControlID is required")
	}

	var assetVersionName *string
	var assetID *uuid.UUID
	var projectID *uuid.UUID
	orgID := shared.GetOrg(ctx).ID
	project, err := shared.MaybeGetProject(ctx)
	if err == nil {
		projectID = &project.ID
		asset, err := shared.MaybeGetAsset(ctx)
		if err == nil {
			assetID = &asset.ID
			assetVersion, err := shared.MaybeGetAssetVersion(ctx)
			if err == nil {
				assetVersionName = &assetVersion.Name
			}
		}
	}

	posture, err := c.CompliancePostureService.GetForControl(ctx.Request().Context(), nil, frameworkControlID, assetVersionName, assetID, projectID, orgID)
	if err != nil {
		return err
	}

	return ctx.JSON(200, transformer.CompliancePostureToDTO(*posture))
}

func (c *CompliancePostureController) ListPaged(ctx shared.Context) error {
	var assetVersionName *string
	var assetID *uuid.UUID
	var projectID *uuid.UUID
	orgID := shared.GetOrg(ctx).ID
	project, err := shared.MaybeGetProject(ctx)
	if err == nil {
		projectID = &project.ID
		asset, err := shared.MaybeGetAsset(ctx)
		if err == nil {
			assetID = &asset.ID
			assetVersion, err := shared.MaybeGetAssetVersion(ctx)
			if err == nil {
				assetVersionName = &assetVersion.Name
			}
		}
	}

	pageInfo := shared.GetPageInfo(ctx)
	search := ctx.QueryParam("search")
	filter := shared.GetFilterQuery(ctx)
	sort := shared.GetSortQuery(ctx)

	postures, err := c.CompliancePostureService.GetForAllControlsPaged(ctx.Request().Context(), nil, assetVersionName, assetID, projectID, orgID, pageInfo, search, filter, sort)
	if err != nil {
		return err
	}

	frameworks, err := c.FrameworkControlRepository.ListFrameworkControls(ctx.Request().Context(), nil)
	if err != nil {
		return err
	}

	return ctx.JSON(200, struct {
		shared.Paged[dtos.CompliancePostureWithControlDTO]
		Frameworks []string `json:"frameworks"`
	}{
		Paged:      postures,
		Frameworks: frameworks,
	})
}

func (c *CompliancePostureController) Stats(ctx shared.Context) error {
	var assetVersionName *string
	var assetID *uuid.UUID
	var projectID *uuid.UUID
	orgID := shared.GetOrg(ctx).ID
	project, err := shared.MaybeGetProject(ctx)
	if err == nil {
		projectID = &project.ID
		asset, err := shared.MaybeGetAsset(ctx)
		if err == nil {
			assetID = &asset.ID
			assetVersion, err := shared.MaybeGetAssetVersion(ctx)
			if err == nil {
				assetVersionName = &assetVersion.Name
			}
		}
	}

	filter := shared.GetFilterQuery(ctx)

	stats, err := c.CompliancePostureService.GetStatsForAllControls(ctx.Request().Context(), nil, assetVersionName, assetID, projectID, orgID, filter)
	if err != nil {
		return err
	}

	return ctx.JSON(200, stats)
}

func (c *CompliancePostureController) CreateEvent(ctx shared.Context) error {

	frameworkControlID := ctx.Param("frameworkControlID")
	if frameworkControlID == "" {
		return echo.NewHTTPError(400, "frameworkControlID is required")
	}

	userID := shared.GetSession(ctx).GetUserID()
	userAgent := ctx.Request().UserAgent()

	orgID := shared.GetOrg(ctx).ID
	var projectID *uuid.UUID
	var assetID *uuid.UUID
	var assetVersionName *string
	project, err := shared.MaybeGetProject(ctx)
	if err == nil {
		projectID = &project.ID
		asset, err := shared.MaybeGetAsset(ctx)
		if err == nil {
			assetID = &asset.ID
			assetVersion, err := shared.MaybeGetAssetVersion(ctx)
			if err == nil {
				assetVersionName = &assetVersion.Name
			}
		}
	}

	var state struct {
		Status        string  `json:"status"`
		Justification *string `json:"justification"`
	}
	err = json.NewDecoder(ctx.Request().Body).Decode(&state)
	if err != nil {
		return echo.NewHTTPError(400, "invalid payload").WithInternal(err)
	}
	statusType := state.Status
	err = models.CheckStatusType(statusType)
	if err != nil {
		return echo.NewHTTPError(400, "invalid state").WithInternal(err)
	}
	compliancePosture := models.CompliancePosture{
		FrameworkControlID: frameworkControlID,
		OrgID:              orgID,
		ProjectID:          projectID,
		AssetID:            assetID,
		AssetVersionName:   assetVersionName,
		Vulnerability: models.Vulnerability{
			State: dtos.VulnStateOpen,
		},
	}

	compliancePosture.ID = compliancePosture.CalculateHash()

	compliancePostureNew, err := c.CompliancePostureRepository.FindOrCreate(ctx.Request().Context(), nil, compliancePosture)
	if err != nil {
		return echo.NewHTTPError(500, "failed to find or create compliance posture").WithInternal(err)
	}

	justification := ""
	if state.Justification != nil {
		justification = *state.Justification
	}
	_, err = c.CompliancePostureService.UpdateCompliancePostureState(ctx.Request().Context(), nil, userID, compliancePostureNew, statusType, justification, "", &userAgent)
	if err != nil {
		return err
	}

	return ctx.JSON(200, transformer.CompliancePostureToDTO(*compliancePostureNew))
}

func (c *CompliancePostureController) GetOSCAL(ctx shared.Context) error {
	var assetVersionName *string
	var assetID *uuid.UUID
	var projectID *uuid.UUID
	orgID := shared.GetOrg(ctx).ID
	project, err := shared.MaybeGetProject(ctx)
	if err == nil {
		projectID = &project.ID
		asset, err := shared.MaybeGetAsset(ctx)
		if err == nil {
			assetID = &asset.ID
			assetVersion, err := shared.MaybeGetAssetVersion(ctx)
			if err == nil {
				assetVersionName = &assetVersion.Name
			}
		}
	}

	var framework *string
	var filter []shared.FilterQuery
	frameworkParam := ctx.QueryParam("framework")
	if frameworkParam != "" {
		framework = &frameworkParam
		filter = append(filter, shared.FilterQuery{
			Field:      "framework",
			Operator:   "is",
			FieldValue: frameworkParam,
		})

	}

	compliancePostures, err := c.CompliancePostureService.GetAllControls(ctx.Request().Context(), nil, assetVersionName, assetID, projectID, orgID, "", filter, nil)
	if err != nil {
		return err
	}

	//calculate the hash for each compliance posture
	for i := range compliancePostures {
		postureOrgID := orgID
		if compliancePostures[i].OrgID != nil {
			postureOrgID = *compliancePostures[i].OrgID
		}
		compliancePostures[i].CompliancePostureID = models.CalculateCompliancePostureHash(compliancePostures[i].FrameworkControlID, postureOrgID, compliancePostures[i].ProjectID, compliancePostures[i].AssetID, compliancePostures[i].AssetVersionName).String()
	}

	frameworkControls, err := c.FrameworkControlRepository.GetAll(ctx.Request().Context(), nil, framework)
	if err != nil {
		return err
	}

	oscal, err := transformer.ConvertCompliancePosturesToSystemSecurityPlanOSCAL(compliancePostures, frameworkControls)
	if err != nil {
		return err
	}

	if err := compliance.ValidateOSCAL(oscal); err != nil {
		return echo.NewHTTPError(500, "OSCAL validation failed").WithInternal(err)
	}

	return ctx.JSON(200, oscal)
}
