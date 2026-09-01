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
	"net/url"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/compliance"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/transformer"

	"github.com/labstack/echo/v4"
)

type CompliancePostureController struct {
	compliancePostureRepository shared.CompliancePostureRepository
	compliancePostureService    shared.CompliancePostureService
	frameworkControlRepository  shared.FrameworkControlRepository
}

func NewCompliancePostureController(compliancePostureRepository shared.CompliancePostureRepository, compliancePostureService shared.CompliancePostureService, frameworkControlRepository shared.FrameworkControlRepository) *CompliancePostureController {
	return &CompliancePostureController{
		compliancePostureRepository: compliancePostureRepository,
		compliancePostureService:    compliancePostureService,
		frameworkControlRepository:  frameworkControlRepository,
	}
}

// @Summary Get compliance posture for a framework control
// @Tags Compliance Postures
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param frameworkControlID path string true "Framework Control ID"
// @Success 200 {object} dtos.CompliancePostureWithDetailsDTO
// @Router /organizations/{organization}/compliance-postures/{frameworkControlID} [get]
func (c *CompliancePostureController) OrgRead(ctx shared.Context) error {
	return c.Read(ctx)
}

// @Summary Get compliance posture for a framework control
// @Tags Compliance Postures
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param frameworkControlID path string true "Framework Control ID"
// @Success 200 {object} dtos.CompliancePostureWithDetailsDTO
// @Router /organizations/{organization}/projects/{projectSlug}/compliance-postures/{frameworkControlID} [get]
func (c *CompliancePostureController) ProjectRead(ctx shared.Context) error {
	return c.Read(ctx)
}

// @Summary Get compliance posture for a framework control
// @Tags Compliance Postures
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Param assetVersionSlug path string true "Asset version slug"
// @Param frameworkControlID path string true "Framework Control ID"
// @Success 200 {object} dtos.CompliancePostureWithDetailsDTO
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/refs/{assetVersionSlug}/compliance-postures/{frameworkControlID} [get]
func (c *CompliancePostureController) AssetVersionRead(ctx shared.Context) error {
	return c.Read(ctx)
}

func (c *CompliancePostureController) Read(ctx shared.Context) error {
	frameworkControlID, err := getFrameworkControlIDFromCtx(ctx)
	if err != nil {
		return err
	}

	orgID := shared.GetOrg(ctx).ID
	projectID, assetID, assetVersionName := getOwnershipFromCtx(ctx)

	posture, err := c.compliancePostureService.GetForControl(ctx.Request().Context(), nil, frameworkControlID, assetVersionName, assetID, projectID, orgID)
	if err != nil {
		if shared.IsNotFound(err) {
			return echo.NewHTTPError(404, "compliance posture not found")
		}
		return err
	}

	return ctx.JSON(200, transformer.CompliancePostureToDTO(*posture))
}

// @Summary List compliance postures paged
// @Tags Compliance Postures
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Success 200 {object} shared.Paged[dtos.CompliancePostureWithControlDTO]
// @Router /organizations/{organization}/compliance-postures [get]
func (c *CompliancePostureController) OrgListPaged(ctx shared.Context) error {
	return c.ListPaged(ctx)
}

// @Summary List compliance postures paged
// @Tags Compliance Postures
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Success 200 {object} shared.Paged[dtos.CompliancePostureWithControlDTO]
// @Router /organizations/{organization}/projects/{projectSlug}/compliance-postures [get]
func (c *CompliancePostureController) ProjectListPaged(ctx shared.Context) error {
	return c.ListPaged(ctx)
}

// @Summary List compliance postures paged
// @Tags Compliance Postures
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Param assetVersionSlug path string true "Asset version slug"
// @Success 200 {object} shared.Paged[dtos.CompliancePostureWithControlDTO]
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/refs/{assetVersionSlug}/compliance-postures [get]
func (c *CompliancePostureController) AssetVersionListPaged(ctx shared.Context) error {
	return c.ListPaged(ctx)
}

func (c *CompliancePostureController) ListPaged(ctx shared.Context) error {
	orgID := shared.GetOrg(ctx).ID
	projectID, assetID, assetVersionName := getOwnershipFromCtx(ctx)

	pageInfo := shared.GetPageInfo(ctx)
	search := ctx.QueryParam("search")
	filter := shared.GetFilterQuery(ctx)
	sort := shared.GetSortQuery(ctx)

	postures, err := c.compliancePostureService.GetForAllControlsPaged(ctx.Request().Context(), nil, assetVersionName, assetID, projectID, orgID, pageInfo, search, filter, sort)
	if err != nil {
		return err
	}

	frameworks, err := c.frameworkControlRepository.ListFrameworkControls(ctx.Request().Context(), nil)
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

// @Summary Get compliance posture stats
// @Tags Compliance Postures
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Success 200 {object} dtos.CompliancePostureStatsDTO
// @Router /organizations/{organization}/compliance-postures/stats [get]
func (c *CompliancePostureController) OrgStats(ctx shared.Context) error {
	return c.Stats(ctx)
}

// @Summary Get compliance posture stats
// @Tags Compliance Postures
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Success 200 {object} dtos.CompliancePostureStatsDTO
// @Router /organizations/{organization}/projects/{projectSlug}/compliance-postures/stats [get]
func (c *CompliancePostureController) ProjectStats(ctx shared.Context) error {
	return c.Stats(ctx)
}

// @Summary Get compliance posture stats
// @Tags Compliance Postures
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Param assetVersionSlug path string true "Asset version slug"
// @Success 200 {object} dtos.CompliancePostureStatsDTO
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/refs/{assetVersionSlug}/compliance-postures/stats [get]
func (c *CompliancePostureController) AssetVersionStats(ctx shared.Context) error {
	return c.Stats(ctx)
}

func (c *CompliancePostureController) Stats(ctx shared.Context) error {
	orgID := shared.GetOrg(ctx).ID
	filter := shared.GetFilterQuery(ctx)
	projectID, assetID, assetVersionName := getOwnershipFromCtx(ctx)
	stats, err := c.compliancePostureService.GetStatsForAllControls(ctx.Request().Context(), nil, assetVersionName, assetID, projectID, orgID, filter)
	if err != nil {
		return err
	}

	return ctx.JSON(200, stats)
}

func getOwnershipFromCtx(ctx shared.Context) (projectID *uuid.UUID, assetID *uuid.UUID, assetVersionName *string) {
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
	return projectID, assetID, assetVersionName
}

func getFrameworkControlIDFromCtx(ctx shared.Context) (string, error) {
	frameworkControlID, err := url.PathUnescape(ctx.Param("frameworkControlID"))
	if err != nil || frameworkControlID == "" {
		return "", echo.NewHTTPError(400, "frameworkControlID is required")
	}
	return frameworkControlID, nil
}

// @Summary Create a compliance posture event
// @Tags Compliance Postures
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param frameworkControlID path string true "Framework Control ID"
// @Success 200 {object} dtos.CompliancePostureWithDetailsDTO
// @Param body body object{status=string,justification=string} true "Event data"
// @Router /organizations/{organization}/compliance-postures/{frameworkControlID} [post]
func (c *CompliancePostureController) OrgCreateEvent(ctx shared.Context) error {
	return c.CreateEvent(ctx)
}

// @Summary Create a compliance posture event
// @Tags Compliance Postures
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param frameworkControlID path string true "Framework Control ID"
// @Success 200 {object} dtos.CompliancePostureWithDetailsDTO
// @Param body body object{status=string,justification=string} true "Event data"
// @Router /organizations/{organization}/projects/{projectSlug}/compliance-postures/{frameworkControlID} [post]
func (c *CompliancePostureController) ProjectCreateEvent(ctx shared.Context) error {
	return c.CreateEvent(ctx)
}

// @Summary Create a compliance posture event
// @Tags Compliance Postures
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Param assetVersionSlug path string true "Asset version slug"
// @Param frameworkControlID path string true "Framework Control ID"
// @Success 200 {object} dtos.CompliancePostureWithDetailsDTO
// @Param body body object{status=string,justification=string} true "Event data"
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/refs/{assetVersionSlug}/compliance-postures/{frameworkControlID} [post]
func (c *CompliancePostureController) AssetVersionCreateEvent(ctx shared.Context) error {
	return c.CreateEvent(ctx)
}

func (c *CompliancePostureController) CreateEvent(ctx shared.Context) error {

	frameworkControlID, err := getFrameworkControlIDFromCtx(ctx)
	if err != nil {
		return err
	}

	ownerID := shared.GetSession(ctx).GetActorName()
	userAgent := ctx.Request().UserAgent()

	orgID := shared.GetOrg(ctx).ID

	projectID, assetID, assetVersionName := getOwnershipFromCtx(ctx)

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

	compliancePostureNew, err := c.compliancePostureRepository.FindOrCreate(ctx.Request().Context(), nil, compliancePosture)
	if err != nil {
		return echo.NewHTTPError(500, "failed to find or create compliance posture").WithInternal(err)
	}

	justification := ""
	if state.Justification != nil {
		justification = *state.Justification
	}
	_, err = c.compliancePostureService.UpdateCompliancePostureState(ctx.Request().Context(), nil, ownerID, compliancePostureNew, statusType, justification, "", &userAgent)
	if err != nil {
		return err
	}

	return ctx.JSON(200, transformer.CompliancePostureToDTO(*compliancePostureNew))
}

// @Summary Get OSCAL system security plan
// @Tags Compliance Postures
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Success 200 {object} interface{}
// @Router /organizations/{organization}/compliance-postures/oscal [get]
func (c *CompliancePostureController) OrgGetOSCAL(ctx shared.Context) error {
	return c.GetOSCAL(ctx)
}

// @Summary Get OSCAL system security plan
// @Tags Compliance Postures
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Success 200 {object} interface{}
// @Router /organizations/{organization}/projects/{projectSlug}/compliance-postures/oscal [get]
func (c *CompliancePostureController) ProjectGetOSCAL(ctx shared.Context) error {
	return c.GetOSCAL(ctx)
}

// @Summary Get OSCAL system security plan
// @Tags Compliance Postures
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Param assetVersionSlug path string true "Asset version slug"
// @Success 200 {object} interface{}
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/refs/{assetVersionSlug}/compliance-postures/oscal [get]
func (c *CompliancePostureController) AssetVersionGetOSCAL(ctx shared.Context) error {
	return c.GetOSCAL(ctx)
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

	compliancePostures, err := c.compliancePostureService.GetAllControls(ctx.Request().Context(), nil, assetVersionName, assetID, projectID, orgID, "", filter, nil)
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

	frameworkControls, err := c.frameworkControlRepository.GetAll(ctx.Request().Context(), nil, framework)
	if err != nil {
		return err
	}

	oscal, err := transformer.ConvertCompliancePosturesToSystemSecurityPlanOSCAL(compliancePostures, frameworkControls)
	if err != nil {
		return err
	}

	// The OSCAL SSP schema requires control-implementation.implemented-requirements
	// to have at least one entry (minItems: 1), so a scope with zero tracked
	// controls can never produce a schema-valid document. Skip validation in
	// that case rather than 500ing on an otherwise-correct empty result.
	if len(compliancePostures) > 0 {
		if err := compliance.ValidateOSCAL(oscal); err != nil {
			return echo.NewHTTPError(500, "OSCAL validation failed").WithInternal(err)
		}
	}

	return ctx.JSON(200, oscal)
}
