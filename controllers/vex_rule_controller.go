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
	"log/slog"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/services"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/labstack/echo/v4"
)

type VEXRuleController struct {
	vexRuleService *services.VEXRuleService
}

func NewVEXRuleController(vexRuleService *services.VEXRuleService) *VEXRuleController {
	return &VEXRuleController{
		vexRuleService: vexRuleService,
	}
}

type CreateVEXRuleRequest struct {
	CVEID                   string                           `json:"cveId" validate:"required"`
	Justification           string                           `json:"justification" validate:"required"`
	MechanicalJustification dtos.MechanicalJustificationType `json:"mechanicalJustification"`
	PathPattern             []string                         `json:"pathPattern" validate:"required,min=1"`
}

type UpdateVEXRuleRequest struct {
	CVEID                   string                           `json:"cveId"`
	Justification           string                           `json:"justification"`
	MechanicalJustification dtos.MechanicalJustificationType `json:"mechanicalJustification"`
	PathPattern             []string                         `json:"pathPattern"`
}

// @Summary List VEX rules for an asset
// @Tags VEXRules
// @Security CookieAuth
// @Security PATAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Success 200 {array} dtos.VEXRuleDTO
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/vex-rules [get]
func (c *VEXRuleController) List(ctx shared.Context) error {
	asset := shared.GetAsset(ctx)

	rules, err := c.vexRuleService.FindByAssetID(nil, asset.ID)
	if err != nil {
		return echo.NewHTTPError(500, "failed to list VEX rules").WithInternal(err)
	}

	result := make([]dtos.VEXRuleDTO, len(rules))
	for i, rule := range rules {
		result[i] = transformer.VEXRuleToDTO(rule)
	}

	return ctx.JSON(200, result)
}

func (c *VEXRuleController) Get(ctx shared.Context) error {
	asset := shared.GetAsset(ctx)

	cveID := ctx.QueryParam("cveId")
	pathPatternHash := ctx.QueryParam("pathPatternHash")
	vexSource := ctx.QueryParam("vexSource")

	if cveID == "" || pathPatternHash == "" || vexSource == "" {
		return echo.NewHTTPError(400, "cveId, pathPatternHash, and vexSource query parameters are required")
	}

	rule, err := c.vexRuleService.FindByCompositeKey(nil, asset.ID, cveID, pathPatternHash, vexSource)
	if err != nil {
		return echo.NewHTTPError(404, "rule not found").WithInternal(err)
	}

	return ctx.JSON(200, transformer.VEXRuleToDTO(rule))
}

// @Summary Create a VEX rule
// @Tags VEXRules
// @Security CookieAuth
// @Security PATAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Param body body CreateVEXRuleRequest true "Rule data"
// @Success 201 {object} dtos.VEXRuleDTO
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/vex-rules [post]
func (c *VEXRuleController) Create(ctx shared.Context) error {
	asset := shared.GetAsset(ctx)
	session := shared.GetSession(ctx)

	var req CreateVEXRuleRequest
	if err := ctx.Bind(&req); err != nil {
		return echo.NewHTTPError(400, "invalid request body").WithInternal(err)
	}

	// perform explicit validation to provide clear errors and avoid relying solely on the validator
	if req.CVEID == "" {
		return echo.NewHTTPError(400, "cveId is required")
	}
	if len(req.PathPattern) == 0 {
		return echo.NewHTTPError(400, "pathPattern must contain at least one element")
	}

	rule := &models.VEXRule{
		AssetID:                 asset.ID,
		CVEID:                   req.CVEID,
		VexSource:               "manual",
		Justification:           req.Justification,
		MechanicalJustification: req.MechanicalJustification,
		PathPattern:             req.PathPattern,
		CreatedByID:             session.GetUserID(),
	}

	tx := c.vexRuleService.Begin()

	if err := c.vexRuleService.Create(nil, rule); err != nil {
		return echo.NewHTTPError(500, "failed to create VEX rule").WithInternal(err)
	}

	// Apply this rule to all matching existing dependency vulns
	if err := c.vexRuleService.ApplyRulesToExistingVulns(tx, asset.DesiredUpstreamStateForEvents(), []models.VEXRule{*rule}); err != nil {
		slog.Error("failed to apply VEX rule to existing vulnerabilities", "error", err,
			"cveID", rule.CVEID, "assetID", rule.AssetID, "vexSource", rule.VexSource)
	}

	return ctx.JSON(201, transformer.VEXRuleToDTO(*rule))
}

// @Summary Update a VEX rule
// @Tags VEXRules
// @Security CookieAuth
// @Security PATAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Param cveId query string true "CVE ID"
// @Param pathPatternHash query string true "Path Pattern Hash"
// @Param vexSource query string true "VEX Source"
// @Param body body UpdateVEXRuleRequest true "Updated rule data"
// @Success 200 {object} dtos.VEXRuleDTO
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/vex-rules [put]
func (c *VEXRuleController) Update(ctx shared.Context) error {
	asset := shared.GetAsset(ctx)

	var req UpdateVEXRuleRequest
	if err := ctx.Bind(&req); err != nil {
		return echo.NewHTTPError(400, "invalid request body").WithInternal(err)
	}

	cveID := ctx.QueryParam("cveId")
	pathPatternHash := ctx.QueryParam("pathPatternHash")
	vexSource := ctx.QueryParam("vexSource")

	if cveID == "" || pathPatternHash == "" || vexSource == "" {
		return echo.NewHTTPError(400, "cveId, pathPatternHash, and vexSource query parameters are required")
	}

	rule, err := c.vexRuleService.FindByCompositeKey(nil, asset.ID, cveID, pathPatternHash, vexSource)
	if err != nil {
		return echo.NewHTTPError(404, "rule not found").WithInternal(err)
	}

	// Verify the rule belongs to this asset
	if rule.AssetID != asset.ID {
		return echo.NewHTTPError(403, "rule does not belong to this asset")
	}

	// Update fields if provided
	if req.CVEID != "" {
		rule.CVEID = req.CVEID
	}
	if req.Justification != "" {
		rule.Justification = req.Justification
	}
	if req.MechanicalJustification != "" {
		rule.MechanicalJustification = req.MechanicalJustification
	}
	if len(req.PathPattern) > 0 {
		rule.SetPathPattern(req.PathPattern)
	}

	if err := c.vexRuleService.Update(nil, &rule); err != nil {
		return echo.NewHTTPError(500, "failed to update VEX rule").WithInternal(err)
	}

	// Apply the updated rule to existing vulnerabilities
	if err := c.vexRuleService.ApplyRulesToExistingVulns(nil, asset.DesiredUpstreamStateForEvents(), []models.VEXRule{rule}); err != nil {
		// Log the error but don't fail the update - the rule was saved
		ctx.Logger().Error("failed to apply updated VEX rule to existing vulnerabilities", "error", err, "cveID", rule.CVEID)
	}

	return ctx.JSON(200, transformer.VEXRuleToDTO(rule))
}

// @Summary Delete a VEX rule
// @Tags VEXRules
// @Security CookieAuth
// @Security PATAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Param cveId query string true "CVE ID"
// @Param pathPatternHash query string true "Path Pattern Hash"
// @Param vexSource query string true "VEX Source"
// @Success 204
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/vex-rules [delete]
func (c *VEXRuleController) Delete(ctx shared.Context) error {
	asset := shared.GetAsset(ctx)

	cveID := ctx.QueryParam("cveId")
	pathPatternHash := ctx.QueryParam("pathPatternHash")
	vexSource := ctx.QueryParam("vexSource")

	if cveID == "" || pathPatternHash == "" || vexSource == "" {
		return echo.NewHTTPError(400, "cveId, pathPatternHash, and vexSource query parameters are required")
	}

	rule, err := c.vexRuleService.FindByCompositeKey(nil, asset.ID, cveID, pathPatternHash, vexSource)
	if err != nil {
		return echo.NewHTTPError(404, "rule not found").WithInternal(err)
	}

	// Verify the rule belongs to this asset
	if rule.AssetID != asset.ID {
		return echo.NewHTTPError(403, "rule does not belong to this asset")
	}

	if err := c.vexRuleService.Delete(nil, rule); err != nil {
		return echo.NewHTTPError(500, "failed to delete VEX rule").WithInternal(err)
	}

	return ctx.NoContent(204)
}
