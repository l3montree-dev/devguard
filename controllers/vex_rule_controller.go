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
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/labstack/echo/v4"
)

type VEXRuleController struct {
	vexRuleService shared.VEXRuleService
}

func NewVEXRuleController(vexRuleService shared.VEXRuleService) *VEXRuleController {
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
	Enabled                 *bool                            `json:"enabled"` // Pointer to distinguish between not provided and false
}

// @Summary List VEX rules for an asset
// @Tags VEXRules
// @Security CookieAuth
// @Security PATAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Param assetVersionSlug path string true "Asset version slug (ref)"
// @Success 200 {array} dtos.VEXRuleDTO
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/refs/{assetVersionSlug}/vex-rules [get]
func (c *VEXRuleController) List(ctx shared.Context) error {
	asset := shared.GetAsset(ctx)
	assetVersion := shared.GetAssetVersion(ctx)

	rules, err := c.vexRuleService.FindByAssetVersion(nil, asset.ID, assetVersion.Name)
	if err != nil {
		return echo.NewHTTPError(500, "failed to list VEX rules").WithInternal(err)
	}

	// Count matching vulnerabilities for all rules in batch
	counts, err := c.vexRuleService.CountMatchingVulnsForRules(nil, rules)
	if err != nil {
		ctx.Logger().Error("failed to count matching vulns for rules", "error", err)
		counts = make(map[string]int)
	}

	result := make([]dtos.VEXRuleDTO, len(rules))
	for i, rule := range rules {
		result[i] = transformer.VEXRuleToDTOWithCount(rule, counts[rule.ID])
	}

	return ctx.JSON(200, result)
}

// @Summary Get a VEX rule
// @Tags VEXRules
// @Security CookieAuth
// @Security PATAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Param assetVersionSlug path string true "Asset version slug (ref)"
// @Param ruleId path string true "Rule ID"
// @Success 200 {object} dtos.VEXRuleDTO
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/refs/{assetVersionSlug}/vex-rules/{ruleId} [get]
func (c *VEXRuleController) Get(ctx shared.Context) error {
	asset := shared.GetAsset(ctx)

	ruleID := ctx.Param("ruleId")
	if ruleID == "" {
		return echo.NewHTTPError(400, "ruleId path parameter is required")
	}

	rule, err := c.vexRuleService.FindByID(nil, ruleID)
	if err != nil {
		return echo.NewHTTPError(404, "rule not found").WithInternal(err)
	}

	// Verify the rule belongs to this asset
	if rule.AssetID != asset.ID {
		return echo.NewHTTPError(403, "rule does not belong to this asset")
	}

	// Count matching vulnerabilities
	count, err := c.vexRuleService.CountMatchingVulns(nil, rule)
	if err != nil {
		ctx.Logger().Error("failed to count matching vulns for rule", "ruleId", rule.ID, "error", err)
		count = 0
	}

	return ctx.JSON(200, transformer.VEXRuleToDTOWithCount(rule, count))
}

// @Summary Create a VEX rule
// @Tags VEXRules
// @Security CookieAuth
// @Security PATAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Param assetVersionSlug path string true "Asset version slug (ref)"
// @Param body body CreateVEXRuleRequest true "Rule data"
// @Success 201 {object} dtos.VEXRuleDTO
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/refs/{assetVersionSlug}/vex-rules [post]
func (c *VEXRuleController) Create(ctx shared.Context) error {
	asset := shared.GetAsset(ctx)
	assetVersion := shared.GetAssetVersion(ctx)
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
		AssetVersionName:        assetVersion.Name,
		CVEID:                   req.CVEID,
		VexSource:               "manual",
		Justification:           req.Justification,
		MechanicalJustification: req.MechanicalJustification,
		EventType:               dtos.EventTypeFalsePositive,
		PathPattern:             req.PathPattern,
		CreatedByID:             session.GetUserID(),
		Enabled:                 true, // Manual rules are always enabled
	}

	tx := c.vexRuleService.Begin()

	if err := c.vexRuleService.Create(tx, rule); err != nil {
		return echo.NewHTTPError(500, "failed to create VEX rule").WithInternal(err)
	}

	// Apply this rule to all matching existing dependency vulns
	if _, err := c.vexRuleService.ApplyRulesToExistingVulns(tx, []models.VEXRule{*rule}); err != nil {
		slog.Error("failed to apply VEX rule to existing vulnerabilities", "error", err,
			"cveID", rule.CVEID, "assetID", rule.AssetID, "vexSource", rule.VexSource)
		tx.Rollback()
	}
	if err := tx.Commit().Error; err != nil {
		tx.Rollback()
		return echo.NewHTTPError(500, "failed to commit VEX rule creation").WithInternal(err)
	}

	// Count matching vulnerabilities for the response
	count, err := c.vexRuleService.CountMatchingVulns(nil, *rule)
	if err != nil {
		ctx.Logger().Error("failed to count matching vulns for rule", "ruleId", rule.ID, "error", err)
		count = 0
	}

	return ctx.JSON(201, transformer.VEXRuleToDTOWithCount(*rule, count))
}

// @Summary Update a VEX rule
// @Tags VEXRules
// @Security CookieAuth
// @Security PATAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Param assetVersionSlug path string true "Asset version slug (ref)"
// @Param ruleId path string true "Rule ID"
// @Param body body UpdateVEXRuleRequest true "Updated rule data"
// @Success 200 {object} dtos.VEXRuleDTO
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/refs/{assetVersionSlug}/vex-rules/{ruleId} [put]
func (c *VEXRuleController) Update(ctx shared.Context) error {
	asset := shared.GetAsset(ctx)

	ruleID := ctx.Param("ruleId")
	if ruleID == "" {
		return echo.NewHTTPError(400, "ruleId path parameter is required")
	}

	var req UpdateVEXRuleRequest
	if err := ctx.Bind(&req); err != nil {
		return echo.NewHTTPError(400, "invalid request body").WithInternal(err)
	}

	rule, err := c.vexRuleService.FindByID(nil, ruleID)
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

	// Track if we're enabling the rule (to apply it to vulns)
	wasEnabled := rule.Enabled
	if req.Enabled != nil {
		rule.Enabled = *req.Enabled
	}

	if err := c.vexRuleService.Update(nil, &rule); err != nil {
		return echo.NewHTTPError(500, "failed to update VEX rule").WithInternal(err)
	}

	// Apply the rule to existing vulnerabilities if it's enabled
	// Only apply if rule is now enabled (either was already enabled, or just got enabled)
	if rule.Enabled {
		if _, err := c.vexRuleService.ApplyRulesToExistingVulns(nil, []models.VEXRule{rule}); err != nil {
			// Log the error but don't fail the update - the rule was saved
			ctx.Logger().Error("failed to apply updated VEX rule to existing vulnerabilities", "error", err, "cveID", rule.CVEID)
		}
		// Log if rule was just enabled
		if !wasEnabled {
			slog.Info("VEX rule enabled and applied to existing vulnerabilities", "ruleID", rule.ID, "cveID", rule.CVEID)
		}
	}

	// Count matching vulnerabilities for the response
	count, err := c.vexRuleService.CountMatchingVulns(nil, rule)
	if err != nil {
		ctx.Logger().Error("failed to count matching vulns for rule", "ruleId", rule.ID, "error", err)
		count = 0
	}

	return ctx.JSON(200, transformer.VEXRuleToDTOWithCount(rule, count))
}

// @Summary Delete a VEX rule
// @Tags VEXRules
// @Security CookieAuth
// @Security PATAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Param assetVersionSlug path string true "Asset version slug (ref)"
// @Param ruleId path string true "Rule ID"
// @Success 204
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/refs/{assetVersionSlug}/vex-rules/{ruleId} [delete]
func (c *VEXRuleController) Delete(ctx shared.Context) error {
	asset := shared.GetAsset(ctx)

	ruleID := ctx.Param("ruleId")
	if ruleID == "" {
		return echo.NewHTTPError(400, "ruleId path parameter is required")
	}

	rule, err := c.vexRuleService.FindByID(nil, ruleID)
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
