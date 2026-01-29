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
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/services"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/labstack/echo/v4"
)

type FalsePositiveRuleController struct {
	falsePositiveRuleService *services.FalsePositiveRuleService
}

func NewFalsePositiveRuleController(falsePositiveRuleService *services.FalsePositiveRuleService) *FalsePositiveRuleController {
	return &FalsePositiveRuleController{
		falsePositiveRuleService: falsePositiveRuleService,
	}
}

type CreateFalsePositiveRuleRequest struct {
	CVEID                   string                           `json:"cveId" validate:"required"`
	Justification           string                           `json:"justification" validate:"required"`
	MechanicalJustification dtos.MechanicalJustificationType `json:"mechanicalJustification"`
	PathPattern             []string                         `json:"pathPattern" validate:"required,min=1"`
}

type UpdateFalsePositiveRuleRequest struct {
	CVEID                   string                           `json:"cveId"`
	Justification           string                           `json:"justification"`
	MechanicalJustification dtos.MechanicalJustificationType `json:"mechanicalJustification"`
	PathPattern             []string                         `json:"pathPattern"`
}

// @Summary List false positive rules for an asset
// @Tags FalsePositiveRules
// @Security CookieAuth
// @Security PATAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Success 200 {array} dtos.FalsePositiveRuleDTO
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/false-positive-rules [get]
func (c *FalsePositiveRuleController) List(ctx shared.Context) error {
	asset := shared.GetAsset(ctx)

	rules, err := c.falsePositiveRuleService.FindByAssetID(nil, asset.ID)
	if err != nil {
		return echo.NewHTTPError(500, "failed to list false positive rules").WithInternal(err)
	}

	result := make([]dtos.FalsePositiveRuleDTO, len(rules))
	for i, rule := range rules {
		result[i] = transformer.FalsePositiveRuleToDTO(rule)
	}

	return ctx.JSON(200, result)
}

// @Summary Get a false positive rule by ID
// @Tags FalsePositiveRules
// @Security CookieAuth
// @Security PATAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Param ruleId path string true "Rule ID"
// @Success 200 {object} dtos.FalsePositiveRuleDTO
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/false-positive-rules/{ruleId} [get]
func (c *FalsePositiveRuleController) Get(ctx shared.Context) error {
	asset := shared.GetAsset(ctx)
	ruleID, err := uuid.Parse(ctx.Param("ruleId"))
	if err != nil {
		return echo.NewHTTPError(400, "invalid rule ID")
	}

	rule, err := c.falsePositiveRuleService.FindByID(nil, ruleID)
	if err != nil {
		return echo.NewHTTPError(404, "rule not found").WithInternal(err)
	}

	// Verify the rule belongs to this asset
	if rule.AssetID != asset.ID {
		return echo.NewHTTPError(403, "rule does not belong to this asset")
	}

	return ctx.JSON(200, transformer.FalsePositiveRuleToDTO(rule))
}

// @Summary Create a false positive rule
// @Tags FalsePositiveRules
// @Security CookieAuth
// @Security PATAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Param body body CreateFalsePositiveRuleRequest true "Rule data"
// @Success 201 {object} dtos.FalsePositiveRuleDTO
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/false-positive-rules [post]
func (c *FalsePositiveRuleController) Create(ctx shared.Context) error {
	asset := shared.GetAsset(ctx)
	session := shared.GetSession(ctx)

	var req CreateFalsePositiveRuleRequest
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

	rule := &models.FalsePositiveRule{
		AssetID:                 asset.ID,
		CVEID:                   req.CVEID,
		Justification:           req.Justification,
		MechanicalJustification: req.MechanicalJustification,
		PathPattern:             req.PathPattern,
		CreatedByID:             session.GetUserID(),
	}

	if err := c.falsePositiveRuleService.Create(nil, rule); err != nil {
		return echo.NewHTTPError(500, "failed to create false positive rule").WithInternal(err)
	}

	return ctx.JSON(201, transformer.FalsePositiveRuleToDTO(*rule))
}

// @Summary Update a false positive rule
// @Tags FalsePositiveRules
// @Security CookieAuth
// @Security PATAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Param ruleId path string true "Rule ID"
// @Param body body UpdateFalsePositiveRuleRequest true "Updated rule data"
// @Success 200 {object} dtos.FalsePositiveRuleDTO
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/false-positive-rules/{ruleId} [put]
func (c *FalsePositiveRuleController) Update(ctx shared.Context) error {
	asset := shared.GetAsset(ctx)
	ruleID, err := uuid.Parse(ctx.Param("ruleId"))
	if err != nil {
		return echo.NewHTTPError(400, "invalid rule ID")
	}

	var req UpdateFalsePositiveRuleRequest
	if err := ctx.Bind(&req); err != nil {
		return echo.NewHTTPError(400, "invalid request body").WithInternal(err)
	}

	rule, err := c.falsePositiveRuleService.FindByID(nil, ruleID)
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
		rule.PathPattern = req.PathPattern
	}

	if err := c.falsePositiveRuleService.Update(nil, &rule); err != nil {
		return echo.NewHTTPError(500, "failed to update false positive rule").WithInternal(err)
	}

	return ctx.JSON(200, transformer.FalsePositiveRuleToDTO(rule))
}

// @Summary Delete a false positive rule
// @Tags FalsePositiveRules
// @Security CookieAuth
// @Security PATAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Param ruleId path string true "Rule ID"
// @Success 204
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/false-positive-rules/{ruleId} [delete]
func (c *FalsePositiveRuleController) Delete(ctx shared.Context) error {
	asset := shared.GetAsset(ctx)
	ruleID, err := uuid.Parse(ctx.Param("ruleId"))
	if err != nil {
		return echo.NewHTTPError(400, "invalid rule ID")
	}

	rule, err := c.falsePositiveRuleService.FindByID(nil, ruleID)
	if err != nil {
		return echo.NewHTTPError(404, "rule not found").WithInternal(err)
	}

	// Verify the rule belongs to this asset
	if rule.AssetID != asset.ID {
		return echo.NewHTTPError(403, "rule does not belong to this asset")
	}

	if err := c.falsePositiveRuleService.Delete(nil, ruleID); err != nil {
		return echo.NewHTTPError(500, "failed to delete false positive rule").WithInternal(err)
	}

	return ctx.NoContent(204)
}
