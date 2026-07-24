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
	"context"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel/trace"

	"github.com/google/uuid"
	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/labstack/echo/v4"
)

const vulnCacheTTL = 2 * time.Minute
const vulnCacheSize = 32

var vulnCache = expirable.NewLRU[uuid.UUID, []models.DependencyVuln](vulnCacheSize, nil, vulnCacheTTL)

type VEXRuleController struct {
	vexRuleService           shared.VEXRuleService
	statisticsService        shared.StatisticsService
	dependencyVulnRepository shared.DependencyVulnRepository
	utils.FireAndForgetSynchronizer
}

func NewVEXRuleController(vexRuleService shared.VEXRuleService, statisticsService shared.StatisticsService, dependencyVulnRepository shared.DependencyVulnRepository, synchronizer utils.FireAndForgetSynchronizer) *VEXRuleController {
	return &VEXRuleController{
		vexRuleService:           vexRuleService,
		statisticsService:        statisticsService,
		dependencyVulnRepository: dependencyVulnRepository,

		FireAndForgetSynchronizer: synchronizer,
	}
}

type TestVEXRulesRequest struct {
	ID            string   `json:"id" validate:"required"`
	CelExpression []string `json:"celExpression" validate:"required"`
}
type CreateVEXRuleRequest struct {
	Title                   string                           `json:"title"`
	Justification           string                           `json:"justification" validate:"required"`
	MechanicalJustification dtos.MechanicalJustificationType `json:"mechanicalJustification"`
	PathPattern             []string                         `json:"pathPattern"`
	CELExpression           string                           `json:"celExpression"`
	EventType               dtos.VulnEventType               `json:"eventType"`
}

// @Summary List VEX rules for an asset
// @Tags VEXRules
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Param page query int false "Page number (default: 1)"
// @Param pageSize query int false "Page size (default: 10, max: 100)"
// @Param search query string false "Search term for CVE ID or justification"
// @Success 200 {object} object{pageSize=int,page=int,total=int64,data=[]dtos.VEXRuleDTO}
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/vex-rules [get]
func (c *VEXRuleController) List(ctx shared.Context) error {
	asset := shared.GetAsset(ctx)

	vulnID := ctx.QueryParam("dependencyVulnId")
	if vulnID != "" {
		vulnIDParsed, err := uuid.Parse(vulnID)
		if err != nil {
			return echo.NewHTTPError(400, "could not parse vuln ID to uuid").WithInternal(err)
		}
		rules, err := c.vexRuleService.FindByAssetIDWithMatchingVuln(ctx.Request().Context(), nil, asset.ID, vulnIDParsed)
		if err != nil {
			return echo.NewHTTPError(500, "failed to list VEX rules").WithInternal(err)
		}

		// Count matching vulnerabilities for all rules in batch
		counts, err := c.vexRuleService.CountMatchingVulnsForRules(ctx.Request().Context(), nil, rules)
		if err != nil {
			ctx.Logger().Error("failed to count matching vulns for rules", "error", err)
			counts = make(map[string]int)
		}

		return ctx.JSON(200, utils.Map(rules, func(rule models.VEXRule) any {
			return transformer.VEXRuleToDTOWithCount(rule, counts[rule.ID]) // Count is not needed for this endpoint
		}))
	}

	pageInfo := shared.GetPageInfo(ctx)
	search := ctx.QueryParam("search")
	filterQuery := shared.GetFilterQuery(ctx)
	sortQuery := shared.GetSortQuery(ctx)

	pagedRules, err := c.vexRuleService.FindByAssetIDPaged(ctx.Request().Context(), nil, asset.ID, pageInfo, search, filterQuery, sortQuery)
	if err != nil {
		return echo.NewHTTPError(500, "failed to list VEX rules").WithInternal(err)
	}

	// Count matching vulnerabilities for all rules in batch
	counts, err := c.vexRuleService.CountMatchingVulnsForRules(ctx.Request().Context(), nil, pagedRules.Data)
	if err != nil {
		ctx.Logger().Error("failed to count matching vulns for rules", "error", err)
		counts = make(map[string]int)
	}

	return ctx.JSON(200, pagedRules.Map(func(rule models.VEXRule) any {
		return transformer.VEXRuleToDTOWithCount(rule, counts[rule.ID])
	}))
}

// @Summary Get a VEX rule
// @Tags VEXRules
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Param ruleId path string true "Rule ID"
// @Success 200 {object} dtos.VEXRuleDTO
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/vex-rules/{ruleId} [get]
func (c *VEXRuleController) Get(ctx shared.Context) error {
	asset := shared.GetAsset(ctx)

	ruleID := ctx.Param("ruleId")
	if ruleID == "" {
		return echo.NewHTTPError(400, "ruleId path parameter is required")
	}

	rule, err := c.vexRuleService.FindByID(ctx.Request().Context(), nil, ruleID)
	if err != nil {
		return echo.NewHTTPError(404, "rule not found").WithInternal(err)
	}

	// Verify the rule belongs to this asset
	if rule.AssetID != asset.ID {
		return echo.NewHTTPError(403, "rule does not belong to this asset")
	}

	// Count matching vulnerabilities
	count, err := c.vexRuleService.CountMatchingVulns(ctx.Request().Context(), nil, rule)
	if err != nil {
		ctx.Logger().Error("failed to count matching vulns for rule", "ruleId", rule.ID, "error", err)
		count = 0
	}

	return ctx.JSON(200, transformer.VEXRuleToDTOWithCount(rule, count))
}

func (c *VEXRuleController) cachedVulns(ctx shared.Context) []models.DependencyVuln {
	assetID := shared.GetAsset(ctx).ID

	if vulns, ok := vulnCache.Get(assetID); ok {
		return vulns
	}

	vulns, err := c.dependencyVulnRepository.GetByAssetID(ctx.Request().Context(), nil, assetID)
	if err != nil {
		ctx.Logger().Error("failed to retrieve vulnerabilities", "error", err)
		return nil
	}

	vulnCache.Add(assetID, vulns)
	return vulns
}

func (c *VEXRuleController) TestVexRules(ctx shared.Context) error {

	vulns := c.cachedVulns(ctx)
	response := make(map[string]int)

	var req TestVEXRulesRequest
	if err := ctx.Bind(&req); err != nil {
		return echo.NewHTTPError(400, "invalid request body").WithInternal(err)
	}

	var vexRules []models.VEXRule
	for _, expr := range req.CelExpression {
		vexRules = append(vexRules, models.VEXRule{
			CELExpression: expr,
		})
		response[expr] = 0
	}

	for _, vuln := range vulns {
		for _, rule := range vexRules {
			match, err := c.vexRuleService.EvalCELExpression(ctx.Request().Context(), rule, vuln)
			if err != nil {
				return echo.NewHTTPError(500, "failed to evaluate CEL expression").WithInternal(err)
			}
			if match {
				response[rule.CELExpression]++
			}
		}
	}

	return ctx.JSON(200, response)

}

// @Summary Create a VEX rule
// @Tags VEXRules
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
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
	// a rule either matches via a CEL expression, or via a CVE ID + path pattern
	if req.CELExpression == "" {
		if len(req.PathPattern) == 0 {
			return echo.NewHTTPError(400, "pathPattern must contain at least one element")
		}
	}

	pathPattern := req.PathPattern
	if pathPattern == nil {
		pathPattern = []string{}
	}

	eventType := req.EventType
	if eventType != dtos.EventTypeAccepted {
		eventType = dtos.EventTypeFalsePositive
	}

	rule := &models.VEXRule{
		AssetID:                 asset.ID,
		Title:                   req.Title,
		VexSource:               "manual",
		Justification:           req.Justification,
		MechanicalJustification: req.MechanicalJustification,
		EventType:               eventType,
		CELExpression:           req.CELExpression,
		CreatedByID:             session.GetActorName(),
		Enabled:                 true, // Manual rules are always enabled
	}

	tx := c.vexRuleService.Begin(ctx.Request().Context())
	defer tx.Rollback()

	if err := c.vexRuleService.Create(ctx.Request().Context(), tx, rule); err != nil {
		return echo.NewHTTPError(500, "failed to create VEX rule").WithInternal(err)
	}

	// Apply this rule to all matching existing dependency vulns
	vulns, err := c.vexRuleService.ApplyRulesToExistingVulns(ctx.Request().Context(), tx, []models.VEXRule{*rule})
	if err != nil {
		slog.Error("failed to apply VEX rule to existing vulnerabilities", "error", err,
			"assetID", rule.AssetID, "vexSource", rule.VexSource)
		tx.Rollback()
	}
	if err := tx.Commit().Error; err != nil {
		tx.Rollback()
		return echo.NewHTTPError(500, "failed to commit VEX rule creation").WithInternal(err)
	}

	// Count matching vulnerabilities for the response
	count, err := c.vexRuleService.CountMatchingVulns(ctx.Request().Context(), nil, *rule)
	if err != nil {
		ctx.Logger().Error("failed to count matching vulns for rule", "ruleId", rule.ID, "error", err)
		count = 0
	}
	// Update artifact risk aggregations in background
	c.updateArtifactRiskAggregation(ctx.Request().Context(), asset, vulns)

	return ctx.JSON(201, transformer.VEXRuleToDTOWithCount(*rule, count))
}

func (c *VEXRuleController) updateArtifactRiskAggregation(ctx context.Context, asset models.Asset, vulns []models.DependencyVuln) {
	linkedCtx := trace.ContextWithSpan(context.Background(), trace.SpanFromContext(ctx))
	c.FireAndForget(func() {
		artifacts := map[string]models.Artifact{}
		for _, vuln := range vulns {
			for _, artifact := range vuln.Artifacts {
				artifacts[artifact.ArtifactName] = artifact
			}
		}
		for _, artifact := range artifacts {
			if err := c.statisticsService.UpdateArtifactRiskAggregation(linkedCtx, nil, &artifact, asset.ID, time.Now().Add(-30*time.Minute), time.Now()); err != nil {
				slog.Error("failed to update artifact risk aggregation", "artifact", artifact.ArtifactName, "error", err)
			}
		}
	})
}

// @Summary Delete a VEX rule
// @Tags VEXRules
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Param ruleId path string true "Rule ID"
// @Success 204
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/vex-rules/{ruleId} [delete]
func (c *VEXRuleController) Delete(ctx shared.Context) error {
	asset := shared.GetAsset(ctx)

	ruleID := ctx.Param("ruleId")
	if ruleID == "" {
		return echo.NewHTTPError(400, "ruleId path parameter is required")
	}

	reqCtx := ctx.Request().Context()

	tx := c.vexRuleService.Begin(reqCtx)
	defer tx.Rollback()

	rule, err := c.vexRuleService.FindByID(reqCtx, tx, ruleID)
	if err != nil {
		return echo.NewHTTPError(404, "rule not found").WithInternal(err)
	}

	// Verify the rule belongs to this asset
	if rule.AssetID != asset.ID {
		return echo.NewHTTPError(403, "rule does not belong to this asset")
	}
	//fetch the dependency vulns that match this rule to update the state to the last state after the rule is deleted
	vulns, err := c.dependencyVulnRepository.GetByVexRuleID(reqCtx, tx, ruleID)
	if err != nil {
		return echo.NewHTTPError(500, "failed to fetch dependency vulns for VEX rule").WithInternal(err)
	}

	for i := range vulns {
		vuln := &vulns[i]
		if vuln.State == dtos.VulnStateFixed {
			continue // Skip fixed vulnerabilities
		}

		var ev models.VulnEvent
		found := false
		for j := len(vuln.Events) - 1; j >= 0; j-- {
			if (vuln.Events[j].Type == dtos.EventTypeReopened || vuln.Events[j].Type == dtos.EventTypeAccepted || vuln.Events[j].Type == dtos.EventTypeFalsePositive) && vuln.Events[j].VexRuleID == nil {
				justification := "VEX rule deleted, reverting to last state"
				ev = vuln.Events[j]
				ev.ID = uuid.New()
				ev.Justification = &justification
				ev.UserID = "system"
				ev.CreatedByVexRule = false
				found = true
				break
			}
		}
		if !found {
			justification := "VEX rule deleted, no previous state found, defaulting to reopened"
			ev.Justification = &justification
			ev.UserID = "system"
			ev.DependencyVulnID = &vuln.ID
			ev.CreatedByVexRule = false
			ev.Type = dtos.EventTypeReopened // Default to reopened if no previous state found
		}

		if err := c.dependencyVulnRepository.ApplyAndSave(reqCtx, tx, vuln, &ev); err != nil {
			return echo.NewHTTPError(500, "failed to update dependency vuln after VEX rule deletion").WithInternal(err)
		}
	}

	if err := c.vexRuleService.Delete(reqCtx, tx, rule); err != nil {
		return echo.NewHTTPError(500, "failed to delete VEX rule").WithInternal(err)
	}

	if err := tx.Commit().Error; err != nil {
		return echo.NewHTTPError(500, "failed to commit VEX rule deletion").WithInternal(err)
	}

	// Update artifact risk aggregations in background
	c.updateArtifactRiskAggregation(reqCtx, asset, vulns)

	return ctx.NoContent(204)
}
