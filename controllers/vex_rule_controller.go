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

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/google/uuid"
	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/services"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/l3montree-dev/devguard/vexrules"
	"github.com/labstack/echo/v4"
)

const vulnCacheTTL = 2 * time.Minute
const vulnCacheSize = 32

var vulnMapCache = expirable.NewLRU[uuid.UUID, []map[string]any](vulnCacheSize, nil, vulnCacheTTL)

type VEXRuleController struct {
	vexRuleRepository        shared.VEXRuleRepository
	vulnEventRepository      shared.VulnEventRepository
	statisticsService        shared.StatisticsService
	dependencyVulnRepository shared.DependencyVulnRepository
	dependencyVulnService    shared.DependencyVulnService
	assetVersionRepository   shared.AssetVersionRepository
	utils.FireAndForgetSynchronizer
}

func NewVEXRuleController(vexRuleRepository shared.VEXRuleRepository, vulnEventRepository shared.VulnEventRepository, statisticsService shared.StatisticsService, dependencyVulnRepository shared.DependencyVulnRepository, dependencyVulnService shared.DependencyVulnService, assetVersionRepository shared.AssetVersionRepository, synchronizer utils.FireAndForgetSynchronizer) *VEXRuleController {
	return &VEXRuleController{
		vexRuleRepository:        vexRuleRepository,
		vulnEventRepository:      vulnEventRepository,
		statisticsService:        statisticsService,
		dependencyVulnRepository: dependencyVulnRepository,
		dependencyVulnService:    dependencyVulnService,
		assetVersionRepository:   assetVersionRepository,

		FireAndForgetSynchronizer: synchronizer,
	}
}

func (c *VEXRuleController) countMatchingVulns(ctx context.Context, rule models.VEXRule) (int, error) {
	counts, err := c.vulnEventRepository.CountByVexRuleIDs(ctx, nil, []string{rule.ID})
	if err != nil {
		return 0, err
	}
	return counts[rule.ID], nil
}

func (c *VEXRuleController) countMatchingVulnsForRules(ctx context.Context, rules []models.VEXRule) (map[string]int, error) {
	if len(rules) == 0 {
		return make(map[string]int), nil
	}
	ruleIDs := utils.Map(rules, func(r models.VEXRule) string { return r.ID })
	return c.vulnEventRepository.CountByVexRuleIDs(ctx, nil, ruleIDs)
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
	reqCtx, span := controllersTracer.Start(ctx.Request().Context(), "VEXRuleController.List")
	defer span.End()
	ctx.SetRequest(ctx.Request().WithContext(reqCtx))

	asset := shared.GetAsset(ctx)
	span.SetAttributes(attribute.String("asset.id", asset.ID.String()))

	pageInfo := shared.GetPageInfo(ctx)
	search := ctx.QueryParam("search")
	filterQuery := shared.GetFilterQuery(ctx)
	sortQuery := shared.GetSortQuery(ctx)

	pagedRules, err := c.vexRuleRepository.FindByAssetIDPaged(reqCtx, nil, asset.ID, pageInfo, search, filterQuery, sortQuery)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return echo.NewHTTPError(500, "failed to list VEX rules").WithInternal(err)
	}
	span.SetAttributes(attribute.Int("rules.page_size", len(pagedRules.Data)))

	counts, err := c.countMatchingVulnsForRules(reqCtx, pagedRules.Data)
	if err != nil {
		span.RecordError(err)
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

	rule, err := c.vexRuleRepository.FindByID(ctx.Request().Context(), nil, ruleID)
	if err != nil {
		return echo.NewHTTPError(404, "rule not found").WithInternal(err)
	}

	if rule.AssetID != asset.ID {
		return echo.NewHTTPError(403, "rule does not belong to this asset")
	}

	count, err := c.countMatchingVulns(ctx.Request().Context(), rule)
	if err != nil {
		ctx.Logger().Error("failed to count matching vulns for rule", "ruleId", rule.ID, "error", err)
		count = 0
	}

	return ctx.JSON(200, transformer.VEXRuleToDTOWithCount(rule, count))
}

func (c *VEXRuleController) cachedVulns(ctx shared.Context) ([]map[string]any, error) {
	assetID := shared.GetAsset(ctx).ID

	if vulns, ok := vulnMapCache.Get(assetID); ok {
		return vulns, nil
	}

	vulns, err := utils.CollectSeq2(c.dependencyVulnRepository.GetAllOpenVulnsByAssetIDWithoutEvents(ctx.Request().Context(), nil, assetID, -1))
	if err != nil {
		return nil, err
	}

	// prepare the slice already for eval
	vulnMaps, err := vexrules.PrepareVulnsForEval(ctx.Request().Context(), vulns)
	if err != nil {
		return nil, err
	}

	vulnMapCache.Add(assetID, vulnMaps)
	return vulnMaps, nil
}

// @Summary Test VEX rules against open vulnerabilities
// @Tags VEXRules
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Param body body dtos.TestVEXRulesRequest true "CEL expressions to test"
// @Success 200 {object} map[string]int
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/vex-rules/test [post]
func (c *VEXRuleController) TestVexRules(ctx shared.Context) error {

	vulns, err := c.cachedVulns(ctx)
	if err != nil {
		return echo.NewHTTPError(500, "failed to fetch vulns for asset").WithInternal(err)
	}
	response := make(map[string]int)

	var req dtos.TestVEXRulesRequest
	if err := ctx.Bind(&req); err != nil {
		return echo.NewHTTPError(400, "invalid request body").WithInternal(err)
	}
	if err := dtos.V.Struct(&req); err != nil {
		return echo.NewHTTPError(400, "invalid request body").WithInternal(err)
	}

	var vexRules []models.UpstreamVEXRule
	for _, expr := range req.CelExpression {
		vexRules = append(vexRules, models.UpstreamVEXRule{
			ID:            expr,
			CELExpression: expr,
		})
		response[expr] = 0
	}

	requestCtx := ctx.Request().Context()

	compiledRules, err := vexrules.CompileRules(requestCtx, vexRules)
	if err != nil {
		return echo.NewHTTPError(500, "failed to compile CEL expression").WithInternal(err)
	}

	matches, err := vexrules.EvalCompiledRules(requestCtx, compiledRules, vulns)
	if err != nil {
		return echo.NewHTTPError(500, "failed to evaluate CEL expression").WithInternal(err)
	}

	for _, rule := range vexRules {
		for _, matchingRuleIDs := range matches {
			for _, matchingRuleID := range matchingRuleIDs {
				if matchingRuleID == rule.ID {
					response[rule.CELExpression]++
				}
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
// @Param body body dtos.CreateVEXRuleRequest true "Rule data"
// @Success 201 {object} dtos.VEXRuleDTO
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/vex-rules [post]
func (c *VEXRuleController) Create(ctx shared.Context) error {
	asset := shared.GetAsset(ctx)
	session := shared.GetSession(ctx)

	var req dtos.CreateVEXRuleRequest
	if err := ctx.Bind(&req); err != nil {
		return echo.NewHTTPError(400, "invalid request body").WithInternal(err)
	}
	if err := dtos.V.Struct(&req); err != nil {
		return echo.NewHTTPError(400, "invalid request body").WithInternal(err)
	}

	eventType := req.EventType
	if eventType != dtos.EventTypeAccepted {
		eventType = dtos.EventTypeFalsePositive
	}

	rule := &models.VEXRule{
		AssetID:        asset.ID,
		CreatedByID:    session.GetActorName(),
		Enabled:        true, // Manual rules are always enabled
		WasRecommended: req.WasRecommended,
		UpstreamVEXRule: models.UpstreamVEXRule{
			Title:                   req.Title,
			VexSource:               "manual",
			Justification:           req.Justification,
			MechanicalJustification: req.MechanicalJustification,
			EventType:               eventType,
			CELExpression:           req.CELExpression,
		},
	}

	reqCtx := ctx.Request().Context()
	tx := c.vexRuleRepository.Begin(reqCtx)
	defer tx.Rollback()

	rule.EnsureID()
	if err := c.vexRuleRepository.Create(reqCtx, tx, rule); err != nil {
		return echo.NewHTTPError(500, "failed to create VEX rule").WithInternal(err)
	}

	existingVulns, fetchErr := utils.CollectSeq2(c.dependencyVulnRepository.GetAllOpenVulnsByAssetID(reqCtx, tx, asset.ID, -1))
	var vulns []models.DependencyVuln
	if fetchErr != nil {
		slog.Error("failed to fetch existing vulns for asset", "error", fetchErr, "assetID", asset.ID)
		tx.Rollback()
	} else {
		var events []models.VulnEvent
		var applyErr error
		vulns, events, applyErr = services.ApplyVEXRulesToVulns(reqCtx, []models.VEXRule{*rule}, existingVulns)
		if applyErr != nil {
			slog.Error("failed to apply VEX rules to vulns", "error", applyErr)
			tx.Rollback()
		} else if len(vulns) > 0 {
			if err := c.dependencyVulnRepository.SaveBatchBestEffort(reqCtx, tx, vulns); err != nil {
				slog.Error("failed to save updated vulns", "error", err)
				tx.Rollback()
			}
			if err := c.vulnEventRepository.SaveBatchBestEffort(reqCtx, tx, events); err != nil {
				slog.Error("failed to save events", "error", err)
				tx.Rollback()
			}
		}
	}
	if err := tx.Commit().Error; err != nil {
		tx.Rollback()
		return echo.NewHTTPError(500, "failed to commit VEX rule creation").WithInternal(err)
	}

	c.syncTicketsForVulns(ctx, asset, vulns)

	count, err := c.countMatchingVulns(reqCtx, *rule)
	if err != nil {
		ctx.Logger().Error("failed to count matching vulns for rule", "ruleId", rule.ID, "error", err)
		count = 0
	}
	c.updateArtifactRiskAggregation(ctx.Request().Context(), asset, vulns)

	return ctx.JSON(201, transformer.VEXRuleToDTOWithCount(*rule, count))
}

// syncTicketsForVulns syncs the third-party ticket (e.g. GitLab issue) for
// every vuln on the default branch that a just-applied VEX rule touched, so
// an existing open ticket reflects the new state instead of staying stale.
func (c *VEXRuleController) syncTicketsForVulns(ctx shared.Context, asset models.Asset, vulns []models.DependencyVuln) {
	defaultAssetVersion, err := c.assetVersionRepository.GetDefaultAssetVersion(ctx.Request().Context(), nil, asset.ID)
	if err != nil {
		slog.Error("failed to get default asset version for ticket sync", "assetID", asset.ID, "error", err)
		return
	}

	defaultBranchVulns := utils.Filter(vulns, func(v models.DependencyVuln) bool {
		return v.AssetVersionName == defaultAssetVersion.Name
	})
	if len(defaultBranchVulns) == 0 {
		return
	}

	userAgent := ctx.Request().UserAgent()
	org := shared.GetOrg(ctx)
	project := shared.GetProject(ctx)
	if err := c.dependencyVulnService.SyncIssues(ctx.Request().Context(), org, project, asset, defaultAssetVersion, defaultBranchVulns, &userAgent); err != nil {
		slog.Error("failed to sync tickets after applying VEX rule", "assetID", asset.ID, "error", err)
	}
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

	tx := c.vexRuleRepository.Begin(reqCtx)
	defer tx.Rollback()

	rule, err := c.vexRuleRepository.FindByID(reqCtx, tx, ruleID)
	if err != nil {
		return echo.NewHTTPError(404, "rule not found").WithInternal(err)
	}

	if rule.AssetID != asset.ID {
		return echo.NewHTTPError(403, "rule does not belong to this asset")
	}
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

			if vuln.Events[j].Type == dtos.EventTypeReopened || vuln.Events[j].Type == dtos.EventTypeAccepted || vuln.Events[j].Type == dtos.EventTypeFalsePositive {
				if *vuln.Events[j].VexRuleID == ruleID {
					continue // Skip events created by the rule being deleted
				}

				justification := "VEX rule deleted, reverting to last state"
				ev.ID = uuid.New()
				ev.Justification = &justification
				ev.UserID = "system"
				ev.CreatedByVexRule = false
				ev.DependencyVulnID = &vuln.ID
				ev.Type = vuln.Events[j].Type
				deletedRuleID := ruleID
				ev.VexRuleID = &deletedRuleID
				found = true
				break
			}
		}

		if !found {
			// this can only happen if the only ever event is detected and the rule is deleted, in which case we default to reopened
			justification := "VEX rule deleted, no previous state found, defaulting to reopened"
			ev.Justification = &justification
			ev.UserID = "system"
			ev.DependencyVulnID = &vuln.ID
			ev.CreatedByVexRule = false
			ev.Type = dtos.EventTypeReopened // Default to reopened if no previous state found
			deletedRuleID := ruleID
			ev.VexRuleID = &deletedRuleID
		}

		if err := c.dependencyVulnRepository.ApplyAndSave(reqCtx, tx, vuln, &ev); err != nil {
			return echo.NewHTTPError(500, "failed to update dependency vuln after VEX rule deletion").WithInternal(err)
		}
	}

	if err := c.vexRuleRepository.Delete(reqCtx, tx, rule); err != nil {
		return echo.NewHTTPError(500, "failed to delete VEX rule").WithInternal(err)
	}

	if err := tx.Commit().Error; err != nil {
		return echo.NewHTTPError(500, "failed to commit VEX rule deletion").WithInternal(err)
	}

	c.updateArtifactRiskAggregation(reqCtx, asset, vulns)

	return ctx.NoContent(204)
}
