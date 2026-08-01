package controllers

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/services"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/labstack/echo/v4"
	"go.opentelemetry.io/otel/attribute"
)

type VexRuleRecommendationController struct {
	vexRuleRepository               shared.VEXRuleRepository
	vexRuleRecommendationRepository shared.VEXRuleRecommendationRepository
	assetRepository                 shared.AssetRepository
	dependencyVulnRepository        shared.DependencyVulnRepository
}

func NewVexRuleRecommendationController(vexRuleRepository shared.VEXRuleRepository, vexRuleRecommendationRepository shared.VEXRuleRecommendationRepository, assetRepository shared.AssetRepository, dependencyVulnRepository shared.DependencyVulnRepository) *VexRuleRecommendationController {
	return &VexRuleRecommendationController{
		vexRuleRepository:               vexRuleRepository,
		vexRuleRecommendationRepository: vexRuleRecommendationRepository,
		assetRepository:                 assetRepository,
		dependencyVulnRepository:        dependencyVulnRepository,
	}
}

// @Summary Get a crowdsourced VEX recommendation for a dependency vuln
// @Tags CrowdsourcedVexing
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Param dependencyVulnID path string true "Dependency vuln ID"
// @Success 200 {object} dtos.VexRuleRecommendation
// @Success 204 "No recommendation available"
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/vex-rules/recommendations/{dependencyVulnID} [get]
func (c *VexRuleRecommendationController) Recommend(ctx shared.Context) error {
	reqCtx, span := controllersTracer.Start(ctx.Request().Context(), "CrowdsourcedVexingController.Recommend")
	defer span.End()
	ctx.SetRequest(ctx.Request().WithContext(reqCtx))

	dependencyVulnID := ctx.Param("dependencyVulnID")
	if dependencyVulnID == "" {
		return echo.NewHTTPError(400, "dependencyVulnId query parameter is required")
	}
	span.SetAttributes(attribute.String("dependencyVuln.id", dependencyVulnID))

	dependencyVulnIDParsed, err := uuid.Parse(dependencyVulnID)
	if err != nil {
		return traceErr(span, 400, "could not parse vuln ID to uuid", err)
	}

	vuln, err := c.dependencyVulnRepository.Read(reqCtx, nil, dependencyVulnIDParsed)
	if err != nil {
		return traceErr(span, 500, "Could not calculate recommendation.", err)
	}

	vexRules, err := c.vexRuleRepository.All(reqCtx, nil)
	if err != nil {
		return traceErr(span, 500, "Could not calculate recommendation.", err)
	}

	assetIDs, err := sessionAvailableAssetIDs(ctx)
	if err != nil {
		return traceErr(span, 500, "Could not calculate recommendation.", err)
	}

	matchingSessionRule, err := services.MatchingSessionAccessibleRules(reqCtx, []models.DependencyVuln{vuln}, vexRules, assetIDs)
	if err != nil {
		return traceErr(span, 500, "Could not calculate recommendation.", err)
	}

	// we need to get the amount of dependency vulns, this rule applies to, so we can set the AppliesToAmountOfDependencyVulns field in the recommendation DTO
	allOpenVulns, err := c.dependencyVulnRepository.GetAllOpenVulnsByAssetIDWithoutEvents(reqCtx, nil, vuln.AssetID)
	if err != nil {
		return traceErr(span, 500, "Could not calculate recommendation.", err)
	}

	if rule, ok := matchingSessionRule[vuln.ID]; ok {
		matches, err := services.MatchRulesToVulns(ctx.Request().Context(), []models.UpstreamVEXRule{rule.UpstreamVEXRule}, allOpenVulns)
		if err != nil {
			return traceErr(span, 500, "Could not calculate recommendation.", err)
		}

		asset, err := c.assetRepository.ReadWithProject(reqCtx, nil, rule.AssetID)
		if err != nil {
			return traceErr(span, 500, "Could not calculate recommendation.", err)
		}
		return ctx.JSON(200, transformer.VEXRuleToOriginRecommendationDTO(rule, len(matches[rule.ID]), asset.Slug, asset.Project.Slug))
	}

	// no session rule was found - lets look for upstream or crowdsourced recommendations
	recommendations, err := c.vexRuleRecommendationRepository.FindByDependencyVulnIDs(reqCtx, nil, []uuid.UUID{dependencyVulnIDParsed})
	if err != nil {
		return traceErr(span, 500, "Could not calculate recommendation.", err)
	}

	if len(recommendations) == 0 {
		return ctx.NoContent(204)
	}

	selectedRecommendation := recommendations[dependencyVulnIDParsed]
	var selectedRecommendationEvalStruct models.UpstreamVEXRule
	if selectedRecommendation.VEXRuleID != "" {
		selectedRecommendationEvalStruct = transformer.VEXRuleToUpstreamVEXRule(selectedRecommendation.VEXRule)
	} else if selectedRecommendation.UpstreamVEXRuleID != "" {
		selectedRecommendationEvalStruct = selectedRecommendation.UpstreamVEXRule
	}

	matches, err := services.MatchRulesToVulns(ctx.Request().Context(), []models.UpstreamVEXRule{selectedRecommendationEvalStruct}, allOpenVulns)

	return ctx.JSON(200, transformer.VEXRuleRecommendationToDTO(recommendations[dependencyVulnIDParsed], len(matches[selectedRecommendation.VEXRuleID])))
}

// @Summary Get crowdsourced VEX recommendations for all vulns of an asset
// @Tags CrowdsourcedVexing
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Success 200 {object} map[string]dtos.VexRuleRecommendation
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/vex-rules/recommendations [get]
func (c *VexRuleRecommendationController) RecommendForAsset(ctx shared.Context) error {
	reqCtx, span := controllersTracer.Start(ctx.Request().Context(), "CrowdsourcedVexingController.RecommendForAsset")
	defer span.End()
	ctx.SetRequest(ctx.Request().WithContext(reqCtx))

	asset := shared.GetAsset(ctx)
	span.SetAttributes(attribute.String("asset.id", asset.ID.String()))

	vulns, err := c.dependencyVulnRepository.GetAllOpenVulnsByAssetIDWithoutEvents(reqCtx, nil, asset.ID)
	if err != nil {
		return traceErr(span, 500, "Could not calculate recommendation.", err)
	}
	span.SetAttributes(attribute.Int("dependencyVulns.total", len(vulns)))

	vexRules, err := c.vexRuleRepository.All(reqCtx, nil)
	if err != nil {
		return traceErr(span, 500, "Could not calculate recommendation.", err)
	}
	hasAccessToAssetIDs, err := sessionAvailableAssetIDs(ctx)
	if err != nil {
		return traceErr(span, 500, "Could not calculate recommendation.", err)
	}

	matchingSessionRules, err := services.MatchingSessionAccessibleRules(reqCtx, vulns, vexRules, hasAccessToAssetIDs)
	if err != nil {
		return traceErr(span, 500, "Could not calculate recommendation.", err)
	}
	// fetch all assets for the matched rules in one query to avoid N+1 queries
	assetIDs := make([]uuid.UUID, 0, len(matchingSessionRules))
	for _, rule := range matchingSessionRules {
		assetIDs = append(assetIDs, rule.AssetID)
	}

	assets, err := c.assetRepository.ReadWithProjects(reqCtx, nil, assetIDs)
	if err != nil {
		return traceErr(span, 500, "Could not calculate recommendation.", err)
	}
	// create a map of assetID to asset for easy lookup

	assetsByID := make(map[uuid.UUID]models.Asset)
	for _, asset := range assets {
		assetsByID[asset.ID] = asset
	}

	// build those recommendations already
	recommendations := make(map[uuid.UUID]dtos.VexRuleRecommendation, len(matchingSessionRules))

	// look for unmatched vulns that don't have any matching rules for the session
	unmatchedVulnIDs := make([]uuid.UUID, 0, len(vulns))
	for _, vuln := range vulns {
		if _, ok := matchingSessionRules[vuln.ID]; !ok {
			unmatchedVulnIDs = append(unmatchedVulnIDs, vuln.ID)
		}
	}

	storedRecommendations, err := c.vexRuleRecommendationRepository.FindByDependencyVulnIDs(reqCtx, nil, unmatchedVulnIDs)
	if err != nil {
		return traceErr(span, 500, "Could not calculate recommendation.", err)
	}

	appliesToAmountOfDependencyVulns := make(map[string]int, len(matchingSessionRules)+len(storedRecommendations))
	for _, rule := range matchingSessionRules {
		appliesToAmountOfDependencyVulns[rule.ID]++
	}
	for _, recommendation := range storedRecommendations {
		if recommendation.VEXRuleID != "" {
			appliesToAmountOfDependencyVulns[recommendation.VEXRuleID]++
		}
		if recommendation.UpstreamVEXRuleID != "" {
			appliesToAmountOfDependencyVulns[recommendation.UpstreamVEXRuleID]++
		}
	}

	for vulnID, rule := range matchingSessionRules {
		assetWithProject := assetsByID[rule.AssetID]
		recommendations[vulnID] = transformer.VEXRuleToOriginRecommendationDTO(rule, appliesToAmountOfDependencyVulns[rule.ID], assetWithProject.Project.Slug, assetWithProject.Slug)
	}

	// inject all stored recommendations into the recommendations map - and convert them
	for vulnID, recommendation := range storedRecommendations {
		recommendations[vulnID] = transformer.VEXRuleRecommendationToDTO(recommendation, appliesToAmountOfDependencyVulns[recommendation.VEXRuleID])
	}

	return ctx.JSON(200, recommendations)
}
