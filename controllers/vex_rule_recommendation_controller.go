package controllers

import (
	"slices"
	"strings"

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
// @Success 404 "Dependency vulnerability not found"
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
		if shared.IsNotFound(err) {
			return ctx.NoContent(404)
		}
		return traceErr(span, 500, "Could not calculate recommendation.", err)
	}

	sessionAssetIDs, err := sessionAssetIDsExcluding(ctx, vuln.AssetID)
	if err != nil {
		return traceErr(span, 500, "Could not calculate recommendation.", err)
	}

	vexRules, err := c.vexRuleRepository.FindByAssetIDs(reqCtx, nil, sessionAssetIDs)
	if err != nil {
		return traceErr(span, 500, "Could not calculate recommendation.", err)
	}

	matchingSessionRules, err := services.MatchingRules(reqCtx, []models.DependencyVuln{vuln}, vexRules)
	if err != nil {
		return traceErr(span, 500, "Could not calculate recommendation.", err)
	}

	// we need to get the amount of dependency vulns, this rule applies to, so we can set the AppliesToAmountOfDependencyVulns field in the recommendation DTO
	allOpenVulns, err := c.dependencyVulnRepository.GetVulnsDistinctBySignature(reqCtx, nil, vuln.AssetID, dtos.VulnStateOpen)
	if err != nil {
		return traceErr(span, 500, "Could not calculate recommendation.", err)
	}

	if rules := matchingSessionRules[vuln.ID]; len(rules) > 0 {
		rule := rules[0]
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
	var matchesKey string
	if selectedRecommendation.VEXRuleID != nil {
		selectedRecommendationEvalStruct = transformer.VEXRuleToUpstreamVEXRule(selectedRecommendation.VEXRule)
		matchesKey = *selectedRecommendation.VEXRuleID
	} else if selectedRecommendation.UpstreamVEXRuleID != nil {
		selectedRecommendationEvalStruct = selectedRecommendation.UpstreamVEXRule
		matchesKey = *selectedRecommendation.UpstreamVEXRuleID
	}

	matches, err := services.MatchRulesToVulns(ctx.Request().Context(), []models.UpstreamVEXRule{selectedRecommendationEvalStruct}, allOpenVulns)

	if err != nil {
		return traceErr(span, 500, "Could not calculate recommendation.", err)
	}
	return ctx.JSON(200, transformer.VEXRuleRecommendationToDTO(recommendations[dependencyVulnIDParsed], len(matches[matchesKey])))
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

	sessionAssetIDs, err := sessionAssetIDsExcluding(ctx, asset.ID)
	if err != nil {
		return traceErr(span, 500, "Could not calculate recommendation.", err)
	}

	vexRules, err := c.vexRuleRepository.FindByAssetIDs(reqCtx, nil, sessionAssetIDs)
	if err != nil {
		return traceErr(span, 500, "Could not calculate recommendation.", err)
	}
	if len(vexRules) == 0 {
		return ctx.JSON(200, []dtos.VexRuleRecommendation{})
	}

	// split vexrules into open and closed
	reopenRules := make([]models.VEXRule, 0)
	closedRules := make([]models.VEXRule, 0)
	for _, rule := range vexRules {
		if rule.EventType == dtos.EventTypeReopened {
			reopenRules = append(reopenRules, rule)
		} else {
			closedRules = append(closedRules, rule)
		}
	}

	// closed rules (accept/false-positive) only make sense against open vulns, and
	// reopen rules only make sense against already-accepted vulns - so match each
	// rule set against its own vuln set instead of running every rule against every vuln.
	openVulns, err := c.dependencyVulnRepository.GetVulnsDistinctBySignature(reqCtx, nil, asset.ID, dtos.VulnStateOpen)
	if err != nil {
		return traceErr(span, 500, "Could not calculate recommendation.", err)
	}
	acceptedVulns, err := c.dependencyVulnRepository.GetVulnsDistinctBySignature(reqCtx, nil, asset.ID, dtos.VulnStateAccepted)
	if err != nil {
		return traceErr(span, 500, "Could not calculate recommendation.", err)
	}
	vulns := append(openVulns, acceptedVulns...)
	span.SetAttributes(attribute.Int("dependencyVulns.total", len(vulns)))

	matchingClosedRules, err := services.MatchingRules(reqCtx, openVulns, closedRules)
	if err != nil {
		return traceErr(span, 500, "Could not calculate recommendation.", err)
	}
	matchingReopenRules, err := services.MatchingRules(reqCtx, acceptedVulns, reopenRules)
	if err != nil {
		return traceErr(span, 500, "Could not calculate recommendation.", err)
	}
	matchingSessionRules := matchingClosedRules
	for vulnID, rules := range matchingReopenRules {
		matchingSessionRules[vulnID] = append(matchingSessionRules[vulnID], rules...)
	}
	// fetch all assets for the matched rules in one query to avoid N+1 queries
	assetIDs := make([]uuid.UUID, 0, len(matchingSessionRules))
	for _, rules := range matchingSessionRules {
		for _, rule := range rules {
			assetIDs = append(assetIDs, rule.AssetID)
		}
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

	// look for unmatched vulns that don't have any matching rules for the session
	unmatchedVulnIDs := make([]uuid.UUID, 0, len(vulns))
	for _, vuln := range vulns {
		if len(matchingSessionRules[vuln.ID]) == 0 {
			unmatchedVulnIDs = append(unmatchedVulnIDs, vuln.ID)
		}
	}

	storedRecommendations, err := c.vexRuleRecommendationRepository.FindByDependencyVulnIDs(reqCtx, nil, unmatchedVulnIDs)
	if err != nil {
		return traceErr(span, 500, "Could not calculate recommendation.", err)
	}

	recommendations := buildDedupedVexRuleRecommendations(matchingSessionRules, storedRecommendations, assetsByID)

	return ctx.JSON(200, recommendations)
}

func buildDedupedVexRuleRecommendations(matchingSessionRules map[uuid.UUID][]models.VEXRule, storedRecommendations map[uuid.UUID]models.VEXRuleRecommendation, assetsByID map[uuid.UUID]models.Asset) []dtos.VexRuleRecommendation {
	recommendationsByKey := make(map[string]dtos.VexRuleRecommendation, len(matchingSessionRules)+len(storedRecommendations))

	for _, recommendation := range storedRecommendations {
		key, ok := vexRuleRecommendationDedupKey(recommendation)
		if !ok {
			continue
		}
		if _, ok := recommendationsByKey[key]; !ok {
			recommendationsByKey[key] = transformer.VEXRuleRecommendationToDTO(recommendation, 0)
		}
	}

	for _, rules := range matchingSessionRules {
		for _, rule := range rules {
			if _, ok := recommendationsByKey[rule.ID]; !ok {
				assetWithProject := assetsByID[rule.AssetID]
				recommendationsByKey[rule.ID] = transformer.VEXRuleToOriginRecommendationDTO(rule, 0, assetWithProject.Project.Slug, assetWithProject.Slug)
			}
		}
	}

	recommendations := make([]dtos.VexRuleRecommendation, 0, len(recommendationsByKey))
	for _, recommendation := range recommendationsByKey {
		recommendations = append(recommendations, recommendation)
	}

	slices.SortFunc(recommendations, func(a, b dtos.VexRuleRecommendation) int {
		return strings.Compare(a.Title, b.Title)
	})

	return recommendations
}

func vexRuleRecommendationDedupKey(recommendation models.VEXRuleRecommendation) (string, bool) {
	if recommendation.VEXRuleID != nil {
		return *recommendation.VEXRuleID, true
	}
	if recommendation.UpstreamVEXRuleID != nil {
		return *recommendation.UpstreamVEXRuleID, true
	}
	return "", false
}
