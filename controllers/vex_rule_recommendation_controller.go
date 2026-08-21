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

	if rules := matchingSessionRules[vuln.ID]; len(rules) > 0 {
		rule := rules[0]

		asset, err := c.assetRepository.ReadWithProject(reqCtx, nil, rule.AssetID)
		if err != nil {
			return traceErr(span, 500, "Could not calculate recommendation.", err)
		}
		return ctx.JSON(200, transformer.VEXRuleToOriginRecommendationDTO(rule, asset.Project.Slug, asset.Slug))
	}

	// no session rule was found - lets look for upstream or crowdsourced recommendations
	recommendation, err := c.vexRuleRecommendationRepository.FindByDependencyVulnID(reqCtx, nil, dependencyVulnIDParsed)
	if err != nil {
		if shared.IsNotFound(err) {
			return ctx.NoContent(204)
		}
		return traceErr(span, 500, "Could not calculate recommendation.", err)
	}

	return ctx.JSON(200, transformer.VEXRuleRecommendationToDTO(recommendation))
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

	vulnsByID := make(map[uuid.UUID]models.DependencyVuln, len(vulns))
	for _, vuln := range vulns {
		vulnsByID[vuln.ID] = vuln
	}

	// a session rule has no stored recommendation row and therefore no vuln signature of its
	// own - take the asset signature of the vuln it matched against instead
	matchingSessionRuleIDs := make([]string, 0, len(matchingSessionRules))
	assetSignatureByRuleID := make(map[string]int64, len(matchingSessionRules))
	for vulnID, rules := range matchingSessionRules {
		for _, rule := range rules {
			if _, ok := assetSignatureByRuleID[rule.ID]; ok {
				continue
			}
			assetSignatureByRuleID[rule.ID] = vulnsByID[vulnID].AssetSignature
			matchingSessionRuleIDs = append(matchingSessionRuleIDs, rule.ID)
		}
	}

	pageInfo := shared.GetPageInfo(ctx)
	search := ctx.QueryParam("search")
	filterQuery := shared.GetFilterQuery(ctx)
	sortQuery := shared.GetSortQuery(ctx)

	pagedRecommendations, err := c.vexRuleRecommendationRepository.FindByDependencyVulnIDsAndVexRuleIDsPaged(reqCtx, nil, unmatchedVulnIDs, matchingSessionRuleIDs, pageInfo, search, filterQuery, sortQuery)
	if err != nil {
		return traceErr(span, 500, "Could not calculate recommendation.", err)
	}
	span.SetAttributes(attribute.Int("recommendations.page_size", len(pagedRecommendations.Data)))

	return ctx.JSON(200, pagedRecommendations.Map(func(recommendation models.VEXRuleRecommendation) any {
		if recommendation.VEXRuleID != nil {
			if assetSignature, ok := assetSignatureByRuleID[*recommendation.VEXRuleID]; ok {
				originAsset := assetsByID[recommendation.VEXRule.AssetID]
				dto := transformer.VEXRuleToOriginRecommendationDTO(recommendation.VEXRule, originAsset.Project.Slug, originAsset.Slug)
				dto.AssetSignature = assetSignature
				return dto
			}
		}
		return transformer.VEXRuleRecommendationToDTO(recommendation)
	}))
}
