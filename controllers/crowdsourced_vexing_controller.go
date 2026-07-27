package controllers

import (
	"errors"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/crowdsourcevexing"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/labstack/echo/v4"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
)

type CrowdsourcedVexingController struct {
	crowdsourcedVexingService shared.CrowdSourcedVexingService
	dependencyVulnRepository  shared.DependencyVulnRepository
}

func NewCrowdsourcedVexingController(crowdsourcedVexingService shared.CrowdSourcedVexingService, dependencyVulnRepository shared.DependencyVulnRepository) *CrowdsourcedVexingController {
	return &CrowdsourcedVexingController{
		crowdsourcedVexingService: crowdsourcedVexingService,
		dependencyVulnRepository:  dependencyVulnRepository,
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
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/crowdsourced-vexing/recommendations/{dependencyVulnID} [get]
func (c *CrowdsourcedVexingController) Recommend(ctx shared.Context) error {
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
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return echo.NewHTTPError(400, "could not parse vuln ID to uuid").WithInternal(err)
	}

	rule, err := c.crowdsourcedVexingService.Recommend(ctx, nil, dependencyVulnIDParsed)

	if err != nil {
		if errors.Is(err, crowdsourcevexing.ErrNoRecommendation) {
			return ctx.NoContent(204)
		}
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return echo.NewHTTPError(500, "Could not calculate recommendation.").WithInternal(err)
	}
	return ctx.JSON(200, transformer.VEXRuleToRecommendationDTO(rule))
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
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/crowdsourced-vexing/recommendations [get]
func (c *CrowdsourcedVexingController) RecommendForAsset(ctx shared.Context) error {
	reqCtx, span := controllersTracer.Start(ctx.Request().Context(), "CrowdsourcedVexingController.RecommendForAsset")
	defer span.End()
	ctx.SetRequest(ctx.Request().WithContext(reqCtx))

	asset := shared.GetAsset(ctx)
	span.SetAttributes(attribute.String("asset.id", asset.ID.String()))

	vulns, err := c.dependencyVulnRepository.GetAllOpenVulnsByAssetID(reqCtx, nil, asset.ID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return echo.NewHTTPError(500, "Could not fetch dependency vulns.").WithInternal(err)
	}
	span.SetAttributes(attribute.Int("dependencyVulns.total", len(vulns)))

	rules, err := c.crowdsourcedVexingService.RecommendBatch(ctx, nil, vulns)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return echo.NewHTTPError(500, "Could not calculate recommendation.").WithInternal(err)
	}

	recommendations := make(map[uuid.UUID]dtos.VexRuleRecommendation, len(rules))
	for vulnID, rule := range rules {
		recommendations[vulnID] = transformer.VEXRuleToRecommendationDTO(rule)
	}
	span.SetAttributes(attribute.Int("recommendations.total", len(recommendations)))

	return ctx.JSON(200, recommendations)
}
