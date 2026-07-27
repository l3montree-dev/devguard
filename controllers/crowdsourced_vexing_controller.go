package controllers

import (
	"errors"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/crowdsourcevexing"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/labstack/echo/v4"
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

func (c *CrowdsourcedVexingController) Recommend(ctx shared.Context) error {
	dependencyVulnID := ctx.Param("dependencyVulnID")
	if dependencyVulnID == "" {
		return echo.NewHTTPError(400, "dependencyVulnId query parameter is required")
	}

	dependencyVulnIDParsed, err := uuid.Parse(dependencyVulnID)
	if err != nil {
		return echo.NewHTTPError(400, "could not parse vuln ID to uuid").WithInternal(err)
	}

	rule, err := c.crowdsourcedVexingService.Recommend(ctx, nil, dependencyVulnIDParsed)

	if err != nil {
		if errors.Is(err, crowdsourcevexing.ErrNoRecommendation) {
			return ctx.NoContent(204)
		}
		return echo.NewHTTPError(500, "Could not calculate recommendation.").WithInternal(err)
	}
	return ctx.JSON(200, transformer.VEXRuleToRecommendationDTO(rule))
}

func (c *CrowdsourcedVexingController) RecommendForAssetVersion(ctx shared.Context) error {
	assetVersion := shared.GetAssetVersion(ctx)

	vulns, err := c.dependencyVulnRepository.GetAllOpenVulnsByAssetVersionNameAndAssetID(ctx.Request().Context(), nil, nil, assetVersion.Name, assetVersion.AssetID)
	if err != nil {
		return echo.NewHTTPError(500, "Could not fetch dependency vulns.").WithInternal(err)
	}

	recommendations := make(map[uuid.UUID]dtos.VexRuleRecommendation)
	for _, vuln := range vulns {
		rule, err := c.crowdsourcedVexingService.Recommend(ctx, nil, vuln.ID)
		if err != nil {
			if errors.Is(err, crowdsourcevexing.ErrNoRecommendation) {
				continue
			}
			return echo.NewHTTPError(500, "Could not calculate recommendation.").WithInternal(err)
		}
		recommendations[vuln.ID] = transformer.VEXRuleToRecommendationDTO(rule)
	}

	return ctx.JSON(200, recommendations)
}
