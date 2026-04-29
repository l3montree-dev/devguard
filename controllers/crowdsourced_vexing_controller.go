package controllers

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/labstack/echo/v4"
)

type CrowdsourcedVexingController struct {
	crowdsourcedVexingService shared.CrowdSourcedVexingService
}

func NewCrowdsourcedVexingController(crowdsourcedVexingService shared.CrowdSourcedVexingService) *CrowdsourcedVexingController {
	return &CrowdsourcedVexingController{
		crowdsourcedVexingService: crowdsourcedVexingService,
	}
}

func (c *CrowdsourcedVexingController) Recommend(ctx shared.Context) error {
	vulnId := ctx.QueryParam("dependencyVulnId")
	if vulnId == "" {

		return echo.NewHTTPError(400, "vulnId path parameter is required")
	}

	vulnIDParsed, err := uuid.Parse(vulnId)
	if err != nil {
		return echo.NewHTTPError(400, "could not parse vuln ID to uuid").WithInternal(err)
	}

	rule, err := c.crowdsourcedVexingService.Recommend(ctx, nil, vulnIDParsed)
	if err != nil {
		return echo.NewHTTPError(500, "No recommendation").WithInternal(err)
	}
	return ctx.JSON(200, transformer.VEXRuleToDTO(rule))
}
