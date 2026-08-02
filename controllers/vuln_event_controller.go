package controllers

import (
	"errors"
	"log/slog"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
)

type VulnEventController struct {
	vulnEventRepository    shared.VulnEventRepository
	assetVersionRepository shared.AssetVersionRepository
}

func NewVulnEventController(vulnEventRepository shared.VulnEventRepository, assetVersionRepository shared.AssetVersionRepository) *VulnEventController {
	return &VulnEventController{
		vulnEventRepository:    vulnEventRepository,
		assetVersionRepository: assetVersionRepository,
	}
}

// @Summary List events for a vulnerability
// @Tags Vulnerability Events
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Param assetVersionSlug path string true "Asset version slug"
// @Param dependencyVulnID path string true "Dependency vulnerability ID"
// @Success 200 {array} dtos.VulnEventDTO
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/refs/{assetVersionSlug}/dependency-vulns/{dependencyVulnID}/events [get]
func (c VulnEventController) ReadAssetEventsByVulnID(ctx shared.Context) error {
	vulnID, vulnType, err := shared.GetVulnID(ctx)
	if err != nil {
		return echo.NewHTTPError(400, "vulnID is required").WithInternal(err)
	}

	events, err := c.vulnEventRepository.ReadAssetEventsByVulnID(ctx.Request().Context(), nil, vulnID, vulnType)
	if err != nil {
		return echo.NewHTTPError(500, "could not get events").WithInternal(err)
	}

	var eventDTOs []dtos.VulnEventDTO = transformer.ConvertVulnEventsToDtos(events)
	return ctx.JSON(200, eventDTOs)
}

// @Summary List events for an asset version
// @Tags Vulnerability Events
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Param assetVersionSlug path string true "Asset version slug"
// @Success 200 {array} dtos.VulnEventDTO
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/refs/{assetVersionSlug}/events [get]
func (c VulnEventController) ReadEventsByAssetIDAndAssetVersionName(ctx shared.Context) error {

	asset := shared.GetAsset(ctx)
	assetVersion, err := shared.MaybeGetAssetVersion(ctx)
	if err != nil {
		// we need to get the default asset version
		assetVersion, err = c.assetVersionRepository.GetDefaultAssetVersion(ctx.Request().Context(), nil, asset.ID)
		if err != nil {
			slog.Error("Error getting default asset version", "error", err)
			return ctx.JSON(404, nil)
		}
	}

	events, err := c.vulnEventRepository.ReadEventsByAssetIDAndAssetVersionName(ctx.Request().Context(), nil, asset.ID, assetVersion.Name, shared.GetPageInfo(ctx),
		shared.GetFilterQuery(ctx),
	)
	if err != nil {
		return echo.NewHTTPError(500, "could not get events").WithInternal(err)
	}
	return ctx.JSON(200, events.Map(func(ved models.VulnEventDetail) any {
		var dto dtos.VulnEventDTO = transformer.ConvertVulnEventDetailToDto(ved)
		return dto
	}))
}

// @Summary Delete an event
// @Tags Vulnerability Events
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Param assetVersionSlug path string true "Asset version slug"
// @Param eventID path string true "Event ID"
// @Success 204
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/refs/{assetVersionSlug}/events/{eventID} [delete]
func (c VulnEventController) DeleteEventByID(ctx shared.Context) error {
	eventID, err := shared.GetEventID(ctx)
	if err != nil {
		return echo.NewHTTPError(400, "eventID is required").WithInternal(err)
	}

	err = c.vulnEventRepository.DeleteEventByID(ctx.Request().Context(), nil, eventID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return echo.NewHTTPError(404, "event not found")
		}
		return echo.NewHTTPError(500, "could not delete event").WithInternal(err)
	}

	return ctx.NoContent(204)
}
