package controllers

import (
	"log/slog"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/labstack/echo/v4"
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

func (c VulnEventController) ReadAssetEventsByVulnID(ctx shared.Context) error {
	vulnID, vulnType, err := shared.GetVulnID(ctx)
	if err != nil {
		return echo.NewHTTPError(400, "vulnID is required").WithInternal(err)
	}

	events, err := c.vulnEventRepository.ReadAssetEventsByVulnID(vulnID, vulnType)
	if err != nil {
		return echo.NewHTTPError(500, "could not get events").WithInternal(err)
	}

	return ctx.JSON(200, transformer.ConvertVulnEventsToDtos(events))
}

func (c VulnEventController) ReadEventsByAssetIDAndAssetVersionName(ctx shared.Context) error {

	asset := shared.GetAsset(ctx)
	assetVersion, err := shared.MaybeGetAssetVersion(ctx)
	if err != nil {
		// we need to get the default asset version
		assetVersion, err = c.assetVersionRepository.GetDefaultAssetVersion(asset.ID)
		if err != nil {
			slog.Error("Error getting default asset version", "error", err)
			return ctx.JSON(404, nil)
		}
	}

	events, err := c.vulnEventRepository.ReadEventsByAssetIDAndAssetVersionName(asset.ID, assetVersion.Name, shared.GetPageInfo(ctx),
		shared.GetFilterQuery(ctx),
	)
	if err != nil {
		return echo.NewHTTPError(500, "could not get events").WithInternal(err)
	}
	return ctx.JSON(200, events.Map(func(ved models.VulnEventDetail) any {
		return transformer.ConvertVulnEventToDto(ved.VulnEvent)
	}))
}

func (c VulnEventController) DeleteEventByID(ctx shared.Context) error {
	eventID, err := shared.GetEventID(ctx)
	if err != nil {
		return echo.NewHTTPError(400, "eventID is required").WithInternal(err)
	}

	err = c.vulnEventRepository.DeleteEventByID(nil, eventID)
	if err != nil {
		return echo.NewHTTPError(500, "could not delete event").WithInternal(err)
	}

	return ctx.NoContent(204)
}
