package events

import (
	"log/slog"

	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/labstack/echo/v4"
)

type vulnEventController struct {
	vulnEventRepository    core.VulnEventRepository
	assetVersionRepository core.AssetVersionRepository
}

func NewVulnEventController(vulnEventRepository core.VulnEventRepository, assetVersionRepository core.AssetVersionRepository) *vulnEventController {
	return &vulnEventController{
		vulnEventRepository:    vulnEventRepository,
		assetVersionRepository: assetVersionRepository,
	}
}

func (c vulnEventController) ReadAssetEventsByVulnID(ctx core.Context) error {
	vulnID, vulnType, err := core.GetVulnID(ctx)
	if err != nil {
		return echo.NewHTTPError(400, "vulnID is required").WithInternal(err)
	}

	events, err := c.vulnEventRepository.ReadAssetEventsByVulnID(vulnID, vulnType)
	if err != nil {
		return echo.NewHTTPError(500, "could not get events").WithInternal(err)
	}

	return ctx.JSON(200, convertToDetailedDTO(events))
}

func convertSingleToDetailedDTO(event models.VulnEventDetail) VulnEventDTO {
	originalAssetVersionName := event.AssetVersionName
	if event.OriginalAssetVersionName != nil {
		originalAssetVersionName = *event.OriginalAssetVersionName
	}

	return VulnEventDTO{
		ID:                event.ID,
		Type:              event.Type,
		VulnID:            event.VulnID,
		VulnType:          event.VulnType,
		UserID:            event.UserID,
		Justification:     event.Justification,
		ArbitraryJSONData: event.GetArbitraryJSONData(),
		CreatedAt:         event.CreatedAt,
		AssetVersionName:  originalAssetVersionName,
		AssetVersionSlug:  event.Slug,
		VulnerabilityName: event.CVEID,
		PackageName:       event.ComponentPurl,
		URI:               event.URI,
		Upstream:          event.Upstream,
	}
}

func convertToDetailedDTO(event []models.VulnEventDetail) []VulnEventDTO {
	var dtos []VulnEventDTO
	for _, e := range event {
		originalAssetVersionName := e.AssetVersionName
		if e.OriginalAssetVersionName != nil {
			originalAssetVersionName = *e.OriginalAssetVersionName
		}
		dtos = append(dtos, VulnEventDTO{
			ID:                      e.ID,
			Type:                    e.Type,
			VulnID:                  e.VulnID,
			VulnType:                e.VulnType,
			UserID:                  e.UserID,
			Justification:           e.Justification,
			MechanicalJustification: e.MechanicalJustification,
			ArbitraryJSONData:       e.GetArbitraryJSONData(),
			CreatedAt:               e.CreatedAt,
			AssetVersionName:        originalAssetVersionName,
			AssetVersionSlug:        e.Slug,
			PackageName:             e.ComponentPurl,
			URI:                     e.URI,
			Upstream:                e.Upstream,
		})

	}
	return dtos
}

func (c vulnEventController) ReadEventsByAssetIDAndAssetVersionName(ctx core.Context) error {

	asset := core.GetAsset(ctx)
	assetVersion, err := core.MaybeGetAssetVersion(ctx)
	if err != nil {
		// we need to get the default asset version
		assetVersion, err = c.assetVersionRepository.GetDefaultAssetVersion(asset.ID)
		if err != nil {
			slog.Error("Error getting default asset version", "error", err)
			return ctx.JSON(404, nil)
		}
	}

	events, err := c.vulnEventRepository.ReadEventsByAssetIDAndAssetVersionName(asset.ID, assetVersion.Name, core.GetPageInfo(ctx),
		core.GetFilterQuery(ctx),
	)
	if err != nil {
		return echo.NewHTTPError(500, "could not get events").WithInternal(err)
	}
	return ctx.JSON(200, events.Map(func(ved models.VulnEventDetail) any {
		return convertSingleToDetailedDTO(ved)
	}))
}

func (c vulnEventController) DeleteEventByID(ctx core.Context) error {
	eventID := ctx.Param("eventID")
	if eventID == "" {
		return echo.NewHTTPError(400, "eventID is required")
	}

	asset := core.GetAsset(ctx)
	hasAccess, err := c.vulnEventRepository.HasAccessToEvent(asset.ID, eventID)
	if err != nil {
		return echo.NewHTTPError(500, "could not verify access to event").WithInternal(err)
	}
	if !hasAccess {
		return echo.NewHTTPError(403, "you do not have access to this event")
	}

	err = c.vulnEventRepository.DeleteEventByID(nil, eventID)
	if err != nil {
		return echo.NewHTTPError(500, "could not delete event").WithInternal(err)
	}

	return ctx.NoContent(204)
}
