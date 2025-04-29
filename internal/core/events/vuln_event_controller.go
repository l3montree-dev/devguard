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
	vulnId, vulnType, err := core.GetVulnID(ctx)
	if err != nil {
		return echo.NewHTTPError(400, "vulnId is required").WithInternal(err)
	}

	events, err := c.vulnEventRepository.ReadAssetEventsByVulnID(vulnId, vulnType)
	if err != nil {
		return echo.NewHTTPError(500, "could not get events").WithInternal(err)
	}

	return ctx.JSON(200, convertToDetailedDTO(events))
}

func convertSingleToDetailedDTO(event models.VulnEventDetail) VulnEventDTO {
	return VulnEventDTO{
		ID:                event.ID,
		Type:              event.Type,
		VulnID:            event.VulnID,
		UserID:            event.UserID,
		Justification:     event.Justification,
		ArbitraryJsonData: event.GetArbitraryJsonData(),
		CreatedAt:         event.CreatedAt,
		AssetVersionName:  event.AssetVersionName,
		AssetVersionSlug:  event.Slug,
		VulnerabilityName: event.CVEID,
	}
}

func convertToDetailedDTO(event []models.VulnEventDetail) []VulnEventDTO {
	var dtos []VulnEventDTO
	for _, e := range event {
		dtos = append(dtos, VulnEventDTO{
			ID:                      e.ID,
			Type:                    e.Type,
			VulnID:                  e.VulnID,
			UserID:                  e.UserID,
			Justification:           e.Justification,
			MechanicalJustification: e.MechanicalJustification,
			ArbitraryJsonData:       e.GetArbitraryJsonData(),
			CreatedAt:               e.CreatedAt,
			AssetVersionName:        e.AssetVersionName,
			AssetVersionSlug:        e.Slug,
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
