package events

import (
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/labstack/echo/v4"
)

type vulnEventRepository interface {
	ReadAssetEventsByVulnID(vulnID string) ([]models.VulnEventDetail, error)
}

type vulnEventController struct {
	vulnEventRepository vulnEventRepository
}

func NewVulnEventController(vulnEventRepository vulnEventRepository) *vulnEventController {
	return &vulnEventController{
		vulnEventRepository: vulnEventRepository,
	}
}

func (c vulnEventController) ReadAssetEventsByVulnID(ctx core.Context) error {

	vulnId, err := core.GetVulnID(ctx)
	if err != nil {
		return echo.NewHTTPError(400, "vulnId is required").WithInternal(err)
	}

	events, err := c.vulnEventRepository.ReadAssetEventsByVulnID(vulnId)
	if err != nil {
		return echo.NewHTTPError(500, "could not get events").WithInternal(err)
	}

	return ctx.JSON(200, convertToDetailedDTO(events))
}

func convertToDetailedDTO(event []models.VulnEventDetail) []VulnEventDTO {
	var dtos []VulnEventDTO
	for _, e := range event {
		dtos = append(dtos, VulnEventDTO{
			ID:                e.ID,
			Type:              e.Type,
			VulnID:            e.VulnID,
			UserID:            e.UserID,
			Justification:     e.Justification,
			ArbitraryJsonData: e.GetArbitraryJsonData(),
			CreatedAt:         e.CreatedAt,
			AssetVersionName:  e.AssetVersionName,
			AssetVersionSlug:  e.Slug,
		})

	}
	return dtos
}
