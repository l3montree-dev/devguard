package vuln

import (
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/labstack/echo/v4"
)

type componentOccurrenceHTTPController struct {
	repository core.ComponentOccurrenceRepository
}

func NewComponentOccurrenceHTTPController(repository core.ComponentOccurrenceRepository) *componentOccurrenceHTTPController {
	return &componentOccurrenceHTTPController{repository: repository}
}

func (controller componentOccurrenceHTTPController) SearchByOrg(ctx core.Context) error {
	org := core.GetOrg(ctx)

	pagedResp, err := controller.repository.SearchComponentOccurrencesByOrg(
		nil,
		org.GetID(),
		core.GetPageInfo(ctx),
		ctx.QueryParam("search"),
	)
	if err != nil {
		return echo.NewHTTPError(500, "could not search component occurrences").WithInternal(err)
	}

	return ctx.JSON(200, pagedResp.Map(func(occurrence models.ComponentOccurrence) any {
		return convertComponentOccurrenceToDTO(occurrence)
	}))
}
