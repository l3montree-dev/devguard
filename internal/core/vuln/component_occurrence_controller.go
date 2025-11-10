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
	role, _ := core.GetRBAC(ctx).GetDomainRole(core.GetSession(ctx).GetUserID())

	pagedResp, err := controller.repository.SearchComponentOccurrencesByOrg(
		nil,
		org.GetID(),
		core.GetPageInfo(ctx),
		ctx.QueryParam("search"),
	)
	if err != nil {
		return echo.NewHTTPError(500, "could not search component occurrences").WithInternal(err)
	}

	if role != core.RoleOwner && role != core.RoleAdmin {
		return echo.NewHTTPError(403, "owners or admins only")
	}

	return ctx.JSON(200, pagedResp.Map(func(occurrence models.ComponentOccurrence) any {
		return convertComponentOccurrenceToDTO(occurrence)
	}))
}
