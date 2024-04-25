package vulndb

import (
	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/l3montree-dev/flawfix/internal/database"
	"github.com/l3montree-dev/flawfix/internal/database/models"
	"github.com/labstack/echo/v4"
)

type repository interface {
	FindAllListPaged(tx database.DB, pageInfo core.PageInfo, filter []core.FilterQuery, sort []core.SortQuery) (core.Paged[models.CVE], error)
}

type flawHttpController struct {
	flawRepository repository
}

func NewHttpController(cveRepository repository) *flawHttpController {
	return &flawHttpController{
		flawRepository: cveRepository,
	}
}

func (c flawHttpController) ListPaged(ctx core.Context) error {

	pagedResp, err := c.flawRepository.FindAllListPaged(
		nil,
		core.GetPageInfo(ctx),
		core.GetFilterQuery(ctx),
		core.GetSortQuery(ctx),
	)

	if err != nil {
		return echo.NewHTTPError(500, "could not get flaws").WithInternal(err)
	}

	return ctx.JSON(200, pagedResp)
}
