package vulndb

import (
	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/l3montree-dev/flawfix/internal/database"
	"github.com/l3montree-dev/flawfix/internal/database/models"
	"github.com/labstack/echo/v4"
)

type repository interface {
	FindAllListPaged(tx database.DB, pageInfo core.PageInfo, filter []core.FilterQuery, sort []core.SortQuery) (core.Paged[models.CVE], error)
	FindCVE(tx database.DB, cveId string) (any, error)
}

type cveHttpController struct {
	cveRepository repository
}

func NewHttpController(cveRepository repository) *cveHttpController {
	return &cveHttpController{
		cveRepository: cveRepository,
	}
}

func (c cveHttpController) ListPaged(ctx core.Context) error {

	pagedResp, err := c.cveRepository.FindAllListPaged(
		nil,
		core.GetPageInfo(ctx),
		core.GetFilterQuery(ctx),
		core.GetSortQuery(ctx),
	)

	if err != nil {
		return echo.NewHTTPError(500, "could not get CVEs").WithInternal(err)
	}

	return ctx.JSON(200, pagedResp)
}

func (c cveHttpController) Read(ctx core.Context) error {
	pagedResp, err := c.cveRepository.FindCVE(
		nil,
		core.GetParam(ctx, "cveId"),
	)

	if err != nil {
		return echo.NewHTTPError(500, "could not get CVEs").WithInternal(err)
	}

	return ctx.JSON(200, pagedResp)
}
