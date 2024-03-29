package flaw

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/l3montree-dev/flawfix/internal/database/models"
	"github.com/l3montree-dev/flawfix/internal/database/repositories"
	"github.com/labstack/echo/v4"
)

type repository interface {
	repositories.Repository[uuid.UUID, models.Flaw, core.DB]

	GetByAssetId(tx core.DB, assetId uuid.UUID) ([]models.Flaw, error)
	GetByAssetIdPaged(tx core.DB, pageInfo core.PageInfo, filter []core.FilterQuery, sort []core.SortQuery, assetId uuid.UUID) (core.Paged[models.Flaw], error)
}

type flawHttpController struct {
	flawRepository repository
}

func NewHttpController(flawRepository repository) *flawHttpController {
	return &flawHttpController{
		flawRepository: flawRepository,
	}
}

func (c flawHttpController) ListPaged(ctx core.Context) error {
	// get the asset
	asset := core.GetAsset(ctx)

	pagedResp, err := c.flawRepository.GetByAssetIdPaged(
		nil,
		core.GetPageInfo(ctx),
		core.GetFilterQuery(ctx),
		core.GetSortQuery(ctx),
		asset.GetID(),
	)

	if err != nil {
		return echo.NewHTTPError(500, "could not get flaws").WithInternal(err)
	}

	return ctx.JSON(200, pagedResp)
}

func (c flawHttpController) Read(ctx core.Context) error {
	flawId, err := core.GetFlawID(ctx)
	if err != nil {
		return echo.NewHTTPError(400, "invalid flaw id")
	}

	flaw, err := c.flawRepository.Read(flawId)
	if err != nil {
		return echo.NewHTTPError(404, "could not find flaw")
	}

	// get all the associated cwes

	return ctx.JSON(200, flaw)
}
