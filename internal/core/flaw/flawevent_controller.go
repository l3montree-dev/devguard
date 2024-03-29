package flaw

import (
	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/l3montree-dev/flawfix/internal/database/models"
	"github.com/labstack/echo/v4"
)

type flawEventRepository interface {
	Create(tx core.DB, flawEvent *models.FlawEvent) error
}

type FlawEventHttpController struct {
	flawEventRepository flawEventRepository
}

func NewEventHttpController(flawEventRepository flawEventRepository) *FlawEventHttpController {
	return &FlawEventHttpController{
		flawEventRepository: flawEventRepository,
	}
}

func (c FlawEventHttpController) Create(ctx core.Context) error {
	dto := FlawEventDTO{}
	err := ctx.Bind(&dto)
	if err != nil {
		return echo.NewHTTPError(400, "invalid payload").WithInternal(err)
	}

	flawEvent := dto.ToModel()

	err = c.flawEventRepository.Create(nil, &flawEvent)
	if err != nil {
		return echo.NewHTTPError(500, "could not create flaw event").WithInternal(err)
	}

	return ctx.JSON(200, flawEvent)
}
