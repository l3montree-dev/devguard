package flaw

import (
	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/labstack/echo/v4"
)

type FlawEventHttpController struct {
	flawEventRepository EventRepository
}

func NewEventHttpController(flawEventRepository EventRepository) *FlawEventHttpController {
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
