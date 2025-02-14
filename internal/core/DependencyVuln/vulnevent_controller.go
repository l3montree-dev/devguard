package DependencyVuln

import (
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/labstack/echo/v4"
)

// we are using multiple definitions of the flawEventRepository interface in the same package
// therefore prefixing the interface name with ctr
type ctrFlawEventRepository interface {
	Create(tx core.DB, flawEvent *models.FlawEvent) error
}

type FlawEventHttpController struct {
	flawEventRepository ctrFlawEventRepository
}

func NewEventHttpController(flawEventRepository ctrFlawEventRepository) *FlawEventHttpController {
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
