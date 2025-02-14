package DependencyVuln

import (
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/labstack/echo/v4"
)

// we are using multiple definitions of the dependencyVulnEventRepository interface in the same package
// therefore prefixing the interface name with ctr
type ctrDependencyVulnEventRepository interface {
	Create(tx core.DB, dependencyVulnEvent *models.DependencyVulnEvent) error
}

type DependencyVulnEventHttpController struct {
	dependencyVulnEventRepository ctrDependencyVulnEventRepository
}

func NewEventHttpController(dependencyVulnEventRepository ctrDependencyVulnEventRepository) *DependencyVulnEventHttpController {
	return &DependencyVulnEventHttpController{
		dependencyVulnEventRepository: dependencyVulnEventRepository,
	}
}

func (c DependencyVulnEventHttpController) Create(ctx core.Context) error {
	dto := DependencyVulnEventDTO{}
	err := ctx.Bind(&dto)
	if err != nil {
		return echo.NewHTTPError(400, "invalid payload").WithInternal(err)
	}

	dependencyVulnEvent := dto.ToModel()

	err = c.dependencyVulnEventRepository.Create(nil, &dependencyVulnEvent)
	if err != nil {
		return echo.NewHTTPError(500, "could not create dependencyVuln event").WithInternal(err)
	}

	return ctx.JSON(200, dependencyVulnEvent)
}
