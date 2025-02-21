package dependencyVuln

import (
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/labstack/echo/v4"
)

// we are using multiple definitions of the vulnEventRepository interface in the same package
// therefore prefixing the interface name with ctr
type ctrVulnEventRepository interface {
	Create(tx core.DB, vulnEvent *models.VulnEvent) error
}

type VulnEventHttpController struct {
	vulnEventRepository ctrVulnEventRepository
}

func NewEventHttpController(vulnEventRepository ctrVulnEventRepository) *VulnEventHttpController {
	return &VulnEventHttpController{
		vulnEventRepository: vulnEventRepository,
	}
}

func (c VulnEventHttpController) Create(ctx core.Context) error {
	dto := VulnEventDTO{}
	err := ctx.Bind(&dto)
	if err != nil {
		return echo.NewHTTPError(400, "invalid payload").WithInternal(err)
	}

	vulnEvent := dto.ToModel()

	err = c.vulnEventRepository.Create(nil, &vulnEvent)
	if err != nil {
		return echo.NewHTTPError(500, "could not create dependencyVuln event").WithInternal(err)
	}

	return ctx.JSON(200, vulnEvent)
}
