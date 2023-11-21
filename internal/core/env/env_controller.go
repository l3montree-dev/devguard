package env

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/l3montree-dev/flawfix/internal/core/flaw"
	"github.com/l3montree-dev/flawfix/internal/core/flawevent"
	"github.com/labstack/echo/v4"
)

type applicationService interface {
	GetApplicationIDBySlug(projectID uuid.UUID, slug string) (uuid.UUID, error)
}

type Controller struct {
	envService          Service
	envRepository       Repository
	flawRepository      flaw.Repository
	flawEventRepository flawevent.Repository
	applicationService  applicationService
}

func NewHttpController(
	envService Service,
	envRepo Repository,
	flawRepository flaw.Repository,
	flawEventRepository flawevent.Repository,
	applicationService applicationService,
) *Controller {
	return &Controller{
		envService:          envService,
		envRepository:       envRepo,
		flawRepository:      flawRepository,
		flawEventRepository: flawEventRepository,
		applicationService:  applicationService,
	}
}

func (e *Controller) Read(c core.Context) error {
	envSlug, err := core.GetEnvSlug(c)
	if err != nil {
		return echo.NewHTTPError(400, "invalid env slug")
	}

	applicationSlug, err := core.GetApplicationSlug(c)
	if err != nil {
		return echo.NewHTTPError(400, "invalid application slug")
	}

	project := core.GetProject(c)

	// fetch the application
	applicationID, err := e.applicationService.GetApplicationIDBySlug(project.GetID(), applicationSlug)

	if err != nil {
		return echo.NewHTTPError(404, "could not find application")
	}

	// fetch the env by slug
	env, err := e.envRepository.ReadBySlug(applicationID, envSlug)
	if err != nil {
		return echo.NewHTTPError(404, "could not find env")
	}

	// we found the env.
	return c.JSON(200, env)
}
