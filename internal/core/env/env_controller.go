package env

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/l3montree-dev/flawfix/internal/core/flaw"
	"github.com/labstack/echo/v4"
)

type assetService interface {
	GetAssetIDBySlug(projectID uuid.UUID, slug string) (uuid.UUID, error)
}

type Controller struct {
	envService          Service
	envRepository       Repository
	flawRepository      flaw.Repository
	flawEventRepository flaw.Repository
	assetService        assetService
}

func NewHttpController(
	envService Service,
	envRepo Repository,
	flawRepository flaw.Repository,
	flawEventRepository flaw.Repository,
	assetService assetService,
) *Controller {
	return &Controller{
		envService:          envService,
		envRepository:       envRepo,
		flawRepository:      flawRepository,
		flawEventRepository: flawEventRepository,
		assetService:        assetService,
	}
}

func (e *Controller) Read(c core.Context) error {
	envSlug, err := core.GetEnvSlug(c)
	if err != nil {
		return echo.NewHTTPError(400, "invalid env slug")
	}

	assetSlug, err := core.GetAssetSlug(c)
	if err != nil {
		return echo.NewHTTPError(400, "invalid asset slug")
	}

	project := core.GetProject(c)

	// fetch the asset
	assetID, err := e.assetService.GetAssetIDBySlug(project.GetID(), assetSlug)

	if err != nil {
		return echo.NewHTTPError(404, "could not find asset")
	}

	// fetch the env by slug
	env, err := e.envRepository.ReadBySlug(assetID, envSlug)
	if err != nil {
		return echo.NewHTTPError(404, "could not find env")
	}

	// we found the env.
	return c.JSON(200, env)
}
