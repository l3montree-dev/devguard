package application

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/l3montree-dev/flawfix/internal/core/env"
	"github.com/labstack/echo/v4"
)

type envService interface {
	CreateDefaultEnvForApp(tx core.DB, applicationID uuid.UUID) ([]env.Model, error)
}
type HttpController struct {
	applicationRepository Repository
	envService            envService
}

func NewHttpController(repository Repository, envService envService) *HttpController {
	return &HttpController{
		applicationRepository: repository,
		envService:            envService,
	}
}

func (a *HttpController) List(c core.Context) error {
	project := core.GetProject(c)

	apps, err := a.applicationRepository.GetByProjectID(project.GetID())
	if err != nil {
		return err
	}

	return c.JSON(200, apps)
}

func (a *HttpController) Create(c core.Context) error {
	var req CreateRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(400, "unable to process request").WithInternal(err)
	}

	if err := core.V.Struct(req); err != nil {
		return echo.NewHTTPError(400, err.Error())
	}

	project := core.GetProject(c)

	app := req.ToModel(project.GetID())

	err := a.applicationRepository.Transaction(func(tx core.DB) error {
		err := a.applicationRepository.Create(tx, &app)

		if err != nil {
			return err
		}

		// setup environment for the application
		environments, err := a.envService.CreateDefaultEnvForApp(tx, app.ID)
		if err != nil {
			return err
		}

		app.Envs = environments
		return nil
	})

	if err != nil {
		return echo.NewHTTPError(500, "could not create application").WithInternal(err)
	}

	return c.JSON(200, app)
}

func (a *HttpController) Read(c core.Context) error {
	// get the project
	project := core.GetProject(c)

	applicationSlug, err := core.GetApplicationSlug(c)
	if err != nil {
		return echo.NewHTTPError(400, "invalid application slug")
	}

	app, err := a.applicationRepository.ReadBySlug(project.GetID(), applicationSlug)

	if err != nil {
		return echo.NewHTTPError(404, "could not find application").WithInternal(err)
	}

	return c.JSON(200, app)
}
