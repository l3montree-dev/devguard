package controller

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/flawfix/internal/dto"
	"github.com/l3montree-dev/flawfix/internal/helpers"
	"github.com/l3montree-dev/flawfix/internal/models"
	"github.com/l3montree-dev/flawfix/internal/repositories"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
)

type applicationRepository interface {
	GetByProjectID(uuid.UUID) ([]models.Application, error)
	repositories.Repository[uuid.UUID, models.Application, *gorm.DB]
}

type envRepository interface {
	repositories.Repository[uuid.UUID, models.Env, any]
}

type ApplicationController struct {
	applicationRepository
	envRepository
}

func NewApplicationController(repository applicationRepository, envRepository envRepository) *ApplicationController {
	return &ApplicationController{
		applicationRepository: repository,
		envRepository:         envRepository,
	}
}

func (a *ApplicationController) List(c echo.Context) error {
	project, err := helpers.GetProject(c)
	if err != nil {
		return echo.NewHTTPError(400, "invalid project id")
	}

	apps, err := a.applicationRepository.GetByProjectID(project.ID)
	if err != nil {
		return err
	}

	return c.JSON(200, apps)
}

func (a *ApplicationController) Create(c echo.Context) error {
	var req dto.ApplicationCreateRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(400, "unable to process request").WithInternal(err)
	}

	if err := v.Struct(req); err != nil {
		return echo.NewHTTPError(400, err.Error())
	}

	project, err := helpers.GetProject(c)
	if err != nil {
		return echo.NewHTTPError(400, "invalid project id")
	}

	app := req.ToModel(project.ID)

	a.applicationRepository.Transaction(func(tx *gorm.DB) error {
		err = a.applicationRepository.Create(tx, &app)

		if err != nil {
			return err
		}

		// create a default development and production environment
		devEnv := models.Env{
			Name:          "Development",
			ApplicationID: app.ID,
			Slug:          "development",
		}

		prodEnv := models.Env{
			Name:          "Production",
			ApplicationID: app.ID,
			Slug:          "production",
			IsDefault:     true,
		}

		// create the environments
		err = a.envRepository.Create(tx, &devEnv)
		if err != nil {
			return err
		}

		err = a.envRepository.Create(tx, &prodEnv)
		if err != nil {
			return err
		}

		app.Envs = []models.Env{devEnv, prodEnv}

		return nil
	})

	return c.JSON(200, app)
}
