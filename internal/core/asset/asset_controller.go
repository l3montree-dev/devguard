package asset

import (
	"github.com/l3montree-dev/flawfix/internal/core"

	"github.com/labstack/echo/v4"
)

type httpController struct {
	assetRepository repository
}

func NewHttpController(repository repository) *httpController {
	return &httpController{
		assetRepository: repository,
	}
}

func (a *httpController) List(c core.Context) error {
	project := core.GetProject(c)

	apps, err := a.assetRepository.GetByProjectID(project.GetID())
	if err != nil {
		return err
	}

	return c.JSON(200, apps)
}

func (a *httpController) Create(c core.Context) error {
	var req createRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(400, "unable to process request").WithInternal(err)
	}

	if err := core.V.Struct(req); err != nil {
		return echo.NewHTTPError(400, err.Error())
	}

	project := core.GetProject(c)

	app := req.toModel(project.GetID())

	err := a.assetRepository.Create(nil, &app)

	if err != nil {
		return echo.NewHTTPError(500, "could not create asset").WithInternal(err)
	}

	return c.JSON(200, app)
}

func (a *httpController) Read(c core.Context) error {
	app := core.GetAsset(c).(Model)
	return c.JSON(200, app)
}
