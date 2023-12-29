package env

import (
	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/l3montree-dev/flawfix/internal/core/flaw"
	"github.com/l3montree-dev/flawfix/internal/core/flawevent"
	"github.com/labstack/echo/v4"
)

func envMiddleware(repository Repository) func(next echo.HandlerFunc) echo.HandlerFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		// get the project
		return func(c echo.Context) error {
			app := core.GetApplication(c)

			envSlug, err := core.GetEnvSlug(c)
			if err != nil {
				return echo.NewHTTPError(400, "invalid application slug")
			}

			env, err := repository.ReadBySlug(app.GetID(), envSlug)

			if err != nil {
				return echo.NewHTTPError(404, "could not find env").WithInternal(err)
			}

			c.Set("env", env)

			return next(c)
		}
	}
}

func RegisterHttpHandler(database core.DB, server core.Server, applicationService applicationService) core.Server {
	database.AutoMigrate(&Model{}, &flaw.Model{}, &flawevent.Model{})

	repository := NewGormRepository(database)

	service := NewDomainService(repository)
	controller := NewHttpController(service, repository, flaw.NewGormRepository(database), flawevent.NewGormRepository(database), applicationService)

	envRouter := server.Group("/envs/:envSlug", envMiddleware(repository))
	envRouter.GET("/", controller.Read)

	return envRouter
}
