package application

import (
	"github.com/l3montree-dev/flawfix/internal/accesscontrol"
	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/l3montree-dev/flawfix/internal/core/env"
	"github.com/labstack/echo/v4"
)

func applicationMiddleware(repository Repository) func(next echo.HandlerFunc) echo.HandlerFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		// get the project
		return func(c echo.Context) error {
			project := core.GetProject(c)

			applicationSlug, err := core.GetApplicationSlug(c)
			if err != nil {
				return echo.NewHTTPError(400, "invalid application slug")
			}

			app, err := repository.ReadBySlug(project.GetID(), applicationSlug)

			if err != nil {
				return echo.NewHTTPError(404, "could not find application").WithInternal(err)
			}

			c.Set("application", app)

			return next(c)
		}
	}
}

func RegisterHttpHandler(database core.DB, server core.Server, rbacMiddleware accesscontrol.RBACMiddleware) core.Server {
	database.AutoMigrate(&Model{})

	repository := NewGormRepository(database)

	controller := NewHttpController(repository, env.NewDomainService(env.NewGormRepository(database)))

	server.POST("/applications/", controller.Create, rbacMiddleware(accesscontrol.ObjectApplication, accesscontrol.ActionCreate))

	server.GET("/applications/", controller.Read)

	applicationRouter := server.Group("/applications/:applicationSlug", rbacMiddleware("application", accesscontrol.ActionRead), applicationMiddleware(repository))

	applicationRouter.GET("/", controller.Read)

	return applicationRouter
}
