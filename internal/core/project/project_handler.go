package project

import (
	"github.com/l3montree-dev/flawfix/internal/accesscontrol"
	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/l3montree-dev/flawfix/internal/core/application"
)

func RegisterHttpHandler(
	database core.DB,
	server core.Server,
	appRepository application.Repository,
) core.Server {
	database.AutoMigrate(&Model{})

	repository := NewGormRepository(database)

	controller := NewHttpController(repository, appRepository)

	server.GET("/projects", controller.List, core.AccessControlMiddleware("organization", accesscontrol.ActionRead))

	server.POST("/projects", controller.Create, core.AccessControlMiddleware("organization", accesscontrol.ActionUpdate))

	projectRouter := server.Group("/projects/:projectSlug", ProjectAccessControl(repository, "project", accesscontrol.ActionRead))

	projectRouter.GET("/", controller.Read)

	// returning the subrouter for registering project routes
	return projectRouter
}
