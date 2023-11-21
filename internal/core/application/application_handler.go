package application

import (
	"github.com/l3montree-dev/flawfix/internal/accesscontrol"
	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/l3montree-dev/flawfix/internal/core/env"
)

func RegisterHttpHandler(database core.DB, server core.Server, rbacMiddleware accesscontrol.RBACMiddleware) core.Server {
	repository := NewGormRepository(database)

	controller := NewHttpController(repository, env.NewDomainService(env.NewGormRepository(database)))

	server.POST("/applications", controller.Create, rbacMiddleware(accesscontrol.ObjectApplication, accesscontrol.ActionCreate))

	server.GET("/", controller.Read)

	applicationRouter := server.Group("/applications/:applicationSlug")

	applicationRouter.GET("/", controller.Read, rbacMiddleware("application", accesscontrol.ActionRead))

	return applicationRouter
}
