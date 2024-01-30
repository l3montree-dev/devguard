package org

import (
	accesscontrol "github.com/l3montree-dev/flawfix/internal/accesscontrol"
	"github.com/l3montree-dev/flawfix/internal/core"
)

func RegisterHttpHandler(database core.DB, server core.Server, rbacProvider accesscontrol.RBACProvider) core.Server {
	if err := database.AutoMigrate(&Model{}); err != nil {
		panic(err)
	}

	repository := NewGormRepository(database)
	controller := NewHttpController(repository, rbacProvider)

	orgRouter := server.Group("/organizations")

	orgRouter.POST("/", controller.Create)
	orgRouter.GET("/", controller.List)

	tenantRouter := orgRouter.Group("/:tenant", MultiTenantMiddleware(rbacProvider, repository))

	tenantRouter.DELETE("/", controller.Delete, core.AccessControlMiddleware("organization", accesscontrol.ActionDelete))
	tenantRouter.GET("/", controller.Read, core.AccessControlMiddleware("organization", accesscontrol.ActionRead))

	return tenantRouter
}
