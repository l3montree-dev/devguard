package flaw

import (
	"github.com/l3montree-dev/flawfix/internal/accesscontrol"
	"github.com/l3montree-dev/flawfix/internal/core"
)

func RegisterHttpHandler(database core.DB, server core.Server, rbacMiddleware accesscontrol.RBACMiddleware) core.Server {
	database.AutoMigrate(&Model{})
	repository := NewGormRepository(database)

	controller := NewHttpController(repository)

	flawRouter := server.Group("/flaws")

	flawRouter.GET("/", controller.ListPaged)
	flawRouter.GET("/:flawId/", controller.Read)
	return flawRouter
}
