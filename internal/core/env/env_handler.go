package env

import (
	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/l3montree-dev/flawfix/internal/core/flaw"
	"github.com/l3montree-dev/flawfix/internal/core/flawevent"
)

func RegisterHttpHandler(database core.DB, server core.Server, applicationService applicationService) core.Server {
	repository := NewGormRepository(database)

	service := NewDomainService(repository)
	controller := NewHttpController(service, repository, flaw.NewGormRepository(database), flawevent.NewGormRepository(database), applicationService)

	envRouter := server.Group("/envs/:envSlug")
	envRouter.GET("/", controller.Read)

	return envRouter
}
