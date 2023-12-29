package vulnreport

import (
	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/l3montree-dev/flawfix/internal/core/application"
	"github.com/l3montree-dev/flawfix/internal/core/flaw"
	"github.com/l3montree-dev/flawfix/internal/core/flawevent"
)

func RegisterHttpHandler(database core.DB, server core.Server) {

	applicationRepository := application.NewGormRepository(database)
	flawRepository := flaw.NewGormRepository(database)
	flawEventRepository := flawevent.NewGormRepository(database)

	controller := NewHttpController(
		applicationRepository,
		flawRepository,
		flawEventRepository,
	)

	vulnreportRouter := server.Group("/vulnreports")
	vulnreportRouter.POST("/", controller.ImportVulnReport)
}
