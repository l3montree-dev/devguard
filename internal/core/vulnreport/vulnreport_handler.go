package vulnreport

import (
	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/l3montree-dev/flawfix/internal/core/cve"
	"github.com/l3montree-dev/flawfix/internal/core/env"
	"github.com/l3montree-dev/flawfix/internal/core/flaw"
	"github.com/l3montree-dev/flawfix/internal/core/flawevent"
)

func RegisterHttpHandler(database core.DB, server core.Server) {
	database.AutoMigrate(&cve.CVEModel{}, &cve.CWEModel{})

	cveRepository := cve.NewGormRepository(database)

	cveService := cve.NewService(cveRepository)

	flawRepository := flaw.NewGormRepository(database)

	flawEnricher := flaw.NewEnricher(cveService, flawRepository)

	flawEventRepository := flawevent.NewGormRepository(database)
	envRepository := env.NewGormRepository(database)

	controller := NewHttpController(
		flawRepository,
		flawEnricher,
		flawEventRepository,
		envRepository,
	)

	vulnreportRouter := server.Group("/vulnreports")
	vulnreportRouter.POST("/:envID/", controller.ImportVulnReport)
}
