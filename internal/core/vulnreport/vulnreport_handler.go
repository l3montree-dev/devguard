package vulnreport

import (
	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/l3montree-dev/flawfix/internal/core/asset"
	"github.com/l3montree-dev/flawfix/internal/core/cwe"

	"github.com/l3montree-dev/flawfix/internal/core/flaw"
)

func RegisterHttpHandler(database core.DB, server core.Server) {
	database.AutoMigrate(&cwe.CVEModel{}, &cwe.CWEModel{})

	cweRepository := cwe.NewGormCWERepository(database)

	cwe.SyncCWEs(cweRepository) // sync on startup

	cveRepository := cwe.NewGormRepository(database)

	cveService := cwe.NewService(cveRepository)

	flawRepository := flaw.NewGormRepository(database)

	flawEnricher := flaw.NewEnricher(cveService, flawRepository)

	flawEventRepository := flaw.NewEventGormRepository(database)
	assetRepository := asset.NewGormRepository(database)

	controller := NewHttpController(
		flawRepository,
		flawEnricher,
		flawEventRepository,
		assetRepository,
	)

	vulnreportRouter := server.Group("/vulnreports")
	vulnreportRouter.POST("/:assetID/", controller.ImportVulnReport)
}
