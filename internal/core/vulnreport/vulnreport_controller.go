package vulnreport

import (
	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/l3montree-dev/flawfix/internal/core/application"
	"github.com/l3montree-dev/flawfix/internal/core/flaw"
	"github.com/l3montree-dev/flawfix/internal/core/flawevent"
)

type VulnReportHttpController struct {
	applicationRepository application.Repository
	flawRepository        flaw.Repository
	flawEventRepository   flawevent.Repository
}

func NewHttpController(
	applicationRepository application.Repository,
	flawRepository flaw.Repository,
	flawEventRepository flawevent.Repository,
) VulnReportHttpController {
	return VulnReportHttpController{
		applicationRepository: applicationRepository,
		flawRepository:        flawRepository,
		flawEventRepository:   flawEventRepository,
	}
}

func (c VulnReportHttpController) ImportVulnReport(ctx core.Context) error {
	return nil
}
