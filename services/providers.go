package services

import (
	"net/http"

	"github.com/l3montree-dev/devguard/common"
	"go.uber.org/fx"
)

// ServiceModule provides all service-layer constructors
var ServiceModule = fx.Options(
	fx.Provide(NewFirstPartyVulnService),
	fx.Provide(NewLicenseRiskService),
	fx.Provide(NewProjectService),
	fx.Provide(NewAssetService),
	fx.Provide(NewComponentService),
	fx.Provide(NewAssetVersionService),
	fx.Provide(func() http.Client {
		return common.OutgoingConnectionClient
	}),
	fx.Provide(NewCSAFService),
	fx.Provide(NewArtifactService),
	fx.Provide(NewStatisticsService),
	fx.Provide(NewInTotoService),
	fx.Provide(NewOrgService),
	fx.Provide(NewScanService),
	fx.Provide(NewExternalEntityProviderService),
	fx.Provide(NewReleaseService),
	fx.Provide(NewPatService),
)
