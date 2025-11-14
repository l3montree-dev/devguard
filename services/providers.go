package services

import (
	"net/http"

	"github.com/l3montree-dev/devguard/common"
	"github.com/l3montree-dev/devguard/vulndb/scan"
	"go.uber.org/fx"
)

// Module provides all service-layer constructors
var Module = fx.Options(
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
	fx.Provide(scan.NewScanService),
	fx.Provide(NewExternalEntityProviderService),
	fx.Provide(NewReleaseService),
	fx.Provide(NewPatService),
)
