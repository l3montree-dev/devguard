package services

import (
	"net/http"

	"go.uber.org/fx"

	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/l3montree-dev/devguard/internal/core/asset"
	"github.com/l3montree-dev/devguard/internal/core/assetversion"
	"github.com/l3montree-dev/devguard/internal/core/component"
	"github.com/l3montree-dev/devguard/internal/core/integrations"
	"github.com/l3montree-dev/devguard/internal/core/intoto"
	"github.com/l3montree-dev/devguard/internal/core/org"
	"github.com/l3montree-dev/devguard/internal/core/pat"
	"github.com/l3montree-dev/devguard/internal/core/project"
	"github.com/l3montree-dev/devguard/internal/core/release"
	"github.com/l3montree-dev/devguard/internal/core/statistics"
	"github.com/l3montree-dev/devguard/internal/core/vuln"
	"github.com/l3montree-dev/devguard/internal/core/vulndb"
	"github.com/l3montree-dev/devguard/internal/core/vulndb/scan"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/l3montree-dev/devguard/services"
)

// Module provides all service-layer constructors
var Module = fx.Options(
	fx.Provide(vuln.NewService),
	fx.Provide(vuln.NewFirstPartyVulnService),
	fx.Provide(vuln.NewLicenseRiskService),
	fx.Provide(project.NewService),
	fx.Provide(asset.NewService),
	fx.Provide(vulndb.NewOpenSourceInsightService),
	fx.Provide(utils.NewFireAndForgetSynchronizer),
	fx.Provide(component.NewComponentService),
	fx.Provide(assetversion.NewService),
	fx.Provide(func() http.Client {
		return common.OutgoingConnectionClient
	}),
	fx.Provide(NewCSAFService),
	fx.Provide(services.NewArtifactService),
	fx.Provide(statistics.NewService),
	fx.Provide(intoto.NewInTotoService),
	fx.Provide(org.NewService),
	fx.Provide(scan.NewScanService),
	fx.Provide(integrations.NewExternalEntityProviderService),
	fx.Provide(release.NewService),
	fx.Provide(pat.NewPatService),
)
