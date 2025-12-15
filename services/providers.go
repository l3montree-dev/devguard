package services

import (
	"net/http"

	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"go.uber.org/fx"
)

// ServiceModule provides all service-layer constructors as their interfaces
var ServiceModule = fx.Options(
	fx.Provide(fx.Annotate(utils.NewFireAndForgetSynchronizer, fx.As(new(utils.FireAndForgetSynchronizer)))),
	fx.Provide(fx.Annotate(NewDatabaseLeaderElector, fx.As(new(shared.LeaderElector)))),
	fx.Provide(fx.Annotate(NewConfigService, fx.As(new(shared.ConfigService)))),
	fx.Provide(fx.Annotate(NewFirstPartyVulnService, fx.As(new(shared.FirstPartyVulnService)))),
	fx.Provide(fx.Annotate(NewLicenseRiskService, fx.As(new(shared.LicenseRiskService)))),
	fx.Provide(fx.Annotate(NewProjectService, fx.As(new(shared.ProjectService)))),
	fx.Provide(fx.Annotate(NewAssetService, fx.As(new(shared.AssetService)))),
	fx.Provide(fx.Annotate(NewComponentService, fx.As(new(shared.ComponentService)))),
	fx.Provide(fx.Annotate(NewAssetVersionService, fx.As(new(shared.AssetVersionService)))),
	fx.Provide(func() http.Client { return utils.EgressClient }),
	fx.Provide(fx.Annotate(NewCSAFService, fx.As(new(shared.CSAFService)))),
	fx.Provide(fx.Annotate(NewArtifactService, fx.As(new(shared.ArtifactService)))),
	fx.Provide(fx.Annotate(NewStatisticsService, fx.As(new(shared.StatisticsService)))),
	fx.Provide(fx.Annotate(NewInTotoService, fx.As(new(shared.InTotoVerifierService)))),
	fx.Provide(fx.Annotate(NewOrgService, fx.As(new(shared.OrgService)))),
	fx.Provide(fx.Annotate(NewScanService, fx.As(new(shared.ScanService)))),
	fx.Provide(fx.Annotate(NewExternalEntityProviderService, fx.As(new(shared.ExternalEntityProviderService)))),
	fx.Provide(fx.Annotate(NewReleaseService, fx.As(new(shared.ReleaseService)))),
	fx.Provide(fx.Annotate(NewPatService, fx.As(new(shared.PersonalAccessTokenService)))),
	fx.Provide(fx.Annotate(NewDependencyVulnService, fx.As(new(shared.DependencyVulnService)))),
	fx.Provide(fx.Annotate(NewOpenSourceInsightService, fx.As(new(shared.OpenSourceInsightService)))),
)
