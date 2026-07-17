package router

import (
	"github.com/l3montree-dev/devguard/cmd/devguard/api"
	"github.com/l3montree-dev/devguard/controllers"
	"github.com/l3montree-dev/devguard/integrations/gitlabint"
	"github.com/l3montree-dev/devguard/middlewares"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/labstack/echo/v4"
)

type APIV2Router struct {
	*echo.Group
}

func NewAPIV2Router(
	srv api.Server,
	oryAdmin shared.AdminClient,
	adminClient shared.PublicClient,
	patService shared.PersonalAccessTokenService,
	externalEntityProviderService shared.ExternalEntityProviderService,
	thirdPartyIntegration shared.IntegrationAggregate,
	scanController *controllers.ScanController,
	assetRepository shared.AssetRepository,
	projectRepository shared.ProjectRepository,
	assetVersionRepository shared.AssetVersionRepository,
	casbinRBACProvider shared.RBACProvider,
	orgService shared.OrgService,
	configService shared.ConfigService,
	gitlabOauth2Integrations map[string]*gitlabint.GitlabOauth2Config,
) APIV2Router {
	projectScopedRBAC := middlewares.ProjectAccessControlFactory(projectRepository, patService)
	assetScopedRBAC := middlewares.AssetAccessControlFactory(assetRepository, patService)

	v2 := srv.Echo.Group("/api/v2",
		func(next echo.HandlerFunc) echo.HandlerFunc {
			return func(ctx shared.Context) error {
				// set the ory admin client to the context
				shared.SetAuthAdminClient(ctx, oryAdmin)
				return next(ctx)
			}
		},
		func(next echo.HandlerFunc) echo.HandlerFunc {
			return func(ctx shared.Context) error {
				shared.SetThirdPartyIntegration(ctx, thirdPartyIntegration)
				return next(ctx)
			}
		},
		middlewares.SessionMiddleware(adminClient, configService, patService),
		middlewares.ExternalEntityProviderOrgSyncMiddleware(externalEntityProviderService),
		middlewares.NeededScope([]string{"scan"}),
		middlewares.AssetNameMiddleware(),
		middlewares.MultiOrganizationMiddlewareRBAC(casbinRBACProvider, orgService),
		projectScopedRBAC(shared.ObjectProject, shared.ActionRead),
		assetScopedRBAC(shared.ObjectAsset, shared.ActionRead),
		middlewares.ScanMiddleware(assetVersionRepository),
	)

	v2.POST("/scan/", scanController.ScanSbomFileVex, middlewares.DisallowPublicRequests)
	v2.POST("/sarif-scan/", scanController.ScanSarifFile, middlewares.DisallowPublicRequests)

	srv.Echo.POST("/api/v2/scan-unauthenticated/", scanController.ScanDependencyVulnUnauthenticatedVex)
	srv.Echo.POST("/api/v2/sarif-scan-unauthenticated/", scanController.SarifScanUnauthenticated)

	return APIV2Router{
		Group: v2,
	}
}
