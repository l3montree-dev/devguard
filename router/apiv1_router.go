package router

import (
	"github.com/l3montree-dev/devguard/cmd/devguard/api"
	"github.com/l3montree-dev/devguard/controllers"
	"github.com/l3montree-dev/devguard/middlewares"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/labstack/echo/v4"
)

// Copyright (C) 2025 l3montree GmbH
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

type APIV1Router struct {
	*echo.Group
}

func NewAPIV1Router(srv api.Server,
	thirdPartyIntegration shared.IntegrationAggregate,
	oryAdmin shared.AdminClient,
	systemController *controllers.SystemController,
	adminController *controllers.AdminController,
	integrationController *controllers.IntegrationController,
	assetController *controllers.AssetController,
	intotoController *controllers.InToToController,
	csafController *controllers.CSAFController,
	scanController *controllers.ScanController,
	dependencyVulnController *controllers.DependencyVulnController,
	orgRepository shared.OrganizationRepository,
	projectRepository shared.ProjectRepository,
	assetRepository shared.AssetRepository,
	assetVersionRepository shared.AssetVersionRepository,
	artifactRepository shared.ArtifactRepository,
) APIV1Router {
	apiV1Router := srv.Echo.Group("/api/v1")

	// this makes the third party integrations available to all controllers
	apiV1Router.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx shared.Context) error {
			shared.SetThirdPartyIntegration(ctx, thirdPartyIntegration)
			return next(ctx)
		}
	})

	apiV1Router.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx shared.Context) error {
			// set the ory admin client to the context
			shared.SetAuthAdminClient(ctx, oryAdmin)
			return next(ctx)
		}
	})

	apiV1Router.GET("/info/", systemController.Info)
	apiV1Router.GET("/health/", systemController.Health)
	apiV1Router.GET("/lookup/", assetController.HandleLookup)
	apiV1Router.GET("/verify-supply-chain/", intotoController.VerifySupplyChain)
	apiV1Router.POST("/webhook/", integrationController.HandleWebhook)
	apiV1Router.POST("/scan-unauthenticated/", scanController.ScanDependencyVulnUnauthenticated)
	apiV1Router.POST("/sarif-scan-unauthenticated/", scanController.FirstPartyVulnScanUnauthenticated)
	apiV1Router.GET("/renovate/recommendation/", dependencyVulnController.GetRecommendation)
	apiV1Router.GET("/instance-settings/", adminController.InstanceSettingsPublic)

	// csaf routes
	apiV1Router.GET("/.well-known/csaf-aggregator/aggregator.json/", csafController.GetAggregatorJSON)
	apiV1Router.GET("/organizations/:organization/csaf/provider-metadata.json/", csafController.GetProviderMetadataForOrganization, middlewares.CsafMiddleware(true, orgRepository, projectRepository, assetRepository, assetVersionRepository, artifactRepository))
	apiV1Router.GET("/organizations/:organization/csaf/openpgp/", csafController.GetOpenPGPHTML, middlewares.CsafMiddleware(true, orgRepository, projectRepository, assetRepository, assetVersionRepository, artifactRepository))
	apiV1Router.GET("/organizations/:organization/csaf/openpgp/:file/", csafController.GetOpenPGPFile, middlewares.CsafMiddleware(true, orgRepository, projectRepository, assetRepository, assetVersionRepository, artifactRepository))

	apiV1Router.GET("/organizations/:organization/projects/:projectSlug/assets/:assetSlug/csaf/", csafController.GetCSAFIndexHTML, middlewares.CsafMiddleware(false, orgRepository, projectRepository, assetRepository, assetVersionRepository, artifactRepository))
	apiV1Router.GET("/organizations/:organization/projects/:projectSlug/assets/:assetSlug/csaf/white/index.txt/", csafController.GetIndexFile, middlewares.CsafMiddleware(false, orgRepository, projectRepository, assetRepository, assetVersionRepository, artifactRepository))
	apiV1Router.GET("/organizations/:organization/projects/:projectSlug/assets/:assetSlug/csaf/white/changes.csv/", csafController.GetChangesCSVFile, middlewares.CsafMiddleware(false, orgRepository, projectRepository, assetRepository, assetVersionRepository, artifactRepository))
	apiV1Router.GET("/organizations/:organization/projects/:projectSlug/assets/:assetSlug/csaf/white/", csafController.GetTLPWhiteEntriesHTML, middlewares.CsafMiddleware(false, orgRepository, projectRepository, assetRepository, assetVersionRepository, artifactRepository))
	apiV1Router.GET("/organizations/:organization/projects/:projectSlug/assets/:assetSlug/csaf/white/:year/", csafController.GetReportsByYearHTML, middlewares.CsafMiddleware(false, orgRepository, projectRepository, assetRepository, assetVersionRepository, artifactRepository))
	apiV1Router.GET("/organizations/:organization/projects/:projectSlug/assets/:assetSlug/csaf/white/:year/:version/", csafController.ServeCSAFReportRequest, middlewares.CsafMiddleware(false, orgRepository, projectRepository, assetRepository, assetVersionRepository, artifactRepository))
	return APIV1Router{
		Group: apiV1Router,
	}
}
