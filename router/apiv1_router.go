package router

import (
	"github.com/l3montree-dev/devguard/controllers"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/labstack/echo/v4"
	"github.com/ory/client-go"
	"github.com/prometheus/client_golang/prometheus/promhttp"
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

func health(ctx echo.Context) error {
	return ctx.String(200, "ok")
}

func NewAPIV1Router(srv *echo.Echo,
	thirdPartyIntegration shared.IntegrationAggregate,
	oryAdmin *client.APIClient,
	assetController controllers.AssetController,

) APIV1Router {
	apiV1Router := srv.Group("/api/v1")
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
			shared.SetAuthAdminClient(ctx, shared.NewAdminClient(oryAdmin))
			return next(ctx)
		}
	})

	apiV1Router.GET("/metrics/", echo.WrapHandler(promhttp.Handler()))
	apiV1Router.GET("/health/", health)
	apiV1Router.GET("/badges/:badge/:badgeSecret/", assetController.GetBadges)
	apiV1Router.GET("/lookup/", assetController.HandleLookup)
	apiV1Router.GET("/verify-supply-chain/", intotoController.VerifySupplyChain)
	apiV1Router.POST("/webhook/", thirdPartyIntegration.HandleWebhook)

	// csaf routes
	apiV1Router.GET("/.well-known/csaf-aggregator/aggregator.json/", csafController.GetAggregatorJSON)
	apiV1Router.GET("/organizations/:organization/csaf/provider-metadata.json/", csafController.GetProviderMetadataForOrganization, CsafMiddleware(true, orgRepository, projectRepository, assetRepository, assetVersionRepository, artifactRepository))
	apiV1Router.GET("/organizations/:organization/csaf/openpgp/", csafController.GetOpenPGPHTML, CsafMiddleware(true, orgRepository, projectRepository, assetRepository, assetVersionRepository, artifactRepository))
	apiV1Router.GET("/organizations/:organization/csaf/openpgp/:file/", csafController.GetOpenPGPFile, CsafMiddleware(true, orgRepository, projectRepository, assetRepository, assetVersionRepository, artifactRepository))

	apiV1Router.GET("/organizations/:organization/projects/:projectSlug/assets/:assetSlug/csaf/", csafController.GetCSAFIndexHTML, CsafMiddleware(false, orgRepository, projectRepository, assetRepository, assetVersionRepository, artifactRepository))
	apiV1Router.GET("/organizations/:organization/projects/:projectSlug/assets/:assetSlug/csaf/white/index.txt/", csafController.GetIndexFile, CsafMiddleware(false, orgRepository, projectRepository, assetRepository, assetVersionRepository, artifactRepository))
	apiV1Router.GET("/organizations/:organization/projects/:projectSlug/assets/:assetSlug/csaf/white/changes.csv/", csafController.GetChangesCSVFile, CsafMiddleware(false, orgRepository, projectRepository, assetRepository, assetVersionRepository, artifactRepository))
	apiV1Router.GET("/organizations/:organization/projects/:projectSlug/assets/:assetSlug/csaf/white/", csafController.GetTLPWhiteEntriesHTML, CsafMiddleware(false, orgRepository, projectRepository, assetRepository, assetVersionRepository, artifactRepository))
	apiV1Router.GET("/organizations/:organization/projects/:projectSlug/assets/:assetSlug/csaf/white/:year/", csafController.GetReportsByYearHTML, CsafMiddleware(false, orgRepository, projectRepository, assetRepository, assetVersionRepository, artifactRepository))
	apiV1Router.GET("/organizations/:organization/projects/:projectSlug/assets/:assetSlug/csaf/white/:year/:version/", csafController.ServeCSAFReportRequest, CsafMiddleware(false, orgRepository, projectRepository, assetRepository, assetVersionRepository, artifactRepository))
	return APIV1Router{
		Group: apiV1Router,
	}
}
