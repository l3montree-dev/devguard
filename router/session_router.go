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

package router

import (
	"github.com/l3montree-dev/devguard/controllers"
	"github.com/l3montree-dev/devguard/integrations/gitlabint"
	"github.com/l3montree-dev/devguard/middlewares"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/labstack/echo/v4"
)

type SessionRouter struct {
	*echo.Group
}

// @Summary Get current user info
// @Security CookieAuth
// @Security ApiKeyAuth
// @Success 200 {object} object{userID=string}
// @Router /whoami [get]
func whoami(ctx echo.Context) error {
	return ctx.JSON(200, map[string]string{
		"userID": shared.GetSession(ctx).GetUserID(),
	})
}

func NewSessionRouter(
	apiV1Router APIV1Router,
	adminClient shared.PublicClient,
	patService shared.PersonalAccessTokenService,
	externalEntityProviderService shared.ExternalEntityProviderService,
	integrationController *controllers.IntegrationController,
	orgController *controllers.OrgController,
	scanController *controllers.ScanController,
	attestationController *controllers.AttestationController,
	patController *controllers.PatController,
	assetRepository shared.AssetRepository,
	projectRepository shared.ProjectRepository,
	casbinRBACProvider shared.RBACProvider,
	orgService shared.OrgService,
	gitlabOauth2Integrations map[string]*gitlabint.GitlabOauth2Config,
	assetVersionRepository shared.AssetVersionRepository,
) SessionRouter {
	sessionRouter := apiV1Router.Group.Group("",
		middlewares.SessionMiddleware(adminClient, patService),
		middlewares.ExternalEntityProviderOrgSyncMiddleware(externalEntityProviderService),
	)

	sessionRouter.GET("/trigger-sync/", externalEntityProviderService.TriggerOrgSync, middlewares.NeededScope([]string{"manage"}))
	sessionRouter.GET("/oauth2/gitlab/:integrationName/", integrationController.GitLabOauth2Login)
	sessionRouter.GET("/oauth2/gitlab/callback/:integrationName/", integrationController.GitLabOauth2Callback)
	sessionRouter.GET("/whoami/", whoami)
	sessionRouter.GET("/integrations/repositories/", integrationController.ListRepositories)
	sessionRouter.POST("/accept-invitation/", orgController.AcceptInvitation, middlewares.NeededScope([]string{"manage"}))

	/**
	Following routes are asset routes which are registered on sessionRouter because of fast access.
	They do ALL need to have an assetScopedRBAC middleware applied to them.
	*/
	projectScopedRBAC := middlewares.ProjectAccessControlFactory(projectRepository)
	assetScopedRBAC := middlewares.AssetAccessControlFactory(assetRepository)

	fastAccessRoutes := sessionRouter.Group("",
		middlewares.NeededScope([]string{"scan"}),
		middlewares.AssetNameMiddleware(),
		middlewares.MultiOrganizationMiddlewareRBAC(casbinRBACProvider, orgService, gitlabOauth2Integrations),
		projectScopedRBAC(shared.ObjectProject, shared.ActionRead),
		assetScopedRBAC(shared.ObjectAsset, shared.ActionUpdate),
		middlewares.ScanMiddleware(assetVersionRepository),
	)

	fastAccessRoutes.POST("/scan/", scanController.ScanDependencyVulnFromProject)
	fastAccessRoutes.POST("/vex/", scanController.UploadVEX)
	fastAccessRoutes.POST("/sarif-scan/", scanController.FirstPartyVulnScan)
	fastAccessRoutes.POST("/attestations/", attestationController.Create)

	/**
	Personal access token router
	This does not happen in a org or anything.
	We only need to make sure, that the user is logged in (sessionRouter)
	*/
	patRouter := sessionRouter.Group("/pats", middlewares.NeededScope([]string{"manage"}))
	patRouter.GET("/", patController.List)
	patRouter.POST("/", patController.Create)
	patRouter.POST("/revoke-by-private-key/", patController.RevokeByPrivateKey)
	patRouter.DELETE("/:tokenID/", patController.Delete)

	return SessionRouter{
		Group: sessionRouter,
	}
}

// Note: external entity provider middlewares live in the `middlewares` package.
