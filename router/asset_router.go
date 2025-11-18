// Copyright (C) 2024 Tim Bastin, l3montree GmbH
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
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package router

import (
	"github.com/l3montree-dev/devguard/controllers"
	"github.com/l3montree-dev/devguard/middlewares"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/labstack/echo/v4"
)

type AssetRouter struct {
	*echo.Group
}

func NewAssetRouter(
	projectGroup ProjectRouter,
	assetController *controllers.AssetController,
	assetVersionController *controllers.AssetVersionController,
	complianceController *controllers.ComplianceController,
	statisticsController *controllers.StatisticsController,
	componentController *controllers.ComponentController,
	intotoController *controllers.InToToController,
	integrationController *controllers.IntegrationController,
	scanController *controllers.ScanController,
	assetRepository shared.AssetRepository,
) AssetRouter {
	/**
	Asset scoped router
	All routes below this line are scoped to a specific asset.
	*/
	assetScopedRBAC := middlewares.AssetAccessControlFactory(assetRepository)

	assetRouter := projectGroup.Group.Group("/assets/:assetSlug", assetScopedRBAC(shared.ObjectAsset, shared.ActionRead))
	assetRouter.GET("/", assetController.Read)
	assetRouter.GET("/compliance/", complianceController.AssetCompliance)
	assetRouter.GET("/compliance/:policy/", complianceController.Details)
	assetRouter.GET("/number-of-exploits/", statisticsController.GetCVESWithKnownExploits)
	assetRouter.GET("/components/licenses/", componentController.LicenseDistribution)
	assetRouter.GET("/config-files/:config-file/", assetController.GetConfigFile)
	assetRouter.GET("/refs/", assetVersionController.GetAssetVersionsByAssetID)
	assetRouter.GET("/in-toto/root.layout.json/", intotoController.RootLayout)
	assetRouter.GET("/members/", assetController.Members)

	assetRouter.DELETE("/", assetController.Delete, middlewares.NeededScope([]string{"manage"}), assetScopedRBAC(shared.ObjectAsset, shared.ActionDelete))
	assetRouter.GET("/secrets/", assetController.GetSecrets, middlewares.NeededScope([]string{"manage"}), assetScopedRBAC(shared.ObjectAsset, shared.ActionUpdate))
	assetRouter.POST("/signing-key/", assetController.AttachSigningKey, middlewares.NeededScope([]string{"scan"}), assetScopedRBAC(shared.ObjectAsset, shared.ActionUpdate))
	assetRouter.POST("/in-toto/", intotoController.Create, middlewares.NeededScope([]string{"scan"}), assetScopedRBAC(shared.ObjectAsset, shared.ActionUpdate))

	assetUpdateAccessControlRequired := assetRouter.Group("", middlewares.NeededScope([]string{"manage"}), assetScopedRBAC(shared.ObjectAsset, shared.ActionUpdate))
	assetUpdateAccessControlRequired.POST("/sbom-file/", scanController.ScanSbomFile)
	assetUpdateAccessControlRequired.POST("/integrations/gitlab/autosetup/", integrationController.AutoSetup)
	assetUpdateAccessControlRequired.POST("/members/", assetController.InviteMembers)
	assetUpdateAccessControlRequired.PUT("/members/:userID/", assetController.ChangeRole)
	assetUpdateAccessControlRequired.PATCH("/", assetController.Update)
	assetUpdateAccessControlRequired.DELETE("/members/:userID/", assetController.RemoveMember)
	assetUpdateAccessControlRequired.POST("/refs/", assetVersionController.Create)

	return AssetRouter{Group: assetRouter}
}
