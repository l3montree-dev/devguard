// Copyright (C) 2026 l3montree GmbH
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
	"github.com/l3montree-dev/devguard/middlewares"
	"github.com/labstack/echo/v4"
)

type CompliancePostureRouter struct {
	*echo.Group
}

func NewCompliancePostureRouter(
	assetVersionGroup AssetVersionRouter,
	compliancePostureController *controllers.CompliancePostureController,
	complianceComponentController *controllers.ComplianceComponentController,
) CompliancePostureRouter {
	compliancePostureRouter := assetVersionGroup.Group.Group("/compliance-postures")
	compliancePostureRouter.GET("/", compliancePostureController.AssetVersionListPaged)
	compliancePostureRouter.GET("/stats/", compliancePostureController.AssetVersionStats)
	compliancePostureRouter.GET("/:controlHash/", compliancePostureController.AssetVersionRead)
	compliancePostureRouter.POST("/:controlHash/", compliancePostureController.AssetVersionCreateEvent, middlewares.NeededScope([]string{"manage"}), middlewares.DisallowPublicRequests)
	compliancePostureRouter.GET("/oscal/", compliancePostureController.AssetVersionGetOSCAL)
	compliancePostureRouter.POST("/:controlHash/components/:complianceComponentID/", complianceComponentController.AssetVersionCreateStatement, middlewares.NeededScope([]string{"manage"}), middlewares.DisallowPublicRequests)
	compliancePostureRouter.PUT("/components/:statementID/", complianceComponentController.AssetVersionUpdateStatement, middlewares.NeededScope([]string{"manage"}), middlewares.DisallowPublicRequests)
	compliancePostureRouter.DELETE("/components/:statementID/", complianceComponentController.AssetVersionDeleteStatement, middlewares.NeededScope([]string{"manage"}), middlewares.DisallowPublicRequests)

	return CompliancePostureRouter{Group: compliancePostureRouter}
}
