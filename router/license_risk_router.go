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
	"github.com/labstack/echo/v4"
)

type LicenseRiskRouter struct {
	*echo.Group
}

func NewLicenseRiskRouter(
	assetVersionGroup AssetVersionRouter,
	licenseRiskController *controllers.LicenseRiskController,
) LicenseRiskRouter {
	licenseRiskRouter := assetVersionGroup.Group.Group("/license-risks")
	licenseRiskRouter.GET("/", licenseRiskController.ListPaged)
	licenseRiskRouter.GET("/:licenseRiskID/", licenseRiskController.Read)
	licenseRiskRouter.POST("/", licenseRiskController.Create, middlewares.NeededScope([]string{"manage"}))
	licenseRiskRouter.POST("/:licenseRiskID/", licenseRiskController.CreateEvent, middlewares.NeededScope([]string{"manage"}))
	licenseRiskRouter.POST("/:licenseRiskID/mitigate/", licenseRiskController.Mitigate, middlewares.NeededScope([]string{"manage"}))
	licenseRiskRouter.POST("/:licenseRiskID/final-license-decision/", licenseRiskController.MakeFinalLicenseDecision, middlewares.NeededScope([]string{"manage"}))

	return LicenseRiskRouter{Group: licenseRiskRouter}
}
