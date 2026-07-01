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
) CompliancePostureRouter {
	compliancePostureRouter := assetVersionGroup.Group.Group("/compliance-postures")
	compliancePostureRouter.GET("/", compliancePostureController.ListPaged)
	compliancePostureRouter.GET("/stats/", compliancePostureController.Stats)
	compliancePostureRouter.GET("/:frameworkControlID/", compliancePostureController.Read)
	compliancePostureRouter.POST("/:frameworkControlID/", compliancePostureController.CreateEvent, middlewares.NeededScope([]string{"manage"}), middlewares.DisallowPublicRequests)

	return CompliancePostureRouter{Group: compliancePostureRouter}
}
