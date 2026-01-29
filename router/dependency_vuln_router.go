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

type DependencyVulnRouter struct {
	*echo.Group
}

func NewDependencyVulnRouter(
	assetVersionGroup AssetVersionRouter,
	dependencyVulnController *controllers.DependencyVulnController,
	vulnEventController *controllers.VulnEventController,
) DependencyVulnRouter {
	dependencyVulnRouter := assetVersionGroup.Group.Group("/dependency-vulns")
	dependencyVulnRouter.GET("/", dependencyVulnController.ListPaged)
	dependencyVulnRouter.GET("/sync/", dependencyVulnController.ListByAssetIDWithoutHandledExternalEventsPaged)
	dependencyVulnRouter.GET("/:dependencyVulnID/", dependencyVulnController.Read)
	dependencyVulnRouter.GET("/:dependencyVulnID/events/", vulnEventController.ReadAssetEventsByVulnID)
	dependencyVulnRouter.GET("/:dependencyVulnID/hints/", dependencyVulnController.Hints)

	dependencyVulnRouter.POST("/sync/", dependencyVulnController.SyncDependencyVulns, middlewares.NeededScope([]string{"manage"}))
	dependencyVulnRouter.POST("/batch/", dependencyVulnController.BatchCreateEvent, middlewares.NeededScope([]string{"manage"}))
	dependencyVulnRouter.POST("/:dependencyVulnID/", dependencyVulnController.CreateEvent, middlewares.NeededScope([]string{"manage"}))
	dependencyVulnRouter.POST("/:dependencyVulnID/mitigate/", dependencyVulnController.Mitigate, middlewares.NeededScope([]string{"manage"}))

	return DependencyVulnRouter{Group: dependencyVulnRouter}
}
