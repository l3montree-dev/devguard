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
	"github.com/labstack/echo/v4"
)

type ShareDependencyProxyRouter struct {
	*echo.Group
}

func NewShareDependencyProxyRouter(
	apiV1Group APIV1Router,
	dependencyProxyController *controllers.DependencyProxyController,
) ShareDependencyProxyRouter {
	shareDependencyProxyRouter := apiV1Group.Group.Group("/dependency-proxy/:secret")

	shareDependencyProxyRouter.GET("/npm", dependencyProxyController.ProxyNPM)
	shareDependencyProxyRouter.GET("/npm/*", dependencyProxyController.ProxyNPM)

	shareDependencyProxyRouter.GET("/go", dependencyProxyController.ProxyGo)
	shareDependencyProxyRouter.GET("/go/*", dependencyProxyController.ProxyGo)
	shareDependencyProxyRouter.GET("/pypi", dependencyProxyController.ProxyPyPI)
	shareDependencyProxyRouter.GET("/pypi/*", dependencyProxyController.ProxyPyPI)

	return ShareDependencyProxyRouter{Group: shareDependencyProxyRouter}
}
