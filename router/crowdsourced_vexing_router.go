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

type CrowdsourcedVexingRouter struct {
	*echo.Group
}

func NewCrowdsourcedVexingRouter(
	assetVersionRouter AssetVersionRouter,
	crowdsourcedVexingController *controllers.CrowdsourcedVexingController,
) CrowdsourcedVexingRouter {
	group := assetVersionRouter.Group.Group("/crowdsourced-vexing")

	group.GET("/recommendation/", crowdsourcedVexingController.Recommend)
	return CrowdsourcedVexingRouter{Group: group}
}
