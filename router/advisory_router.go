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

type AdvisoryRouter struct {
	*echo.Group
}

func NewAdvisoryRouter(
	assetVersionGroup AssetVersionRouter,
	advisoryController *controllers.AdvisoryController,
	assetRepository shared.AssetRepository,
) AdvisoryRouter {
	advisoryRouter := assetVersionGroup.Group.Group("/advisory")

	advisoryRouter.GET("/", advisoryController.ReadAll)
	advisoryRouter.GET("/:id/", advisoryController.ReadAdvisory)

	advisoryRouter.POST("/", advisoryController.Create, middlewares.NeededScope([]string{"manage"}), middlewares.AssetAccessControl(shared.ObjectAsset, shared.ActionUpdate))
	advisoryRouter.PATCH("/:id/", advisoryController.Update, middlewares.NeededScope([]string{"manage"}), middlewares.AssetAccessControl(shared.ObjectAsset, shared.ActionUpdate))
	advisoryRouter.DELETE("/:id/", advisoryController.Delete, middlewares.NeededScope([]string{"manage"}), middlewares.AssetAccessControl(shared.ObjectAsset, shared.ActionUpdate))

	return AdvisoryRouter{Group: advisoryRouter}
}
