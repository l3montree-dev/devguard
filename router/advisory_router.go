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
	"github.com/l3montree-dev/devguard/shared"
	"github.com/labstack/echo/v4"
)

type AdvisoryRouter struct {
	*echo.Group
}

func NewAdvisoryRouter(
	assetRepository shared.AssetRepository,
	assetVersionGroup AssetVersionRouter,
	advisoryController *controllers.AdvisoryController,
) AdvisoryRouter {
	advisoryRouter := assetVersionGroup.Group.Group("/advisory")
	advisoryRouter.POST("/", advisoryController.Create)
	// advisoryRouter.GET("/", advisoryController.Read)
	// advisoryRouter.PATCH("/:id/", advisoryController.Update)
	// advisoryRouter.DELETE("/:id/", advisoryController.Delete)

	return AdvisoryRouter{Group: advisoryRouter}
}
