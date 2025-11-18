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

type PatRouter struct {
	*echo.Group
}

func NewPatRouter(
	sessionGroup SessionRouter,
	patController *controllers.PatController,
) PatRouter {
	/**
	Personal access token router
	This does not happen in a org or anything.
	We only need to make sure, that the user is logged in (sessionRouter)
	*/
	patRouter := sessionGroup.Group.Group("/pats", middlewares.NeededScope([]string{"manage"}))
	patRouter.GET("/", patController.List)
	patRouter.POST("/", patController.Create)
	patRouter.POST("/revoke-by-private-key/", patController.RevokeByPrivateKey)
	patRouter.DELETE("/:tokenID/", patController.Delete)

	return PatRouter{Group: patRouter}
}
