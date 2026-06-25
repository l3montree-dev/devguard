// Copyright (C) 2023 Tim Bastin, l3montree GmbH
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

package controllers

import (
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/labstack/echo/v4"
)

type AdvisoryController struct {
	advisoryService shared.AdvisoryService
}

func NewAdvisoryController(advisoryService shared.AdvisoryService) *AdvisoryController {
	return &AdvisoryController{
		advisoryService: advisoryService,
	}
}

func (controller *AdvisoryController) Create(ctx shared.Context) error {
	var req dtos.AdvisoryCreate
	if err := ctx.Bind(&req); err != nil {
		return echo.NewHTTPError(400, "unable to process request").WithInternal(err)
	}

	newAdvisory := transformer.AdvisoryCreateRequestToModel(req)

	err := controller.advisoryService.Create(ctx.Request().Context(), &newAdvisory)

	if err != nil {
		return echo.NewHTTPError(409, "could not set name").WithInternal(err)
	}

	return ctx.NoContent(200)
}

// func (controller *advisoryController) ReadName(ctx shared.Context) error {
// 	advisoryNames, err := controller.advisoryService.ReadName(ctx.Request().Context())
// 	if err != nil {
// 		return echo.NewHTTPError(500, "could not get any name").WithInternal(err)
// 	}
// 	return ctx.JSON(200, advisoryNames)
// }

// func (controller *advisoryController) UpdateName(ctx shared.Context) error {
// 	var req dtos.AdvisoryUpdate // Change to own struct
// 	if err := ctx.Bind(&req); err != nil {
// 		return echo.NewHTTPError(400, "unable to process request").WithInternal(err)
// 	}

// 	updateName := req.Name

// 	advisoryID := ctx.Param("id")
// 	parsedID, err := uuid.Parse(advisoryID)
// 	if err != nil {
// 		return echo.NewHTTPError(400, "invalid uuid provided")
// 	}

// 	err = controller.advisoryService.UpdateName(ctx.Request().Context(), parsedID, updateName)

// 	if err != nil {
// 		return echo.NewHTTPError(409, "could not update name").WithInternal(err)
// 	}

// 	return ctx.JSON(200, updateName)
// }

// func (controller *advisoryController) DeleteName(ctx shared.Context) error {
// 	advisoryID := ctx.Param("id")
// 	parsedID, err := uuid.Parse(advisoryID)
// 	if err != nil {
// 		return echo.NewHTTPError(400, "invalid uuid provided")
// 	}

// 	err = controller.advisoryService.DeleteName(ctx.Request().Context(), parsedID)

// 	if err != nil {
// 		return echo.NewHTTPError(409, "could not remove name").WithInternal(err)
// 	}

// 	return ctx.NoContent(200)
// }
