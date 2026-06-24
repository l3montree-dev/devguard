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
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
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

func (controller *AdvisoryController) CreateName(ctx shared.Context) error {
	var req dtos.AdvisoryCreateName
	if err := ctx.Bind(&req); err != nil {
		return echo.NewHTTPError(400, "unable to process request").WithInternal(err)
	}

	newName := req.Name

	err := controller.advisoryService.CreateName(ctx.Request().Context(), newName)

	if err != nil {
		return echo.NewHTTPError(409, "could not set name").WithInternal(err)
	}

	return ctx.JSON(200, newName)
}

func (controller *AdvisoryController) ReadName(ctx shared.Context) error {
	advisory_names, err := controller.advisoryService.ReadName(ctx.Request().Context())
	if err != nil {
		return echo.NewHTTPError(500, "could not get any name").WithInternal(err)
	}
	return ctx.JSON(200, advisory_names)
}

func (controller *AdvisoryController) UpdateName(ctx shared.Context) error {
	var req dtos.AdvisoryCreateName // Change to own struct
	if err := ctx.Bind(&req); err != nil {
		return echo.NewHTTPError(400, "unable to process request").WithInternal(err)
	}

	updateName := req.Name

	advisoryID := ctx.Param("id")
	parsedID, err := uuid.Parse(advisoryID)
	if err != nil {
		return echo.NewHTTPError(400, "invalid uuid provided")
	}

	err = controller.advisoryService.UpdateName(ctx.Request().Context(), parsedID, updateName)

	if err != nil {
		return echo.NewHTTPError(409, "could not update name").WithInternal(err)
	}

	return ctx.JSON(200, updateName)
}

func (controller *AdvisoryController) DeleteName(ctx shared.Context) error {
	advisoryID := ctx.Param("id")
	parsedID, err := uuid.Parse(advisoryID)
	if err != nil {
		return echo.NewHTTPError(400, "invalid uuid provided")
	}

	err = controller.advisoryService.DeleteName(ctx.Request().Context(), parsedID)

	if err != nil {
		return echo.NewHTTPError(409, "could not remove name").WithInternal(err)
	}

	return ctx.NoContent(200)
}
