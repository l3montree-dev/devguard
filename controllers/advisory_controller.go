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
	"fmt"
	"strconv"

	"github.com/l3montree-dev/devguard/database/models"
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

// @Summary Create advisory
// @Tags Advisories
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param body body dtos.AdvisoryCreate true "Request body"
// @Success 200
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/refs/{assetVersionSlug}/advisory/ [post]
func (controller *AdvisoryController) Create(ctx shared.Context) error {
	var req dtos.AdvisoryCreate
	if err := ctx.Bind(&req); err != nil {
		return echo.NewHTTPError(400, "unable to process request")
	}

	if err := dtos.V.Struct(req); err != nil {
		return echo.NewHTTPError(400, fmt.Sprintf("invalid request: %s", err.Error()))
	}

	newAdvisory := transformer.AdvisoryCreateRequestToModel(req)
	newAdvisory.AssetID = shared.GetAsset(ctx).ID

	err := controller.advisoryService.Create(ctx.Request().Context(), nil, &newAdvisory)

	if err != nil {
		return echo.NewHTTPError(500, "could not create advisory").WithInternal(err)
	}

	return ctx.NoContent(200)
}

// @Summary List advisories
// @Tags Advisories
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Success 200 {object} shared.Paged[models.Advisory]
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/refs/{assetVersionSlug}/advisory/ [get]
func (controller *AdvisoryController) ReadAll(ctx shared.Context) error {
	asset := shared.GetAsset(ctx)
	var advisories shared.Paged[models.Advisory]
	advisories, err := controller.advisoryService.ReadAll(ctx.Request().Context(), nil, asset.ID, shared.GetFilterQuery(ctx), shared.GetPageInfo(ctx))
	if err != nil {
		return echo.NewHTTPError(500, "could not get any data").WithInternal(err)
	}
	return ctx.JSON(200, advisories)
}

// @Summary Get advisory details
// @Tags Advisories
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param id path string true "Advisory ID"
// @Success 200 {object} models.Advisory
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/refs/{assetVersionSlug}/advisory/{id}/ [get]
func (controller *AdvisoryController) ReadAdvisory(ctx shared.Context) error {
	advisoryID := ctx.Param("id")
	parsedID, err := strconv.ParseInt(advisoryID, 10, 64)
	if err != nil {
		return echo.NewHTTPError(400, "invalid id provided")
	}

	var advisory models.Advisory
	advisory, err = controller.advisoryService.ReadAdvisory(ctx.Request().Context(), nil, parsedID)

	if err != nil {
		if shared.IsNotFound(err) {
			return echo.NewHTTPError(404, "advisory not found").WithInternal(err)
		}
		return echo.NewHTTPError(500, "could not get any data").WithInternal(err)
	}

	if advisory.AssetID != shared.GetAsset(ctx).ID {
		return echo.NewHTTPError(404, "advisory not found")
	}

	return ctx.JSON(200, advisory)
}

// @Summary Update advisory
// @Tags Advisories
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param id path string true "Advisory ID"
// @Param body body dtos.AdvisoryUpdate true "Request body"
// @Success 200
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/refs/{assetVersionSlug}/advisory/{id}/ [patch]
func (controller *AdvisoryController) Update(ctx shared.Context) error {
	var req dtos.AdvisoryUpdate
	if err := ctx.Bind(&req); err != nil { // nosemgrep: bind-without-validate -- AdvisoryUpdate fields are all optional patch pointers with no constraints
		return echo.NewHTTPError(400, "unable to process request")
	}

	advisoryID := ctx.Param("id")
	parsedID, err := strconv.ParseInt(advisoryID, 10, 64)
	if err != nil {
		return echo.NewHTTPError(400, "invalid id provided")
	}

	advisory, err := controller.advisoryService.ReadAdvisory(ctx.Request().Context(), nil, parsedID)
	if err != nil {
		if shared.IsNotFound(err) {
			return echo.NewHTTPError(404, "advisory not found").WithInternal(err)
		}
		return echo.NewHTTPError(500, "could not get any data").WithInternal(err)
	}

	if advisory.AssetID != shared.GetAsset(ctx).ID {
		return echo.NewHTTPError(404, "advisory not found")
	}

	currentVisibility := advisory.Visibility

	advisory = transformer.AdvisoryUpdateRequestToModel(req, advisory)
	advisory.AssetID = shared.GetAsset(ctx).ID

	err = controller.advisoryService.Update(ctx.Request().Context(), nil, parsedID, &advisory, currentVisibility)

	if err != nil {
		return echo.NewHTTPError(500, "could not update advisory").WithInternal(err)
	}

	return ctx.NoContent(200)
}

// @Summary Delete advisory
// @Tags Advisories
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param id path string true "Advisory ID"
// @Success 200
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/refs/{assetVersionSlug}/advisory/{id}/ [delete]
func (controller *AdvisoryController) Delete(ctx shared.Context) error {
	advisoryID := ctx.Param("id")
	parsedID, err := strconv.ParseInt(advisoryID, 10, 64)
	if err != nil {
		return echo.NewHTTPError(400, "invalid id provided")
	}

	advisory, err := controller.advisoryService.ReadAdvisory(ctx.Request().Context(), nil, parsedID)
	if err != nil {
		if shared.IsNotFound(err) {
			return echo.NewHTTPError(404, "advisory not found").WithInternal(err)
		}
		return echo.NewHTTPError(500, "could not get any data").WithInternal(err)
	}

	if advisory.AssetID != shared.GetAsset(ctx).ID {
		return echo.NewHTTPError(404, "advisory not found")
	}

	err = controller.advisoryService.Delete(ctx.Request().Context(), nil, parsedID)

	if err != nil {
		return echo.NewHTTPError(500, "could not delete advisory").WithInternal(err)
	}

	return ctx.NoContent(200)
}
