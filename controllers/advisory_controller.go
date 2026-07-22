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
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
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

	userID := shared.GetSession(ctx).GetUserID()
	userAgent := ctx.Request().UserAgent()
	if _, err := controller.advisoryService.CreateVulnEventAndApply(ctx.Request().Context(), nil, userID, &newAdvisory, dtos.EventTypeCreated, "", "", &userAgent); err != nil {
		return echo.NewHTTPError(500, "could not create advisory created event").WithInternal(err)
	}

	return ctx.NoContent(200)
}

func (controller *AdvisoryController) ReadAll(ctx shared.Context) error {
	asset := shared.GetAsset(ctx)
	advisories, err := controller.advisoryService.ReadAll(ctx.Request().Context(), nil, asset.ID, shared.GetFilterQuery(ctx), shared.GetPageInfo(ctx))
	if err != nil {
		return echo.NewHTTPError(500, "could not get any data").WithInternal(err)
	}
	return ctx.JSON(200, advisories)
}

func (controller *AdvisoryController) ReadAdvisory(ctx shared.Context) error {
	advisoryID := ctx.Param("id")
	parsedID, err := uuid.Parse(advisoryID)
	if err != nil {
		return echo.NewHTTPError(400, "invalid id provided")
	}

	advisory, err := controller.advisoryService.ReadAdvisory(ctx.Request().Context(), nil, parsedID)

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return echo.NewHTTPError(404, "advisory not found").WithInternal(err)
		}
		return echo.NewHTTPError(500, "could not get any data").WithInternal(err)
	}

	if advisory.AssetID != shared.GetAsset(ctx).ID {
		return echo.NewHTTPError(404, "advisory not found")
	}

	return ctx.JSON(200, advisory)
}

func (controller *AdvisoryController) Update(ctx shared.Context) error {
	var req dtos.AdvisoryUpdate
	if err := ctx.Bind(&req); err != nil {
		return echo.NewHTTPError(400, "unable to process request")
	}

	advisoryID := ctx.Param("id")
	parsedID, err := uuid.Parse(advisoryID)
	if err != nil {
		return echo.NewHTTPError(400, "invalid id provided")
	}

	advisory, err := controller.advisoryService.ReadAdvisory(ctx.Request().Context(), nil, parsedID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return echo.NewHTTPError(404, "advisory not found").WithInternal(err)
		}
		return echo.NewHTTPError(500, "could not get any data").WithInternal(err)
	}

	if advisory.AssetID != shared.GetAsset(ctx).ID {
		return echo.NewHTTPError(404, "advisory not found")
	}

	currentState := advisory.State

	advisory = transformer.AdvisoryUpdateRequestToModel(req, advisory)
	advisory.AssetID = shared.GetAsset(ctx).ID

	err = controller.advisoryService.Update(ctx.Request().Context(), nil, parsedID, &advisory, currentState)

	if err != nil {
		return echo.NewHTTPError(500, "could not update advisory").WithInternal(err)
	}

	return ctx.NoContent(200)
}

func (controller *AdvisoryController) Delete(ctx shared.Context) error {
	advisoryID := ctx.Param("id")
	parsedID, err := uuid.Parse(advisoryID)
	if err != nil {
		return echo.NewHTTPError(400, "invalid id provided")
	}

	advisory, err := controller.advisoryService.ReadAdvisory(ctx.Request().Context(), nil, parsedID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
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

func (controller *AdvisoryController) CreateEvent(ctx shared.Context) error {
	advisoryID := ctx.Param("id")
	parsedID, err := uuid.Parse(advisoryID)
	if err != nil {
		return echo.NewHTTPError(400, "invalid id provided")
	}

	advisory, err := controller.advisoryService.ReadAdvisory(ctx.Request().Context(), nil, parsedID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return echo.NewHTTPError(404, "advisory not found").WithInternal(err)
		}
		return echo.NewHTTPError(500, "could not get any data").WithInternal(err)
	}

	if advisory.AssetID != shared.GetAsset(ctx).ID {
		return echo.NewHTTPError(404, "advisory not found")
	}

	userID := shared.GetSession(ctx).GetUserID()

	var status dtos.CreateEventRequest
	if err := json.NewDecoder(ctx.Request().Body).Decode(&status); err != nil {
		return echo.NewHTTPError(400, "invalid payload").WithInternal(err)
	}

	if err := dtos.V.Struct(status); err != nil {
		return echo.NewHTTPError(400, fmt.Sprintf("could not validate request: %s", err.Error()))
	}

	statusType := status.StatusType
	if err := models.CheckStatusType(statusType); err != nil {
		return echo.NewHTTPError(400, "invalid status type")
	}

	userAgent := ctx.Request().UserAgent()
	_, err = controller.advisoryService.CreateVulnEventAndApply(ctx.Request().Context(), nil, userID, &advisory, dtos.VulnEventType(statusType), status.Justification, status.MechanicalJustification, &userAgent)
	if err != nil {
		return echo.NewHTTPError(500, "could not create event").WithInternal(err)
	}

	return ctx.JSON(200, advisory)
}
