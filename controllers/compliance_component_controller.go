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

package controllers

import (
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/transformer"
	"gorm.io/gorm"

	"github.com/labstack/echo/v4"
)

type ComplianceComponentController struct {
	complianceComponentRepository shared.ComplianceComponentRepository
	compliancePostureRepository   shared.CompliancePostureRepository
}

func NewComplianceComponentController(complianceComponentRepository shared.ComplianceComponentRepository, compliancePostureRepository shared.CompliancePostureRepository) *ComplianceComponentController {
	return &ComplianceComponentController{
		complianceComponentRepository: complianceComponentRepository,
		compliancePostureRepository:   compliancePostureRepository,
	}
}

func (c *ComplianceComponentController) List(ctx shared.Context) error {
	filter := shared.GetFilterQuery(ctx)

	components, err := c.complianceComponentRepository.ListAll(ctx.Request().Context(), nil, filter)
	if err != nil {
		return err
	}

	result := make([]any, 0, len(components))
	for _, comp := range components {
		result = append(result, transformer.ComplianceComponentToDetailsDTO(comp))
	}

	return ctx.JSON(200, result)
}

func (c *ComplianceComponentController) Details(ctx shared.Context) error {
	id, err := uuid.Parse(ctx.Param("complianceComponentID"))
	if err != nil {
		return echo.NewHTTPError(400, "invalid complianceComponentID")
	}

	component, err := c.complianceComponentRepository.GetDetails(ctx.Request().Context(), nil, id)
	if err != nil {
		return err
	}

	return ctx.JSON(200, transformer.ComplianceComponentToDetailsDTO(*component))
}

type statementPayload struct {
	ImplementationStatus string `json:"implementationStatus"`
	Description          string `json:"description"`
}

func (c *ComplianceComponentController) CreateStatement(ctx shared.Context) error {
	frameworkControlID := ctx.Param("frameworkControlID")
	if frameworkControlID == "" {
		return echo.NewHTTPError(400, "frameworkControlID is required")
	}
	complianceComponentID, err := uuid.Parse(ctx.Param("complianceComponentID"))
	if err != nil {
		return echo.NewHTTPError(400, "invalid complianceComponentID")
	}

	var payload statementPayload
	if err := json.NewDecoder(ctx.Request().Body).Decode(&payload); err != nil {
		return echo.NewHTTPError(400, "invalid payload").WithInternal(err)
	}

	orgID := shared.GetOrg(ctx).ID
	projectID, assetID, assetVersionName := getOwnershipFromCtx(ctx)
	userAgent := ctx.Request().UserAgent()

	posture := models.CompliancePosture{
		FrameworkControlID: frameworkControlID,
		OrgID:              orgID,
		ProjectID:          projectID,
		AssetID:            assetID,
		AssetVersionName:   assetVersionName,
	}
	posture.ID = posture.CalculateHash()

	var created *models.ComplianceComponentImplementsControlStatement
	err = c.compliancePostureRepository.Transaction(ctx.Request().Context(), func(tx *gorm.DB) error {
		compliancePosture, err := c.compliancePostureRepository.FindOrCreate(ctx.Request().Context(), tx, posture)
		if err != nil {
			return fmt.Errorf("failed to find or create compliance posture: %w", err)
		}

		statement := models.ComplianceComponentImplementsControlStatement{
			CompliancePostureID:   compliancePosture.ID,
			ComplianceComponentID: complianceComponentID,
			FrameworkControlID:    frameworkControlID,
			ImplementationStatus:  payload.ImplementationStatus,
			Description:           payload.Description,
		}

		created, err = c.complianceComponentRepository.CreateStatement(ctx.Request().Context(), tx, statement)
		if err != nil {
			return err
		}

		component, err := c.complianceComponentRepository.GetDetails(ctx.Request().Context(), tx, complianceComponentID)
		if err != nil {
			return err
		}

		ev := models.NewAttachedComplianceComponentEvent(compliancePosture.ID, shared.GetSession(ctx).GetActorName(), component.Title, &userAgent)
		return c.compliancePostureRepository.ApplyAndSave(ctx.Request().Context(), tx, compliancePosture, &ev)
	})
	if err != nil {
		return err
	}

	return ctx.JSON(201, transformer.ComplianceComponentImplementsControlStatementToDTO(*created))
}

func (c *ComplianceComponentController) UpdateStatement(ctx shared.Context) error {
	statementID, err := uuid.Parse(ctx.Param("statementID"))
	if err != nil {
		return echo.NewHTTPError(400, "invalid statementID")
	}

	var payload statementPayload
	if err := json.NewDecoder(ctx.Request().Body).Decode(&payload); err != nil {
		return echo.NewHTTPError(400, "invalid payload").WithInternal(err)
	}

	updated, err := c.complianceComponentRepository.UpdateStatement(ctx.Request().Context(), nil, statementID, payload.ImplementationStatus, payload.Description)
	if err != nil {
		return err
	}

	return ctx.JSON(200, transformer.ComplianceComponentImplementsControlStatementToDTO(*updated))
}

func (c *ComplianceComponentController) DeleteStatement(ctx shared.Context) error {
	statementID, err := uuid.Parse(ctx.Param("statementID"))
	if err != nil {
		return echo.NewHTTPError(400, "invalid statementID")
	}

	userAgent := ctx.Request().UserAgent()

	err = c.compliancePostureRepository.Transaction(ctx.Request().Context(), func(tx *gorm.DB) error {
		deleted, err := c.complianceComponentRepository.DeleteStatement(ctx.Request().Context(), tx, statementID)
		if err != nil {
			return err
		}

		posture, err := c.compliancePostureRepository.Read(ctx.Request().Context(), tx, deleted.CompliancePostureID)
		if err != nil {
			return err
		}

		ev := models.NewRemovedComplianceComponentEvent(deleted.CompliancePostureID, shared.GetSession(ctx).GetActorName(), deleted.ComplianceComponentImplementsControl.ComplianceComponent.Title, &userAgent)
		return c.compliancePostureRepository.ApplyAndSave(ctx.Request().Context(), tx, &posture, &ev)
	})
	if err != nil {
		return err
	}

	return ctx.NoContent(204)
}
