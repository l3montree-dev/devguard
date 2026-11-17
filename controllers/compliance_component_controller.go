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
	"net/http"
	"net/url"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	_ "github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/transformer"
	"gorm.io/gorm"

	"github.com/labstack/echo/v4"
)

type ComplianceComponentController struct {
	complianceComponentRepository        shared.ComplianceComponentRepository
	compliancePostureRepository          shared.CompliancePostureRepository
	compliancePostureService             shared.CompliancePostureService
	complianceComponentDefinitionService shared.ComplianceComponentDefinitionService
}

func NewComplianceComponentController(complianceComponentRepository shared.ComplianceComponentRepository, compliancePostureRepository shared.CompliancePostureRepository, compliancePostureService shared.CompliancePostureService, complianceComponentDefinitionService shared.ComplianceComponentDefinitionService) *ComplianceComponentController {
	return &ComplianceComponentController{
		complianceComponentRepository:        complianceComponentRepository,
		compliancePostureRepository:          compliancePostureRepository,
		compliancePostureService:             compliancePostureService,
		complianceComponentDefinitionService: complianceComponentDefinitionService,
	}
}

type saveComponentDefinitionRequest struct {
	// optional, defaults to the title of the component definition
	Name                string          `json:"name"`
	ComponentDefinition json.RawMessage `json:"componentDefinition" swaggertype:"object"`
}

// @Summary List the compliance components which apply to the organization
// @Tags Compliance Components
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Success 200 {array} dtos.ComplianceComponentDetails
// @Router /organizations/{organization}/compliance-components/ [get]
func (c *ComplianceComponentController) OrgList(ctx shared.Context) error {
	return c.List(ctx)
}

// @Summary List the compliance components which apply to the project
// @Tags Compliance Components
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Success 200 {array} dtos.ComplianceComponentDetails
// @Router /organizations/{organization}/projects/{projectSlug}/compliance-components/ [get]
func (c *ComplianceComponentController) ProjectList(ctx shared.Context) error {
	return c.List(ctx)
}

// @Summary List the compliance components which apply to the asset
// @Tags Compliance Components
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Success 200 {array} dtos.ComplianceComponentDetails
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/compliance-components/ [get]
func (c *ComplianceComponentController) AssetList(ctx shared.Context) error {
	return c.List(ctx)
}

func (c *ComplianceComponentController) List(ctx shared.Context) error {
	filter := shared.GetFilterQuery(ctx)
	orgID := shared.GetOrg(ctx).ID
	projectID, assetID, _, _ := getOwnershipFromCtx(ctx)

	components, err := c.complianceComponentRepository.ListAll(ctx.Request().Context(), nil, orgID, projectID, assetID, filter)
	if err != nil {
		return err
	}

	result := make([]any, 0, len(components))
	for _, comp := range components {
		result = append(result, transformer.ComplianceComponentToDetailsDTO(comp))
	}

	return ctx.JSON(200, result)
}

// @Summary Get compliance component details
// @Tags Compliance Components
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param complianceComponentID path string true "Compliance component ID"
// @Success 200 {object} dtos.ComplianceComponentDetails
// @Router /organizations/{organization}/compliance-components/{complianceComponentID}/ [get]
func (c *ComplianceComponentController) OrgDetails(ctx shared.Context) error {
	return c.Details(ctx)
}

// @Summary Get compliance component details
// @Tags Compliance Components
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param complianceComponentID path string true "Compliance component ID"
// @Success 200 {object} dtos.ComplianceComponentDetails
// @Router /organizations/{organization}/projects/{projectSlug}/compliance-components/{complianceComponentID}/ [get]
func (c *ComplianceComponentController) ProjectDetails(ctx shared.Context) error {
	return c.Details(ctx)
}

// @Summary Get compliance component details
// @Tags Compliance Components
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Param complianceComponentID path string true "Compliance component ID"
// @Success 200 {object} dtos.ComplianceComponentDetails
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/compliance-components/{complianceComponentID}/ [get]
func (c *ComplianceComponentController) AssetDetails(ctx shared.Context) error {
	return c.Details(ctx)
}

func (c *ComplianceComponentController) Details(ctx shared.Context) error {
	id, err := uuid.Parse(ctx.Param("complianceComponentID"))
	if err != nil {
		return echo.NewHTTPError(400, "invalid complianceComponentID")
	}

	orgID := shared.GetOrg(ctx).ID
	projectID, assetID, _, _ := getOwnershipFromCtx(ctx)

	component, err := c.complianceComponentRepository.GetDetails(ctx.Request().Context(), nil, orgID, projectID, assetID, id)
	if err != nil {
		if shared.IsNotFound(err) {
			return echo.NewHTTPError(404, "compliance component not found")
		}
		return err
	}

	return ctx.JSON(200, transformer.ComplianceComponentToDetailsDTO(*component))
}

type statementPayload struct {
	ImplementationStatus string `json:"implementationStatus"`
	Description          string `json:"description"`
}

// @Summary Create a compliance statement for a component
// @Tags Compliance Components
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param controlHash path string true "Control hash"
// @Param complianceComponentID path string true "Compliance component ID"
// @Param body body statementPayload true "Request body"
// @Success 201 {object} dtos.ComplianceComponentImplementsControlStatement
// @Router /organizations/{organization}/compliance-postures/{controlHash}/components/{complianceComponentID}/ [post]
func (c *ComplianceComponentController) OrgCreateStatement(ctx shared.Context) error {
	return c.CreateStatement(ctx)
}

// @Summary Create a compliance statement for a component
// @Tags Compliance Components
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param controlHash path string true "Control hash"
// @Param complianceComponentID path string true "Compliance component ID"
// @Param body body statementPayload true "Request body"
// @Success 201 {object} dtos.ComplianceComponentImplementsControlStatement
// @Router /organizations/{organization}/projects/{projectSlug}/compliance-postures/{controlHash}/components/{complianceComponentID} [post]
func (c *ComplianceComponentController) ProjectCreateStatement(ctx shared.Context) error {
	return c.CreateStatement(ctx)
}

// @Summary Create a compliance statement for a component
// @Tags Compliance Components
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Param assetVersionSlug path string true "Asset version slug"
// @Param controlHash path string true "Control hash"
// @Param complianceComponentID path string true "Compliance component ID"
// @Param body body statementPayload true "Request body"
// @Success 201 {object} dtos.ComplianceComponentImplementsControlStatement
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/refs/{assetVersionSlug}/compliance-postures/{controlHash}/components/{complianceComponentID} [post]
func (c *ComplianceComponentController) AssetVersionCreateStatement(ctx shared.Context) error {
	return c.CreateStatement(ctx)
}

func (c *ComplianceComponentController) CreateStatement(ctx shared.Context) error {
	controlHash, err := getControlHashFromCtx(ctx)
	if err != nil {
		return err
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
	projectID, assetID, assetVersionID, assetVersionName := getOwnershipFromCtx(ctx)
	userAgent := ctx.Request().UserAgent()

	frameworkControlID, err := c.implementedFrameworkControlID(ctx, controlHash, complianceComponentID)
	if err != nil {
		return err
	}

	posture := models.CompliancePosture{
		ControlHash:      controlHash,
		OrgID:            orgID,
		ProjectID:        projectID,
		AssetID:          assetID,
		AssetVersionID:   assetVersionID,
		AssetVersionName: assetVersionName,
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

		ev := models.NewAttachedComplianceComponentEvent(compliancePosture.ID, shared.GetSession(ctx).GetActorName(), &userAgent)
		return c.compliancePostureRepository.ApplyAndSave(ctx.Request().Context(), tx, compliancePosture, &ev)
	})
	if err != nil {
		return err
	}

	return ctx.JSON(201, transformer.ComplianceComponentImplementsControlStatementToDTO(*created))
}

// implementedFrameworkControlID returns the "<framework>:<control_id>" by which the component implements the control.
// Both the control and the component have to apply to the scope.
func (c *ComplianceComponentController) implementedFrameworkControlID(ctx shared.Context, controlHash string, complianceComponentID uuid.UUID) (string, error) {
	orgID := shared.GetOrg(ctx).ID
	projectID, assetID, assetVersionID, _ := getOwnershipFromCtx(ctx)

	posture, err := c.compliancePostureService.GetForControl(ctx.Request().Context(), nil, controlHash, assetVersionID, assetID, projectID, orgID)
	if err != nil {
		if shared.IsNotFound(err) {
			return "", echo.NewHTTPError(404, "control not found")
		}
		return "", err
	}
	component, err := c.complianceComponentRepository.GetDetails(ctx.Request().Context(), nil, orgID, projectID, assetID, complianceComponentID)
	if err != nil {
		if shared.IsNotFound(err) {
			return "", echo.NewHTTPError(404, "compliance component not found")
		}
		return "", err
	}

	for _, sf := range posture.FrameworkControl.ScopeFrameworks {
		frameworkControlID := sf.Framework + ":" + posture.FrameworkControl.ControlID
		for _, implemented := range component.ImplementedControls {
			if implemented.FrameworkControlID == frameworkControlID {
				return frameworkControlID, nil
			}
		}
	}
	return "", echo.NewHTTPError(400, "the compliance component does not implement this control")
}

// @Summary Update a compliance statement
// @Tags Compliance Components
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param statementID path string true "Statement ID"
// @Param body body statementPayload true "Request body"
// @Success 200 {object} dtos.ComplianceComponentImplementsControlStatement
// @Router /organizations/{organization}/compliance-postures/components/{statementID}/ [put]
func (c *ComplianceComponentController) OrgUpdateStatement(ctx shared.Context) error {
	return c.UpdateStatement(ctx)
}

// @Summary Update a compliance statement
// @Tags Compliance Components
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param statementID path string true "Statement ID"
// @Param body body statementPayload true "Request body"
// @Success 200 {object} dtos.ComplianceComponentImplementsControlStatement
// @Router /organizations/{organization}/projects/{projectSlug}/compliance-postures/components/{statementID} [put]
func (c *ComplianceComponentController) ProjectUpdateStatement(ctx shared.Context) error {
	return c.UpdateStatement(ctx)
}

// @Summary Update a compliance statement
// @Tags Compliance Components
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Param assetVersionSlug path string true "Asset version slug"
// @Param statementID path string true "Statement ID"
// @Param body body statementPayload true "Request body"
// @Success 200 {object} dtos.ComplianceComponentImplementsControlStatement
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/refs/{assetVersionSlug}/compliance-postures/components/{statementID} [put]
func (c *ComplianceComponentController) AssetVersionUpdateStatement(ctx shared.Context) error {
	return c.UpdateStatement(ctx)
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

// @Summary Delete a compliance statement
// @Tags Compliance Components
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param statementID path string true "Statement ID"
// @Success 200 {object} object
// @Router /organizations/{organization}/compliance-postures/components/{statementID}/ [delete]
func (c *ComplianceComponentController) OrgDeleteStatement(ctx shared.Context) error {
	return c.DeleteStatement(ctx)
}

// @Summary Delete a compliance statement
// @Tags Compliance Components
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param statementID path string true "Statement ID"
// @Success 200 {object} object
// @Router /organizations/{organization}/projects/{projectSlug}/compliance-postures/components/{statementID} [delete]
func (c *ComplianceComponentController) ProjectDeleteStatement(ctx shared.Context) error {
	return c.DeleteStatement(ctx)
}

// @Summary Delete a compliance statement
// @Tags Compliance Components
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Param assetVersionSlug path string true "Asset version slug"
// @Param statementID path string true "Statement ID"
// @Success 200 {object} object
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/refs/{assetVersionSlug}/compliance-postures/components/{statementID} [delete]
func (c *ComplianceComponentController) AssetVersionDeleteStatement(ctx shared.Context) error {
	return c.DeleteStatement(ctx)
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

		ev := models.NewRemovedComplianceComponentEvent(deleted.CompliancePostureID, shared.GetSession(ctx).GetActorName(), &userAgent)
		return c.compliancePostureRepository.ApplyAndSave(ctx.Request().Context(), tx, &posture, &ev)
	})
	if err != nil {
		// a missing statementID surfaces as gorm.ErrRecordNotFound from inside the
		// transaction - translate that into a 404 instead of a 500
		if shared.IsNotFound(err) {
			return echo.NewHTTPError(404, "statement not found")
		}
		return err
	}

	return ctx.NoContent(204)
}

// @Summary Upload a component definition for the organization
// @Tags Compliance Component Definitions
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param body body saveComponentDefinitionRequest true "OSCAL component definition"
// @Success 204
// @Router /organizations/{organization}/compliance-components/definitions/ [post]
func (c *ComplianceComponentController) OrgSaveComponentDefinition(ctx shared.Context) error {
	return c.SaveComponentDefinition(ctx)
}

// @Summary Upload a component definition for the project
// @Tags Compliance Component Definitions
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param body body saveComponentDefinitionRequest true "OSCAL component definition"
// @Success 204
// @Router /organizations/{organization}/projects/{projectSlug}/compliance-components/definitions/ [post]
func (c *ComplianceComponentController) ProjectSaveComponentDefinition(ctx shared.Context) error {
	return c.SaveComponentDefinition(ctx)
}

// @Summary Upload a component definition for the asset
// @Tags Compliance Component Definitions
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Param body body saveComponentDefinitionRequest true "OSCAL component definition"
// @Success 204
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/compliance-components/definitions/ [post]
func (c *ComplianceComponentController) AssetSaveComponentDefinition(ctx shared.Context) error {
	return c.SaveComponentDefinition(ctx)
}

func (c *ComplianceComponentController) SaveComponentDefinition(ctx shared.Context) error {
	ctx.Request().Body = http.MaxBytesReader(ctx.Response(), ctx.Request().Body, maxOSCALDocumentSize)
	defer ctx.Request().Body.Close()

	var req saveComponentDefinitionRequest
	if err := json.NewDecoder(ctx.Request().Body).Decode(&req); err != nil {
		return echo.NewHTTPError(400, "invalid payload").WithInternal(err)
	}
	if len(req.ComponentDefinition) == 0 {
		return echo.NewHTTPError(400, "componentDefinition is required")
	}

	orgID := shared.GetOrg(ctx).ID
	projectID, assetID, _, _ := getOwnershipFromCtx(ctx)

	if err := c.complianceComponentDefinitionService.SaveComponentDefinition(ctx.Request().Context(), nil, orgID, projectID, assetID, req.Name, req.ComponentDefinition); err != nil {
		return err
	}
	return ctx.NoContent(204)
}

// @Summary Remove a component definition from the organization
// @Tags Compliance Component Definitions
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param name path string true "Component definition name"
// @Success 204
// @Router /organizations/{organization}/compliance-components/definitions/{name}/ [delete]
func (c *ComplianceComponentController) OrgDeleteComponentDefinition(ctx shared.Context) error {
	return c.DeleteComponentDefinition(ctx)
}

// @Summary Remove a component definition from the project
// @Tags Compliance Component Definitions
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param name path string true "Component definition name"
// @Success 204
// @Router /organizations/{organization}/projects/{projectSlug}/compliance-components/definitions/{name}/ [delete]
func (c *ComplianceComponentController) ProjectDeleteComponentDefinition(ctx shared.Context) error {
	return c.DeleteComponentDefinition(ctx)
}

// @Summary Remove a component definition from the asset
// @Tags Compliance Component Definitions
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Param name path string true "Component definition name"
// @Success 204
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/compliance-components/definitions/{name}/ [delete]
func (c *ComplianceComponentController) AssetDeleteComponentDefinition(ctx shared.Context) error {
	return c.DeleteComponentDefinition(ctx)
}

func (c *ComplianceComponentController) DeleteComponentDefinition(ctx shared.Context) error {
	name, err := url.PathUnescape(ctx.Param("name"))
	if err != nil || name == "" {
		return echo.NewHTTPError(400, "name is required")
	}

	orgID := shared.GetOrg(ctx).ID
	projectID, assetID, _, _ := getOwnershipFromCtx(ctx)

	if err := c.complianceComponentDefinitionService.DeleteComponentDefinition(ctx.Request().Context(), nil, orgID, projectID, assetID, name); err != nil {
		return err
	}
	return ctx.NoContent(204)
}
