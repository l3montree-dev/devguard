// Copyright (C) 2026 L3montree GmbH
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
	"fmt"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/labstack/echo/v4"
)

type SecretController struct {
	secretRepository shared.SecretRepository
	secretService    shared.SecretService
}

func NewSecretController(secretRepository shared.SecretRepository, projectRepository shared.ProjectRepository, secretService shared.SecretService) *SecretController {
	return &SecretController{
		secretRepository: secretRepository,
		secretService:    secretService,
	}
}

func scopeIDs(ctx shared.Context) (uuid.UUID, *uuid.UUID, *uuid.UUID) {
	var orgID uuid.UUID
	var projectID, assetID *uuid.UUID
	orgID = shared.GetOrg(ctx).GetID()
	project, err := shared.MaybeGetProject(ctx)
	if err == nil {
		id := project.ID
		projectID = &id
	}
	asset, err := shared.MaybeGetAsset(ctx)
	if err == nil {
		id := asset.ID
		assetID = &id
	}
	return orgID, projectID, assetID
}

func (c *SecretController) list(ctx shared.Context) error {
	orgID, projectID, assetID := scopeIDs(ctx)
	// we swallow the error - if there is no asset, we will go with nil asset name
	asset, _ := shared.MaybeGetAsset(ctx)

	secrets, err := c.secretService.GetSecrets(ctx.Request().Context(), orgID, projectID, assetID, shared.GetOrg(ctx).Name, utils.EmptyThenNil(asset.Name))
	if err != nil {
		return echo.NewHTTPError(500, "could not load secrets").WithInternal(err)
	}

	return ctx.JSON(200, secrets)
}

func (c *SecretController) create(ctx shared.Context) error {
	var req dtos.SecretCreateRequest
	if err := ctx.Bind(&req); err != nil {
		return echo.NewHTTPError(400, "unable to process request").WithInternal(err)
	}
	if err := dtos.V.Struct(req); err != nil {
		return echo.NewHTTPError(400, fmt.Sprintf("could not validate request: %s", err.Error()))
	}

	orgID, projectID, assetID := scopeIDs(ctx)
	secret := models.Secret{Name: req.Name, Value: req.Value}
	switch {
	case assetID != nil:
		secret.AssetID = assetID
	case projectID != nil:
		secret.ProjectID = projectID
	default:
		secret.OrgID = &orgID
	}

	if err := c.secretRepository.Save(ctx.Request().Context(), nil, &secret); err != nil {
		if database.IsDuplicateKeyError(err) {
			return echo.NewHTTPError(409, fmt.Sprintf("secret %s already exists", req.Name)).WithInternal(err)
		}
		return echo.NewHTTPError(500, "could not save secret").WithInternal(err)
	}

	return ctx.JSON(201, transformer.SecretToDTO(secret, nil))
}

func (c *SecretController) delete(ctx shared.Context) error {
	id, err := uuid.Parse(ctx.Param("id"))
	if err != nil {
		return echo.NewHTTPError(400, "invalid id format")
	}

	orgID, projectID, assetID := scopeIDs(ctx)
	if err := c.secretRepository.DeleteOwned(ctx.Request().Context(), nil, id, orgID, projectID, assetID); err != nil {
		if shared.IsNotFound(err) {
			return echo.NewHTTPError(404, "secret not found")
		}
		return echo.NewHTTPError(500, "could not delete secret").WithInternal(err)
	}

	return ctx.NoContent(200)
}

// @Summary List organization secrets
// @Tags Secrets
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Success 200 {array} dtos.SecretDTO
// @Router /organizations/{organization}/devguard-secrets [get]
func (c *SecretController) OrgList(ctx shared.Context) error {
	return c.list(ctx)
}

// @Summary Create organization secret
// @Tags Secrets
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param body body dtos.SecretCreateRequest true "Request body"
// @Success 201 {object} dtos.SecretDTO
// @Router /organizations/{organization}/devguard-secrets [post]
func (c *SecretController) OrgCreate(ctx shared.Context) error {
	return c.create(ctx)
}

// @Summary Delete organization secret
// @Tags Secrets
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param id path string true "Secret ID"
// @Success 200
// @Router /organizations/{organization}/devguard-secrets/{id} [delete]
func (c *SecretController) OrgDelete(ctx shared.Context) error {
	return c.delete(ctx)
}

// @Summary List project secrets
// @Tags Secrets
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Success 200 {array} dtos.SecretDTO
// @Router /organizations/{organization}/projects/{projectSlug}/devguard-secrets [get]
func (c *SecretController) ProjectList(ctx shared.Context) error {
	return c.list(ctx)
}

// @Summary Create project secret
// @Tags Secrets
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param body body dtos.SecretCreateRequest true "Request body"
// @Success 201 {object} dtos.SecretDTO
// @Router /organizations/{organization}/projects/{projectSlug}/devguard-secrets [post]
func (c *SecretController) ProjectCreate(ctx shared.Context) error {
	return c.create(ctx)
}

// @Summary Delete project secret
// @Tags Secrets
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param id path string true "Secret ID"
// @Success 200
// @Router /organizations/{organization}/projects/{projectSlug}/devguard-secrets/{id} [delete]
func (c *SecretController) ProjectDelete(ctx shared.Context) error {
	return c.delete(ctx)
}

// @Summary List repository secrets
// @Tags Secrets
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Success 200 {array} dtos.SecretDTO
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/devguard-secrets [get]
func (c *SecretController) AssetList(ctx shared.Context) error {
	return c.list(ctx)
}

// @Summary Create repository secret
// @Tags Secrets
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Param body body dtos.SecretCreateRequest true "Request body"
// @Success 201 {object} dtos.SecretDTO
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/devguard-secrets [post]
func (c *SecretController) AssetCreate(ctx shared.Context) error {
	return c.create(ctx)
}

// @Summary Delete repository secret
// @Tags Secrets
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Param id path string true "Secret ID"
// @Success 200
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/devguard-secrets/{id} [delete]
func (c *SecretController) AssetDelete(ctx shared.Context) error {
	return c.delete(ctx)
}
