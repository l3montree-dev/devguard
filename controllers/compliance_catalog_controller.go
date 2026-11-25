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
	"net/http"
	"net/url"

	_ "github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/labstack/echo/v4"
)

// the SCF catalog alone has about 32mb
const maxOSCALDocumentSize int64 = 64 * 1024 * 1024

type ComplianceCatalogController struct {
	complianceCatalogService shared.ComplianceCatalogService
}

func NewComplianceCatalogController(complianceCatalogService shared.ComplianceCatalogService) *ComplianceCatalogController {
	return &ComplianceCatalogController{
		complianceCatalogService: complianceCatalogService,
	}
}

type saveCatalogRequest struct {
	// optional, defaults to the title of the catalog
	Name    string          `json:"name"`
	Catalog json.RawMessage `json:"catalog" swaggertype:"object"`
}

// @Summary List the catalogs which apply to the organization
// @Tags Compliance Catalogs
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Success 200 {array} dtos.ScopeFramework
// @Router /organizations/{organization}/compliance-postures/catalogs/ [get]
func (c *ComplianceCatalogController) OrgListCatalogs(ctx shared.Context) error {
	return c.ListCatalogs(ctx)
}

// @Summary List the catalogs which apply to the project
// @Tags Compliance Catalogs
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Success 200 {array} dtos.ScopeFramework
// @Router /organizations/{organization}/projects/{projectSlug}/compliance-postures/catalogs/ [get]
func (c *ComplianceCatalogController) ProjectListCatalogs(ctx shared.Context) error {
	return c.ListCatalogs(ctx)
}

// @Summary List the catalogs which apply to the asset
// @Tags Compliance Catalogs
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Success 200 {array} dtos.ScopeFramework
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/compliance-postures/catalogs/ [get]
func (c *ComplianceCatalogController) AssetListCatalogs(ctx shared.Context) error {
	return c.ListCatalogs(ctx)
}

func (c *ComplianceCatalogController) ListCatalogs(ctx shared.Context) error {
	orgID := shared.GetOrg(ctx).ID
	projectID, assetID, _, _ := getOwnershipFromCtx(ctx)

	catalogs, err := c.complianceCatalogService.ListCatalogs(ctx.Request().Context(), nil, orgID, projectID, assetID)
	if err != nil {
		return err
	}
	return ctx.JSON(200, catalogs)
}

// @Summary Activate or upload a catalog for the organization
// @Tags Compliance Catalogs
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param body body saveCatalogRequest true "OSCAL catalog"
// @Success 204
// @Router /organizations/{organization}/compliance-postures/catalogs/ [post]
func (c *ComplianceCatalogController) OrgSaveCatalog(ctx shared.Context) error {
	return c.SaveCatalog(ctx)
}

// @Summary Activate or upload a catalog for the project
// @Tags Compliance Catalogs
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param body body saveCatalogRequest true "OSCAL catalog"
// @Success 204
// @Router /organizations/{organization}/projects/{projectSlug}/compliance-postures/catalogs/ [post]
func (c *ComplianceCatalogController) ProjectSaveCatalog(ctx shared.Context) error {
	return c.SaveCatalog(ctx)
}

// @Summary Activate or upload a catalog for the asset
// @Tags Compliance Catalogs
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Param body body saveCatalogRequest true "OSCAL catalog"
// @Success 204
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/compliance-postures/catalogs/ [post]
func (c *ComplianceCatalogController) AssetSaveCatalog(ctx shared.Context) error {
	return c.SaveCatalog(ctx)
}

func (c *ComplianceCatalogController) SaveCatalog(ctx shared.Context) error {
	ctx.Request().Body = http.MaxBytesReader(ctx.Response(), ctx.Request().Body, maxOSCALDocumentSize)
	defer ctx.Request().Body.Close()

	var req saveCatalogRequest
	if err := json.NewDecoder(ctx.Request().Body).Decode(&req); err != nil {
		return echo.NewHTTPError(400, "invalid payload").WithInternal(err)
	}
	if len(req.Catalog) == 0 {
		return echo.NewHTTPError(400, "catalog is required")
	}

	orgID := shared.GetOrg(ctx).ID
	projectID, assetID, _, _ := getOwnershipFromCtx(ctx)

	if err := c.complianceCatalogService.SaveCatalog(ctx.Request().Context(), nil, orgID, projectID, assetID, req.Name, req.Catalog); err != nil {
		return err
	}
	return ctx.NoContent(204)
}

// @Summary Remove a catalog from the organization
// @Tags Compliance Catalogs
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param name path string true "Catalog name"
// @Success 204
// @Router /organizations/{organization}/compliance-postures/catalogs/{name}/ [delete]
func (c *ComplianceCatalogController) OrgDeleteCatalog(ctx shared.Context) error {
	return c.DeleteCatalog(ctx)
}

// @Summary Remove a catalog from the project
// @Tags Compliance Catalogs
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param name path string true "Catalog name"
// @Success 204
// @Router /organizations/{organization}/projects/{projectSlug}/compliance-postures/catalogs/{name}/ [delete]
func (c *ComplianceCatalogController) ProjectDeleteCatalog(ctx shared.Context) error {
	return c.DeleteCatalog(ctx)
}

// @Summary Remove a catalog from the asset
// @Tags Compliance Catalogs
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Param name path string true "Catalog name"
// @Success 204
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/compliance-postures/catalogs/{name}/ [delete]
func (c *ComplianceCatalogController) AssetDeleteCatalog(ctx shared.Context) error {
	return c.DeleteCatalog(ctx)
}

func (c *ComplianceCatalogController) DeleteCatalog(ctx shared.Context) error {
	name, err := url.PathUnescape(ctx.Param("name"))
	if err != nil || name == "" {
		return echo.NewHTTPError(400, "name is required")
	}

	orgID := shared.GetOrg(ctx).ID
	projectID, assetID, _, _ := getOwnershipFromCtx(ctx)

	if err := c.complianceCatalogService.DeleteCatalog(ctx.Request().Context(), nil, orgID, projectID, assetID, name); err != nil {
		return err
	}
	return ctx.NoContent(204)
}
