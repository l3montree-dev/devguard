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

package router

import (
	"github.com/l3montree-dev/devguard/controllers"
	"github.com/l3montree-dev/devguard/middlewares"
	"github.com/labstack/echo/v4"
)

// ComplianceComponentRouter exposes the global catalog of compliance
// components (an instance-wide catalog, not scoped to any org/project/asset -
// components are seeded from OSCAL component-definitions and shared across
// all tenants).
type ComplianceComponentRouter struct {
	Group *echo.Group
}

func NewComplianceComponentRouter(apiV1Router APIV1Router, complianceComponentController *controllers.ComplianceComponentController) ComplianceComponentRouter {
	complianceComponentRouter := apiV1Router.Group.Group("/compliance-components")
	complianceComponentRouter.GET("/", complianceComponentController.List)
	complianceComponentRouter.GET("/:complianceComponentID/", complianceComponentController.Details)

	return ComplianceComponentRouter{Group: complianceComponentRouter}
}

// ComplianceComponentStatementRouter exposes CRUD for statements: a specific
// posture's per-component claim about implementation status. Postures are
// scoped to an org/project/asset/asset-version, so this is mounted alongside
// compliance-postures at the asset-version level.
type ComplianceComponentStatementRouter struct {
	*echo.Group
}

func NewComplianceComponentStatementRouter(
	assetVersionGroup AssetVersionRouter,
	complianceComponentController *controllers.ComplianceComponentController,
) ComplianceComponentStatementRouter {
	compliancePostureRouter := assetVersionGroup.Group.Group("/compliance-postures")
	compliancePostureRouter.POST("/:frameworkControlID/components/:complianceComponentID/", complianceComponentController.CreateStatement, middlewares.NeededScope([]string{"manage"}), middlewares.DisallowPublicRequests)
	compliancePostureRouter.PUT("/components/:statementID/", complianceComponentController.UpdateStatement, middlewares.NeededScope([]string{"manage"}), middlewares.DisallowPublicRequests)
	compliancePostureRouter.DELETE("/components/:statementID/", complianceComponentController.DeleteStatement, middlewares.NeededScope([]string{"manage"}), middlewares.DisallowPublicRequests)

	return ComplianceComponentStatementRouter{Group: compliancePostureRouter}
}
