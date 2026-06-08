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
	"github.com/l3montree-dev/devguard/shared"
	"github.com/labstack/echo/v4"
)

type ExternalReferenceRouter struct {
	*echo.Group
}

func NewExternalReferenceRouter(
	assetVersionRouter AssetVersionRouter,
	externalReferenceController *controllers.ExternalReferenceController,
	assetRepository shared.AssetRepository,
) ExternalReferenceRouter {
	assetScopedRBAC := middlewares.AssetAccessControlFactory(assetRepository)
	// External references are scoped to asset versions
	// Read access - anyone who can read the asset version can list references
	refGroup := assetVersionRouter.Group.Group("/external-references")
	refGroup.GET("/", externalReferenceController.List) // List all references for asset version

	// Write access - requires asset update permission
	refWriteGroup := refGroup.Group("", middlewares.NeededScope([]string{"manage"}))
	refWriteGroup.POST("/", externalReferenceController.Create, assetScopedRBAC(shared.ObjectAsset, shared.ActionUpdate))       // Create reference
	refWriteGroup.POST("/sync/", externalReferenceController.Sync, assetScopedRBAC(shared.ObjectAsset, shared.ActionUpdate))    // Sync external sources
	refWriteGroup.DELETE("/:id/", externalReferenceController.Delete, assetScopedRBAC(shared.ObjectAsset, shared.ActionUpdate)) // Delete reference

	return ExternalReferenceRouter{Group: refGroup}
}
