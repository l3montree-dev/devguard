// Copyright (C) 2025 l3montree GmbH
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

type ShareRouter struct {
	*echo.Group
}

func NewShareRouter(apiV1Router APIV1Router,
	assetController *controllers.AssetController,
	orgRepository shared.OrganizationRepository,
	projectRepository shared.ProjectRepository,
	assetRepository shared.AssetRepository,
	assetVersionRepository shared.AssetVersionRepository,
	artifactRepository shared.ArtifactRepository,
	artifactController *controllers.ArtifactController,
) ShareRouter {
	shareRouter := apiV1Router.Group.Group("/public/:assetID/refs/:assetVersionSlug/artifacts/:artifactName", middlewares.ShareMiddleware(orgRepository, projectRepository, assetRepository, assetVersionRepository, artifactRepository))
	shareRouter.GET("/vex.json/", artifactController.VEXJSON)
	shareRouter.GET("/sbom.json/", artifactController.SBOMJSON)
	shareRouter.GET("/badges/:badge/", assetController.GetBadges)

	return ShareRouter{
		Group: shareRouter,
	}
}
