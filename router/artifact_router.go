// Copyright (C) 2024 Tim Bastin, l3montree GmbH
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

package router

import (
	"github.com/l3montree-dev/devguard/controllers"
	"github.com/l3montree-dev/devguard/middlewares"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/labstack/echo/v4"
)

type ArtifactRouter struct {
	*echo.Group
}

func NewArtifactRouter(
	assetVersionGroup AssetVersionRouter,
	artifactController *controllers.ArtifactController,
	artifactRepository shared.ArtifactRepository,
) ArtifactRouter {
	artifactRouter := assetVersionGroup.Group.Group("/artifacts/:artifactName", middlewares.ArtifactMiddleware(artifactRepository))

	artifactRouter.GET("/sbom.json/", artifactController.SBOMJSON)
	artifactRouter.GET("/sbom.xml/", artifactController.SBOMXML)
	artifactRouter.GET("/vex.json/", artifactController.VEXJSON)
	artifactRouter.GET("/openvex.json/", artifactController.OpenVEXJSON)
	artifactRouter.GET("/vex.xml/", artifactController.VEXXML)
	artifactRouter.GET("/sbom.pdf/", artifactController.BuildPDFFromSBOM)
	artifactRouter.GET("/vulnerability-report.pdf/", artifactController.BuildVulnerabilityReportPDF)

	artifactRouter.DELETE("/", artifactController.DeleteArtifact, middlewares.NeededScope([]string{"manage"}))
	artifactRouter.PUT("/", artifactController.UpdateArtifact, middlewares.NeededScope([]string{"manage"}))

	return ArtifactRouter{Group: artifactRouter}
}
