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

type AssetVersionRouter struct {
	*echo.Group
}

func NewAssetVersionRouter(
	assetGroup AssetRouter,
	assetVersionController *controllers.AssetVersionController,
	firstPartyVulnController *controllers.FirstPartyVulnController,
	complianceController *controllers.ComplianceController,
	componentController *controllers.ComponentController,
	statisticsController *controllers.StatisticsController,
	attestationController *controllers.AttestationController,
	intotoController *controllers.InToToController,
	vulnEventController *controllers.VulnEventController,
	artifactController *controllers.ArtifactController,
	externalReferenceController *controllers.ExternalReferenceController,
	assetVersionRepository shared.AssetVersionRepository,
	assetRepository shared.AssetRepository,
	vulnEventRepository shared.VulnEventRepository,
) AssetVersionRouter {
	assetScopedRBAC := middlewares.AssetAccessControlFactory(assetRepository)

	assetVersionRouter := assetGroup.Group.Group("/refs/:assetVersionSlug", middlewares.AssetVersionMiddleware(assetVersionRepository))

	assetVersionRouter.GET("/sarif.json/", firstPartyVulnController.Sarif)
	assetVersionRouter.GET("/", assetVersionController.Read)
	assetVersionRouter.GET("/compliance/", complianceController.AssetCompliance)
	assetVersionRouter.GET("/compliance/:policy/", complianceController.Details)
	assetVersionRouter.GET("/metrics/", assetVersionController.Metrics)
	assetVersionRouter.GET("/components/licenses/", componentController.LicenseDistribution)
	assetVersionRouter.GET("/vulnerability-report.pdf/", assetVersionController.BuildVulnerabilityReportPDF)
	assetVersionRouter.GET("/affected-components/", assetVersionController.AffectedComponents)
	assetVersionRouter.GET("/dependency-graph/", assetVersionController.DependencyGraph)
	assetVersionRouter.GET("/path-to-component/", assetVersionController.GetDependencyPathFromPURL)
	assetVersionRouter.GET("/stats/average-fixing-time/", statisticsController.GetAverageFixingTime)
	assetVersionRouter.GET("/stats/risk-history/", statisticsController.GetArtifactRiskHistory)
	assetVersionRouter.GET("/stats/component-risk/", statisticsController.GetComponentRisk)
	assetVersionRouter.GET("/sbom.json/", assetVersionController.SBOMJSON)
	assetVersionRouter.GET("/sbom.xml/", assetVersionController.SBOMXML)
	assetVersionRouter.GET("/vex.json/", assetVersionController.VEXJSON)
	assetVersionRouter.GET("/openvex.json/", assetVersionController.OpenVEXJSON)
	assetVersionRouter.GET("/vex.xml/", assetVersionController.VEXXML)
	assetVersionRouter.GET("/sbom.pdf/", assetVersionController.BuildPDFFromSBOM)
	assetVersionRouter.GET("/attestations/", attestationController.List)
	assetVersionRouter.GET("/in-toto/:supplyChainID/", intotoController.Read)
	assetVersionRouter.GET("/components/", componentController.ListPaged)
	assetVersionRouter.GET("/events/", vulnEventController.ReadEventsByAssetIDAndAssetVersionName)
	assetVersionRouter.GET("/artifacts/", assetVersionController.ListArtifacts)
	assetVersionRouter.GET("/artifact-root-nodes/", assetVersionController.ReadRootNodes)

	assetVersionRouter.POST("/artifacts/", artifactController.Create, middlewares.NeededScope([]string{"manage"}))

	assetVersionRouter.POST("/components/licenses/refresh/", assetVersionController.RefetchLicenses, middlewares.NeededScope([]string{"manage"}))
	assetVersionRouter.DELETE("/", assetVersionController.Delete, middlewares.NeededScope([]string{"manage"}), assetScopedRBAC(shared.ObjectAsset, shared.ActionUpdate))
	assetVersionRouter.POST("/make-default/", assetVersionController.MakeDefault, middlewares.NeededScope([]string{"manage"}), assetScopedRBAC(shared.ObjectAsset, shared.ActionUpdate))
	assetVersionRouter.DELETE("/events/:eventID/", vulnEventController.DeleteEventByID, middlewares.EventMiddleware(vulnEventRepository), middlewares.NeededScope([]string{"manage"}), assetScopedRBAC(shared.ObjectAsset, shared.ActionUpdate))

	return AssetVersionRouter{Group: assetVersionRouter}
}
