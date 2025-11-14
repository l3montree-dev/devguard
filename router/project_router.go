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

type ProjectRouter struct {
	*echo.Group
}

func NewProjectRouter(
	organizationGroup OrgRouter,
	projectController *controllers.ProjectController,
	assetController *controllers.AssetController,
	dependencyVulnController *controllers.DependencyVulnController,
	policyController *controllers.PolicyController,
	releaseController *controllers.ReleaseController,
	statisticsController *controllers.StatisticsController,
	webhookIntegration *controllers.WebhookIntegration,
	projectRepository shared.ProjectRepository,
) ProjectRouter {
	/**
	Project scoped router
	All routes below this line are scoped to a specific project.
	*/
	projectScopedRBAC := middlewares.ProjectAccessControlFactory(projectRepository)

	projectRouter := organizationGroup.Group.Group("/projects/:projectSlug", projectScopedRBAC(shared.ObjectProject, shared.ActionRead))
	projectRouter.GET("/", projectController.Read)
	projectRouter.GET("/policies/", policyController.GetProjectPolicies)
	projectRouter.GET("/dependency-vulns/", dependencyVulnController.ListByProjectPaged)
	projectRouter.GET("/assets/", assetController.List)
	projectRouter.GET("/members/", projectController.Members)
	projectRouter.GET("/config-files/:config-file/", projectController.GetConfigFile)
	projectRouter.GET("/releases/:releaseID/sbom.json/", releaseController.SBOMJSON)
	projectRouter.GET("/releases/:releaseID/sbom.xml/", releaseController.SBOMXML)
	projectRouter.GET("/releases/:releaseID/vex.json/", releaseController.VEXJSON)
	projectRouter.GET("/releases/:releaseID/vex.xml/", releaseController.VEXXML)
	projectRouter.GET("/releases/:releaseID/stats/risk-history/", statisticsController.GetReleaseRiskHistory)
	projectRouter.GET("/releases/:releaseID/stats/average-fixing-time/", statisticsController.GetAverageReleaseFixingTime)
	projectRouter.GET("/releases/:releaseID/candidates/", releaseController.ListCandidates)
	projectRouter.GET("/releases/candidates/", releaseController.ListCandidates)
	projectRouter.GET("/releases/:releaseID/", releaseController.Read)
	projectRouter.GET("/releases/", releaseController.List)

	projectRouter.POST("/assets/", assetController.Create, middlewares.NeededScope([]string{"manage"}), projectScopedRBAC(shared.ObjectAsset, shared.ActionCreate))

	projectUpdateAccessControlRequired := projectRouter.Group("", middlewares.NeededScope([]string{"manage"}), projectScopedRBAC(shared.ObjectProject, shared.ActionUpdate))

	projectUpdateAccessControlRequired.POST("/integrations/webhook/test-and-save/", webhookIntegration.Save)
	projectUpdateAccessControlRequired.POST("/integrations/webhook/test/", webhookIntegration.Test)
	projectUpdateAccessControlRequired.POST("/members/", projectController.InviteMembers)
	projectUpdateAccessControlRequired.POST("/releases/", releaseController.Create)
	projectUpdateAccessControlRequired.POST("/releases/:releaseID/items/", releaseController.AddItem)

	projectUpdateAccessControlRequired.DELETE("/integrations/webhook/:id/", webhookIntegration.Delete)
	projectUpdateAccessControlRequired.DELETE("/policies/:policyID/", policyController.DisablePolicyForProject)
	projectUpdateAccessControlRequired.DELETE("/", projectController.Delete)
	projectUpdateAccessControlRequired.DELETE("/members/:userID/", projectController.RemoveMember)
	projectUpdateAccessControlRequired.DELETE("/releases/:releaseID/", releaseController.Delete)
	projectUpdateAccessControlRequired.DELETE("/releases/:releaseID/items/:itemID/", releaseController.RemoveItem)

	projectUpdateAccessControlRequired.PUT("/integrations/webhook/:id/", webhookIntegration.Update)
	projectUpdateAccessControlRequired.PUT("/policies/:policyID/", policyController.EnablePolicyForProject)
	projectUpdateAccessControlRequired.PATCH("/", projectController.Update)
	projectUpdateAccessControlRequired.PUT("/members/:userID/", projectController.ChangeRole)
	projectUpdateAccessControlRequired.PATCH("/releases/:releaseID/", releaseController.Update)

	return ProjectRouter{Group: projectRouter}
}
