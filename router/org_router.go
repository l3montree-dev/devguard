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
	"github.com/l3montree-dev/devguard/integrations/gitlabint"
	"github.com/l3montree-dev/devguard/middlewares"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/labstack/echo/v4"
)

type OrgRouter struct {
	*echo.Group
}

func NewOrgRouter(
	sessionGroup SessionRouter,
	orgController *controllers.OrgController,
	projectController *controllers.ProjectController,
	dependencyVulnController *controllers.DependencyVulnController,
	firstPartyVulnController *controllers.FirstPartyVulnController,
	policyController *controllers.PolicyController,
	integrationController *controllers.IntegrationController,
	webhookIntegration *controllers.WebhookController,
	externalEntityProviderService shared.ExternalEntityProviderService,
	orgService shared.OrgService,
	gitlabOauth2Integrations map[string]*gitlabint.GitlabOauth2Config,
	casbinRBACProvider shared.RBACProvider,
	statisticsController *controllers.StatisticsController,
) OrgRouter {
	/**
	Organization router
	*/
	orgRouter := sessionGroup.Group.Group("/organizations")
	orgRouter.GET("/", orgController.List)
	orgRouter.POST("/", orgController.Create, middlewares.NeededScope([]string{"manage"}))

	/**
	Organization scoped router
	All routes below this line are scoped to a specific organization.
	*/
	organizationRouter := orgRouter.Group("/:organization",
		middlewares.MultiOrganizationMiddlewareRBAC(casbinRBACProvider, orgService, gitlabOauth2Integrations),
		middlewares.OrganizationAccessControlMiddleware(shared.ObjectOrganization, shared.ActionRead),
		middlewares.ExternalEntityProviderRefreshMiddleware(externalEntityProviderService))

	organizationRouter.DELETE("/", orgController.Delete, middlewares.NeededScope([]string{"manage"}), middlewares.OrganizationAccessControlMiddleware(shared.ObjectOrganization, shared.ActionDelete))

	// overview page endpoints
	organizationRouter.GET("/stats/vuln-statistics/", statisticsController.GetOrgStatistics)

	organizationRouter.GET("/config-files/:config-file/", orgController.GetConfigFile)
	organizationRouter.GET("/trigger-sync/", externalEntityProviderService.TriggerSync)
	organizationRouter.GET("/", orgController.Read)
	organizationRouter.GET("/metrics/", orgController.Metrics)
	organizationRouter.GET("/content-tree/", orgController.ContentTree)
	organizationRouter.GET("/dependency-vulns/", dependencyVulnController.ListByOrgPaged)
	organizationRouter.GET("/first-party-vulns/", firstPartyVulnController.ListByOrgPaged)
	organizationRouter.GET("/policies/", policyController.GetOrganizationPolicies)
	organizationRouter.GET("/policies/:policyID/", policyController.GetPolicy)
	organizationRouter.GET("/members/", orgController.Members)
	organizationRouter.GET("/integrations/finish-installation/", integrationController.FinishInstallation)
	organizationRouter.GET("/projects/", projectController.List)
	organizationRouter.GET("/integrations/repositories/", integrationController.ListRepositories)

	organizationUpdateAccessControlRequired := organizationRouter.Group("", middlewares.NeededScope([]string{"manage"}), middlewares.OrganizationAccessControlMiddleware(shared.ObjectOrganization, shared.ActionUpdate))

	organizationUpdateAccessControlRequired.POST("/members/", orgController.InviteMember)
	organizationUpdateAccessControlRequired.POST("/integrations/jira/test-and-save/", integrationController.TestAndSaveJiraIntegration)
	organizationUpdateAccessControlRequired.POST("/integrations/webhook/test-and-save/", webhookIntegration.Save)
	organizationUpdateAccessControlRequired.POST("/integrations/webhook/test/", webhookIntegration.Test)
	organizationUpdateAccessControlRequired.POST("/policies/", policyController.CreatePolicy)
	organizationUpdateAccessControlRequired.POST("/integrations/gitlab/test-and-save/", integrationController.TestAndSaveGitlabIntegration)
	organizationUpdateAccessControlRequired.POST("/projects/", projectController.Create)

	organizationUpdateAccessControlRequired.DELETE("/policies/:policyID/", policyController.DeletePolicy)
	organizationUpdateAccessControlRequired.DELETE("/integrations/gitlab/:gitlab_integration_id/", integrationController.DeleteGitLabAccessToken)
	organizationUpdateAccessControlRequired.DELETE("/members/:userID/", orgController.RemoveMember)
	organizationUpdateAccessControlRequired.DELETE("/integrations/jira/:jira_integration_id/", integrationController.DeleteJiraAccessToken)
	organizationUpdateAccessControlRequired.DELETE("/integrations/webhook/:id/", webhookIntegration.Delete)

	organizationUpdateAccessControlRequired.PATCH("/", orgController.Update)
	organizationUpdateAccessControlRequired.PUT("/policies/:policyID/", policyController.UpdatePolicy)
	organizationUpdateAccessControlRequired.PUT("/members/:userID/", orgController.ChangeRole)
	organizationUpdateAccessControlRequired.PUT("/integrations/webhook/:id/", webhookIntegration.Update)

	return OrgRouter{Group: organizationRouter}
}
