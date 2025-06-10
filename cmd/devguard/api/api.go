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

package api

import (
	"log/slog"
	"os"
	"sort"
	"strings"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/l3montree-dev/devguard/internal/accesscontrol"
	"github.com/l3montree-dev/devguard/internal/auth"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/asset"
	"github.com/l3montree-dev/devguard/internal/core/assetversion"
	"github.com/l3montree-dev/devguard/internal/core/attestation"
	"github.com/l3montree-dev/devguard/internal/core/compliance"
	"github.com/l3montree-dev/devguard/internal/core/component"
	"github.com/l3montree-dev/devguard/internal/core/events"
	"github.com/l3montree-dev/devguard/internal/core/integrations"
	"github.com/l3montree-dev/devguard/internal/core/integrations/githubint"
	"github.com/l3montree-dev/devguard/internal/core/integrations/gitlabint"
	"github.com/l3montree-dev/devguard/internal/core/intoto"
	"github.com/l3montree-dev/devguard/internal/core/org"
	"github.com/l3montree-dev/devguard/internal/core/pat"
	"github.com/l3montree-dev/devguard/internal/core/project"
	"github.com/l3montree-dev/devguard/internal/core/statistics"
	"github.com/l3montree-dev/devguard/internal/core/vuln"
	"github.com/l3montree-dev/devguard/internal/core/vulndb"
	"github.com/l3montree-dev/devguard/internal/core/vulndb/scan"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
	"github.com/l3montree-dev/devguard/internal/echohttp"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/labstack/echo/v4"
)

func accessControlMiddleware(obj core.Object, act core.Action) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx echo.Context) error {
			// get the rbac
			rbac := core.GetRBAC(ctx)
			org := core.GetOrg(ctx)
			// get the user
			user := core.GetSession(ctx).GetUserID()

			allowed, err := rbac.IsAllowed(user, obj, act)
			if err != nil {
				ctx.Response().WriteHeader(500)
				return echo.NewHTTPError(500, "could not determine if the user has access")
			}

			// check if the user has the required role
			if !allowed {
				if org.IsPublic && act == core.ActionRead {
					core.SetIsPublicRequest(ctx)
				} else {
					ctx.Response().WriteHeader(403)
					return echo.NewHTTPError(403, "forbidden")
				}
			}

			return next(ctx)
		}
	}
}

func assetMiddleware(repository core.AssetRepository) func(next echo.HandlerFunc) echo.HandlerFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		// get the project
		return func(ctx echo.Context) error {

			project := core.GetProject(ctx)

			assetSlug, err := core.GetAssetSlug(ctx)
			if err != nil {
				return echo.NewHTTPError(400, "invalid asset slug")
			}

			asset, err := repository.ReadBySlug(project.GetID(), assetSlug)

			if err != nil {
				return echo.NewHTTPError(404, "could not find asset").WithInternal(err)
			}

			core.SetAsset(ctx, asset)

			return next(ctx)
		}
	}
}

func assetVersionMiddleware(repository core.AssetVersionRepository) func(next echo.HandlerFunc) echo.HandlerFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx echo.Context) error {

			asset := core.GetAsset(ctx)

			assetVersionSlug, err := core.GetAssetVersionSlug(ctx)
			if err != nil {
				return echo.NewHTTPError(400, "invalid asset version slug")
			}

			assetVersion, err := repository.ReadBySlug(asset.GetID(), assetVersionSlug)

			if err != nil {
				if assetVersionSlug == "default" {
					core.SetAssetVersion(ctx, models.AssetVersion{})

					return next(ctx)
				}
				return echo.NewHTTPError(404, "could not find asset version")
			}

			core.SetAssetVersion(ctx, assetVersion)

			return next(ctx)
		}
	}
}

func projectAccessControlFactory(projectRepository core.ProjectRepository) core.RBACMiddleware {
	return func(obj core.Object, act core.Action) core.MiddlewareFunc {
		return func(next echo.HandlerFunc) echo.HandlerFunc {
			return func(ctx core.Context) error {
				// get the rbac
				rbac := core.GetRBAC(ctx)

				// get the user
				user := core.GetSession(ctx).GetUserID()

				// get the project id
				projectSlug, err := core.GetProjectSlug(ctx)
				if err != nil {
					return echo.NewHTTPError(500, "could not get project id")
				}

				// get the project by slug and organization.
				project, err := projectRepository.ReadBySlug(core.GetOrg(ctx).GetID(), projectSlug)

				if err != nil {
					return echo.NewHTTPError(404, "could not get project")
				}

				allowed, err := rbac.IsAllowedInProject(&project, user, obj, act)

				if err != nil {
					return echo.NewHTTPError(500, "could not determine if the user has access")
				}

				// check if the user has the required role
				if !allowed {
					if project.IsPublic && act == core.ActionRead {
						// allow READ on all objects in the project - if access is public
						core.SetIsPublicRequest(ctx)
					} else {
						return echo.NewHTTPError(403, "forbidden")
					}
				}

				ctx.Set("project", project)

				return next(ctx)
			}
		}
	}
}

func projectAccessControl(projectService core.ProjectService, obj core.Object, act core.Action) core.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx core.Context) error {
			// get the rbac
			rbac := core.GetRBAC(ctx)

			// get the user
			user := core.GetSession(ctx).GetUserID()

			// get the project id
			projectSlug, err := core.GetProjectSlug(ctx)
			if err != nil {
				return echo.NewHTTPError(500, "could not get project id")
			}

			// get the project by slug and organization.
			project, err := projectService.ReadBySlug(ctx, core.GetOrg(ctx).GetID(), projectSlug)

			if err != nil {
				return echo.NewHTTPError(404, "could not get project")
			}

			allowed, err := rbac.IsAllowedInProject(&project, user, obj, act)

			if err != nil {
				return echo.NewHTTPError(500, "could not determine if the user has access")
			}

			// check if the user has the required role
			if !allowed {
				// check if public
				if project.IsPublic && act == core.ActionRead {
					core.SetIsPublicRequest(ctx)
				} else {
					return echo.NewHTTPError(403, "forbidden")
				}
			}

			ctx.Set("project", project)

			return next(ctx)
		}
	}
}

func neededScope(neededScopes []string) core.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c core.Context) error {
			userScopes := core.GetSession(c).GetScopes()

			ok := utils.ContainsAll(userScopes, neededScopes)
			if !ok {
				return echo.NewHTTPError(403, "your personal access token does not have the required scope, needed scopes: "+strings.Join(neededScopes, ", "))
			}

			return next(c)

		}
	}
}

// this middleware is used to set the project slug parameter based on an X-Asset-ID header.
// it is useful for reusing the projectAccessControl middleware and rely on the rbac to determine if the user has access to an specific asset
func assetNameMiddleware() core.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx core.Context) error {
			// extract the asset id from the header
			// asset name is <organization_slug>/<project_slug>/<asset_slug>
			assetName := ctx.Request().Header.Get("X-Asset-Name")
			if assetName == "" {
				return echo.NewHTTPError(400, "no X-Asset-Name header provided")
			}
			// split the asset name
			assetParts := strings.Split(assetName, "/")
			if len(assetParts) == 5 {
				// the user probably provided the full url
				// check if projects and assets is part of the asset parts - if so, remove them
				// <organization>/projects/<project>/assets/<asset>
				if assetParts[1] == "projects" && assetParts[3] == "assets" {
					assetParts = []string{assetParts[0], assetParts[2], assetParts[4]}
				}
			}
			if len(assetParts) != 3 {
				return echo.NewHTTPError(400, "invalid asset name")
			}
			// set the project slug
			ctx.Set("projectSlug", assetParts[1])
			ctx.Set("organization", assetParts[0])
			ctx.Set("assetSlug", assetParts[2])
			return next(ctx)
		}
	}
}

func multiOrganizationMiddleware(rbacProvider core.RBACProvider, organizationService core.OrgService) core.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx core.Context) (err error) {

			// get the organization from the provided context
			organization := core.GetParam(ctx, "organization")
			if organization == "" {
				// if no organization is provided, we can't continue
				slog.Error("no organization provided")
				return ctx.JSON(400, map[string]string{"error": "no organization"})
			}

			// get the organization
			org, err := organizationService.ReadBySlug(organization)
			if err != nil {
				return echo.NewHTTPError(404, "organization not found").WithInternal(err)
			}

			// check what kind of RBAC we need
			var domainRBAC core.AccessControl
			if org.IsExternalEntity() {
				domainRBAC = accesscontrol.NewExternalEntityProviderRBAC(ctx, core.GetThirdPartyIntegration(ctx), *org.ExternalEntityProviderID)
			} else {
				domainRBAC = rbacProvider.GetDomainRBAC(org.ID.String())
			}

			// check if the user is allowed to access the organization
			session := core.GetSession(ctx)
			allowed, err := domainRBAC.HasAccess(session.GetUserID())
			if err != nil {
				slog.Info("asking user to reauthorize", "err", err)
				return ctx.JSON(401, map[string]string{"error": err.Error()})
			}

			if !allowed {
				if org.IsPublic {
					core.SetIsPublicRequest(ctx)
				} else {
					// not allowed and not a public organization
					slog.Error("access denied")
					return ctx.JSON(403, map[string]string{"error": "access denied"})
				}
			}

			core.SetOrg(ctx, *org)
			core.SetRBAC(ctx, domainRBAC)
			core.SetOrgSlug(ctx, organization)
			// continue to the request
			return next(ctx)
		}
	}
}

// @Summary      Get user info
// @Description  Retrieves the user ID from the session
// @Tags         session
// @Produce      json
// @Success      200  {object} object{userId=string}
// @Failure      401  {object}  object{error=string}
// @Router       /whoami/ [get]
func whoami(ctx echo.Context) error {
	return ctx.JSON(200, map[string]string{
		"userId": core.GetSession(ctx).GetUserID(),
	})
}

// @Summary      Health Check
// @Description  Indicating the service is running
// @Tags         health
// @Produce      json
// @Success      200  {string}  string "ok"
// @Router       /health [get]
func health(ctx echo.Context) error {
	return ctx.String(200, "ok")
}

func BuildRouter(db core.DB) *echo.Echo {
	ory := auth.GetOryApiClient(os.Getenv("ORY_KRATOS_PUBLIC"))
	oryAdmin := auth.GetOryApiClient(os.Getenv("ORY_KRATOS_ADMIN"))
	casbinRBACProvider, err := accesscontrol.NewCasbinRBACProvider(db)
	if err != nil {
		panic(err)
	}

	githubIntegration := githubint.NewGithubIntegration(db)
	gitlabOauth2Integrations := gitlabint.NewGitLabOauth2Integrations(db)

	gitlabClientFactory := gitlabint.NewGitlabClientFactory(
		repositories.NewGitLabIntegrationRepository(db),
		gitlabOauth2Integrations,
	)

	gitlabIntegration := gitlabint.NewGitLabIntegration(db, gitlabOauth2Integrations, casbinRBACProvider, gitlabClientFactory)
	thirdPartyIntegration := integrations.NewThirdPartyIntegrations(gitlabIntegration, githubIntegration)

	// init all repositories using the provided database
	patRepository := repositories.NewPATRepository(db)
	assetRepository := repositories.NewAssetRepository(db)
	assetRiskAggregationRepository := repositories.NewAssetRiskHistoryRepository(db)
	assetVersionRepository := repositories.NewAssetVersionRepository(db)
	statisticsRepository := repositories.NewStatisticsRepository(db)
	projectRepository := repositories.NewProjectRepository(db)
	componentRepository := repositories.NewComponentRepository(db)
	vulnEventRepository := repositories.NewVulnEventRepository(db)
	projectScopedRBAC := projectAccessControlFactory(projectRepository)
	orgRepository := repositories.NewOrgRepository(db)
	cveRepository := repositories.NewCVERepository(db)
	dependencyVulnRepository := repositories.NewDependencyVulnRepository(db)
	firstPartyVulnRepository := repositories.NewFirstPartyVulnerabilityRepository(db)
	intotoLinkRepository := repositories.NewInTotoLinkRepository(db)
	supplyChainRepository := repositories.NewSupplyChainRepository(db)
	attestationRepository := repositories.NewAttestationRepository(db)
	policyRepository := repositories.NewPolicyRepository(db)
	licenseOverwriteRepository := repositories.NewLicenseOverwriteRepository(db)

	dependencyVulnService := vuln.NewService(dependencyVulnRepository, vulnEventRepository, assetRepository, cveRepository, orgRepository, projectRepository, thirdPartyIntegration, assetVersionRepository)
	firstPartyVulnService := vuln.NewFirstPartyVulnService(firstPartyVulnRepository, vulnEventRepository, assetRepository)
	projectService := project.NewService(projectRepository, assetRepository)
	dependencyVulnController := vuln.NewHttpController(dependencyVulnRepository, dependencyVulnService, projectService)

	vulnEventController := events.NewVulnEventController(vulnEventRepository, assetVersionRepository)

	assetService := asset.NewService(assetRepository, dependencyVulnRepository, dependencyVulnService)
	depsDevService := vulndb.NewDepsDevService()
	componentProjectRepository := repositories.NewComponentProjectRepository(db)
	componentService := component.NewComponentService(&depsDevService, componentProjectRepository, componentRepository)

	assetVersionService := assetversion.NewService(assetVersionRepository, componentRepository, dependencyVulnRepository, firstPartyVulnRepository, dependencyVulnService, firstPartyVulnService, assetRepository, vulnEventRepository, &componentService)
	statisticsService := statistics.NewService(statisticsRepository, componentRepository, assetRiskAggregationRepository, dependencyVulnRepository, assetVersionRepository, projectRepository, repositories.NewProjectRiskHistoryRepository(db))
	invitationRepository := repositories.NewInvitationRepository(db)

	intotoService := intoto.NewInTotoService(casbinRBACProvider, intotoLinkRepository, projectRepository, patRepository, supplyChainRepository)

	orgService := org.NewService(orgRepository, casbinRBACProvider)

	// init all http controllers using the repositories
	policyController := compliance.NewPolicyController(policyRepository, projectRepository)
	patController := pat.NewHttpController(patRepository)
	orgController := org.NewHttpController(orgRepository, orgService, casbinRBACProvider, projectService, invitationRepository)
	projectController := project.NewHttpController(projectRepository, assetRepository, projectService)
	assetController := asset.NewHttpController(assetRepository, assetVersionRepository, assetService, dependencyVulnService, statisticsService)

	scanController := scan.NewHttpController(db, cveRepository, componentRepository, assetRepository, assetVersionRepository, assetVersionService, statisticsService, dependencyVulnService)

	assetVersionController := assetversion.NewAssetVersionController(assetVersionRepository, assetVersionService, dependencyVulnRepository, componentRepository, dependencyVulnService, supplyChainRepository, licenseOverwriteRepository)
	attestationController := attestation.NewAttestationController(attestationRepository, assetVersionRepository)
	intotoController := intoto.NewHttpController(intotoLinkRepository, supplyChainRepository, patRepository, intotoService)
	componentController := component.NewHTTPController(componentRepository, assetVersionRepository, licenseOverwriteRepository)
	complianceController := compliance.NewHTTPController(assetVersionRepository, attestationRepository, policyRepository)

	statisticsController := statistics.NewHttpController(statisticsService, statisticsRepository, assetRepository, assetVersionRepository, projectService)
	firstPartyVulnController := vuln.NewFirstPartyVulnController(firstPartyVulnRepository, firstPartyVulnService, projectService)
	licenseOverwriteController := component.NewLicenseOverwriteController(licenseOverwriteRepository)

	patService := pat.NewPatService(patRepository)

	vulndbController := vulndb.NewHttpController(cveRepository)

	server := echohttp.Server()

	integrationController := integrations.NewIntegrationController(gitlabOauth2Integrations)

	apiV1Router := server.Group("/api/v1")

	// this makes the third party integrations available to all controllers
	apiV1Router.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx core.Context) error {
			core.SetThirdPartyIntegration(ctx, thirdPartyIntegration)
			return next(ctx)
		}
	})

	apiV1Router.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx core.Context) error {
			// set the ory admin client to the context
			core.SetAuthAdminClient(ctx, core.NewAdminClient(oryAdmin))
			return next(ctx)
		}
	})

	apiV1Router.GET("/metrics/", echo.WrapHandler(promhttp.Handler()))

	apiV1Router.POST("/webhook/", thirdPartyIntegration.HandleWebhook)

	// apply the health route without any session or multi organization middleware
	apiV1Router.GET("/health/", health)

	apiV1Router.GET("/badges/:badge/:badgeSecret/", assetController.GetBadges)

	apiV1Router.GET("/lookup/", assetController.HandleLookup)

	// everything below this line is protected by the session middleware
	sessionRouter := apiV1Router.Group("", auth.SessionMiddleware(ory, patService))
	sessionRouter.GET("/oauth2/gitlab/:integrationName/", integrationController.GitLabOauth2Login)
	sessionRouter.GET("/oauth2/gitlab/callback/:integrationName/", integrationController.GitLabOauth2Callback)

	// register a simple whoami route for testing purposes
	sessionRouter.GET("/whoami/", whoami)
	sessionRouter.POST("/accept-invitation/", orgController.AcceptInvitation, neededScope([]string{"manage"}))

	//TODO: change "/scan/" to "/sbom-scan/"
	sessionRouter.POST("/scan/", scanController.ScanDependencyVulnFromProject, neededScope([]string{"scan"}), assetNameMiddleware(), multiOrganizationMiddleware(casbinRBACProvider, orgService), projectScopedRBAC(core.ObjectAsset, core.ActionUpdate), assetMiddleware(assetRepository))

	sessionRouter.POST("/sarif-scan/", scanController.FirstPartyVulnScan, neededScope([]string{"scan"}), assetNameMiddleware(), multiOrganizationMiddleware(casbinRBACProvider, orgService), projectScopedRBAC(core.ObjectAsset, core.ActionUpdate), assetMiddleware(assetRepository))

	sessionRouter.POST("/attestations/", attestationController.Create, neededScope([]string{"scan"}), assetNameMiddleware(), multiOrganizationMiddleware(casbinRBACProvider, orgService), projectScopedRBAC(core.ObjectAsset, core.ActionUpdate), assetMiddleware(assetRepository))

	sessionRouter.GET("/integrations/repositories/", integrationController.ListRepositories)

	patRouter := sessionRouter.Group("/pats")
	patRouter.POST("/", patController.Create, neededScope([]string{"manage"}))
	patRouter.GET("/", patController.List)
	patRouter.DELETE("/:tokenId/", patController.Delete, neededScope([]string{"manage"}))
	patRouter.POST("/revoke-by-private-key/", patController.RevokeByPrivateKey, neededScope([]string{"manage"}))

	cveRouter := apiV1Router.Group("/vulndb")
	cveRouter.GET("/", vulndbController.ListPaged)
	cveRouter.GET("/:cveId/", vulndbController.Read)

	orgRouter := sessionRouter.Group("/organizations")

	orgRouter.POST("/", orgController.Create, neededScope([]string{"manage"}))
	orgRouter.GET("/", orgController.List)

	//Api functions for interacting with an organization  ->  .../organizations/<organization-name>/...
	organizationRouter := orgRouter.Group("/:organization", multiOrganizationMiddleware(casbinRBACProvider, orgService))
	organizationRouter.DELETE("/", orgController.Delete, neededScope([]string{"manage"}), accessControlMiddleware(core.ObjectOrganization, core.ActionDelete))
	organizationRouter.GET("/", orgController.Read, accessControlMiddleware(core.ObjectOrganization, core.ActionRead))

	organizationRouter.PATCH("/", orgController.Update, neededScope([]string{"manage"}), accessControlMiddleware(core.ObjectOrganization, core.ActionUpdate))

	organizationRouter.GET("/metrics/", orgController.Metrics)
	organizationRouter.GET("/content-tree/", orgController.ContentTree)
	//TODO: change it
	//organizationRouter.GET("/dependency-vulns/", dependencyVulnController.ListByOrgPaged)
	organizationRouter.GET("/dependency-vulns/", dependencyVulnController.ListByOrgPaged)
	organizationRouter.GET("/first-party-vulns/", firstPartyVulnController.ListByOrgPaged)

	organizationRouter.GET("/policies/", policyController.GetOrganizationPolicies)
	organizationRouter.GET("/policies/:policyId/", policyController.GetPolicy)
	organizationRouter.PUT("/policies/:policyId/", policyController.UpdatePolicy, neededScope([]string{"manage"}), accessControlMiddleware(core.ObjectOrganization, core.ActionUpdate))
	organizationRouter.POST("/policies/", policyController.CreatePolicy, neededScope([]string{"manage"}), accessControlMiddleware(core.ObjectOrganization, core.ActionUpdate))
	organizationRouter.DELETE("/policies/:policyId/", policyController.DeletePolicy, neededScope([]string{"manage"}), accessControlMiddleware(core.ObjectOrganization, core.ActionDelete))

	organizationRouter.GET("/members/", orgController.Members)
	organizationRouter.POST("/members/", orgController.InviteMember, neededScope([]string{"manage"}), accessControlMiddleware(core.ObjectOrganization, core.ActionUpdate))

	organizationRouter.DELETE("/members/:userId/", orgController.RemoveMember, neededScope([]string{"manage"}), accessControlMiddleware(core.ObjectOrganization, core.ActionDelete))

	organizationRouter.PUT("/members/:userId/", orgController.ChangeRole, neededScope([]string{"manage"}), accessControlMiddleware(core.ObjectOrganization, core.ActionUpdate))

	organizationRouter.GET("/integrations/finish-installation/", integrationController.FinishInstallation)

	organizationRouter.POST("/integrations/gitlab/test-and-save/", integrationController.TestAndSaveGitlabIntegration, neededScope([]string{"manage"}))
	organizationRouter.DELETE("/integrations/gitlab/:gitlab_integration_id/", integrationController.DeleteGitLabAccessToken, neededScope([]string{"manage"}))
	organizationRouter.GET("/integrations/repositories/", integrationController.ListRepositories)
	organizationRouter.GET("/stats/risk-history/", statisticsController.GetOrgRiskHistory)
	organizationRouter.GET("/stats/average-fixing-time/", statisticsController.GetAverageOrgFixingTime)
	//TODO: change it
	//organizationRouter.GET("/stats/dependency-vuln-aggregation-state-and-change/", statisticsController.GetOrgDependencyVulnAggregationStateAndChange)
	organizationRouter.GET("/stats/vuln-aggregation-state-and-change/", statisticsController.GetOrgDependencyVulnAggregationStateAndChange)
	organizationRouter.GET("/stats/risk-distribution/", statisticsController.GetOrgRiskDistribution)

	organizationRouter.GET("/projects/", projectController.List, accessControlMiddleware(core.ObjectOrganization, core.ActionRead))
	organizationRouter.POST("/projects/", projectController.Create, neededScope([]string{"manage"}), accessControlMiddleware(core.ObjectOrganization, core.ActionUpdate))

	organizationRouter.GET("/config-files/:config-file/", orgController.GetConfigFile)
	organizationRouter.PUT("/license-overwrite/", licenseOverwriteController.Create, neededScope([]string{"manage"}))
	organizationRouter.DELETE("/license-overwrite/:componentPurl", licenseOverwriteController.Delete, neededScope([]string{"manage"}))
	//Api functions for interacting with a project inside an organization  ->  .../organizations/<organization-name>/projects/<project-name>/...
	projectRouter := organizationRouter.Group("/projects/:projectSlug", projectAccessControl(projectService, "project", core.ActionRead))
	projectRouter.GET("/", projectController.Read)

	projectRouter.PUT("/policies/:policyId/", policyController.EnablePolicyForProject, neededScope([]string{"manage"}), projectScopedRBAC(core.ObjectProject, core.ActionUpdate))
	projectRouter.DELETE("/policies/:policyId/", policyController.DisablePolicyForProject, neededScope([]string{"manage"}), projectScopedRBAC(core.ObjectProject, core.ActionDelete))

	//TODO: change it
	//projectRouter.GET("/dependency-vulns/", dependencyVulnController.ListByProjectPaged)
	projectRouter.GET("/dependency-vulns/", dependencyVulnController.ListByProjectPaged)

	projectRouter.PATCH("/", projectController.Update, neededScope([]string{"manage"}), projectScopedRBAC(core.ObjectProject, core.ActionUpdate))
	projectRouter.DELETE("/", projectController.Delete, neededScope([]string{"manage"}), projectScopedRBAC(core.ObjectProject, core.ActionDelete))

	projectRouter.POST("/assets/", assetController.Create, neededScope([]string{"manage"}), projectScopedRBAC(core.ObjectAsset, core.ActionCreate))

	projectRouter.GET("/assets/", assetController.List)

	projectRouter.GET("/stats/risk-distribution/", statisticsController.GetProjectRiskDistribution)
	projectRouter.GET("/stats/risk-history/", statisticsController.GetProjectRiskHistory)
	projectRouter.GET("/compliance/", complianceController.ProjectCompliance)
	projectRouter.GET("/policies/", policyController.GetProjectPolicies)

	//projectRouter.GET("/stats/dependency-vuln-aggregation-state-and-change/", statisticsController.GetProjectDependencyVulnAggregationStateAndChange)
	projectRouter.GET("/stats/vuln-aggregation-state-and-change/", statisticsController.GetProjectDependencyVulnAggregationStateAndChange)
	projectRouter.GET("/stats/average-fixing-time/", statisticsController.GetAverageProjectFixingTime)

	projectRouter.GET("/members/", projectController.Members)
	projectRouter.POST("/members/", projectController.InviteMembers, neededScope([]string{"manage"}), projectScopedRBAC(core.ObjectProject, core.ActionUpdate))
	projectRouter.DELETE("/members/:userId/", projectController.RemoveMember, neededScope([]string{"manage"}), projectScopedRBAC(core.ObjectProject, core.ActionDelete))

	projectRouter.GET("/config-files/:config-file/", projectController.GetConfigFile)

	projectRouter.PUT("/members/:userId/", projectController.ChangeRole, neededScope([]string{"manage"}), projectScopedRBAC(core.ObjectProject, core.ActionUpdate))

	//Api functions for interacting with an asset inside a project  ->  .../projects/<project-name>/assets/<asset-name>/...
	assetRouter := projectRouter.Group("/assets/:assetSlug", projectScopedRBAC(core.ObjectAsset, core.ActionRead), assetMiddleware(assetRepository))
	assetRouter.GET("/", assetController.Read)
	assetRouter.DELETE("/", assetController.Delete, neededScope([]string{"manage"}), projectScopedRBAC(core.ObjectAsset, core.ActionDelete))

	assetRouter.GET("/secrets/", assetController.GetSecrets, neededScope([]string{"manage"}), projectScopedRBAC(core.ObjectAsset, core.ActionUpdate))
	assetRouter.GET("/compliance/", complianceController.AssetCompliance)
	assetRouter.GET("/compliance/:policy/", complianceController.Details)
	assetRouter.GET("/stats/risk-distribution/", statisticsController.GetAssetVersionRiskDistribution)
	assetRouter.GET("/stats/cvss-distribution/", statisticsController.GetAssetVersionCvssDistribution)
	assetRouter.GET("/number-of-exploits/", statisticsController.GetCVESWithKnownExploits)
	assetRouter.GET("/components/licenses/", componentController.LicenseDistribution)
	assetRouter.GET("/config-files/:config-file/", assetController.GetConfigFile)

	assetRouter.GET("/refs/", assetVersionController.GetAssetVersionsByAssetID)

	//Api to scan manually using an uploaded SBOM provided by the user
	assetRouter.POST("/sbom-file/", scanController.ScanSbomFile, neededScope([]string{"scan"}))

	//TODO: add the projectScopedRBAC middleware to the following routes
	assetVersionRouter := assetRouter.Group("/refs/:assetVersionSlug", assetVersionMiddleware(assetVersionRepository))

	assetVersionRouter.GET("/", assetVersionController.Read)

	assetVersionRouter.GET("/compliance/", complianceController.AssetCompliance)
	assetVersionRouter.GET("/compliance/:policy/", complianceController.Details)
	assetVersionRouter.DELETE("/", assetVersionController.Delete, neededScope([]string{"manage"})) //Delete an asset version

	assetVersionRouter.GET("/metrics/", assetVersionController.Metrics)
	assetVersionRouter.GET("/dependency-graph/", assetVersionController.DependencyGraph)
	assetVersionRouter.GET("/path-to-component/", assetVersionController.GetDependencyPathFromPURL)
	assetVersionRouter.GET("/affected-components/", assetVersionController.AffectedComponents)
	assetVersionRouter.GET("/sbom.json/", assetVersionController.SBOMJSON)
	assetVersionRouter.GET("/sbom.xml/", assetVersionController.SBOMXML)
	assetVersionRouter.GET("/vex.json/", assetVersionController.VEXJSON)
	assetVersionRouter.GET("/openvex.json/", assetVersionController.OpenVEXJSON)
	assetVersionRouter.GET("/vex.xml/", assetVersionController.VEXXML)

	assetVersionRouter.GET("/stats/component-risk/", statisticsController.GetComponentRisk)
	assetVersionRouter.GET("/stats/risk-distribution/", statisticsController.GetAssetVersionRiskDistribution)
	assetVersionRouter.GET("/stats/cvss-distribution/", statisticsController.GetAssetVersionCvssDistribution)

	assetVersionRouter.GET("/stats/risk-history/", statisticsController.GetAssetVersionRiskHistory)
	//TODO: change it
	//assetVersionRouter.GET("/stats/dependency-vuln-count-by-scanner/", statisticsController.GetDependencyVulnCountByScannerId)
	assetVersionRouter.GET("/stats/vuln-count-by-scanner/", statisticsController.GetDependencyVulnCountByScannerId)
	assetVersionRouter.GET("/stats/dependency-count-by-scan-type/", statisticsController.GetDependencyCountPerScanner)

	//TODO: change it
	//assetVersionRouter.GET("/stats/dependency-vuln-aggregation-state-and-change/", statisticsController.GetDependencyVulnAggregationStateAndChange)
	assetVersionRouter.GET("/stats/vuln-aggregation-state-and-change/", statisticsController.GetDependencyVulnAggregationStateAndChange)
	assetVersionRouter.GET("/stats/average-fixing-time/", statisticsController.GetAverageAssetVersionFixingTime)

	assetRouter.POST("/integrations/gitlab/autosetup/", integrationController.AutoSetup, neededScope([]string{"manage"}), projectScopedRBAC(core.ObjectAsset, core.ActionUpdate))
	assetRouter.PATCH("/", assetController.Update, neededScope([]string{"manage"}), projectScopedRBAC(core.ObjectAsset, core.ActionUpdate))

	assetVersionRouter.GET("/attestations/", attestationController.List)

	assetRouter.POST("/integrations/gitlab/autosetup/", integrationController.AutoSetup, neededScope([]string{"manage"}), projectScopedRBAC(core.ObjectAsset, core.ActionUpdate))

	assetRouter.PATCH("/", assetController.Update, neededScope([]string{"manage"}), projectScopedRBAC(core.ObjectAsset, core.ActionUpdate))
	assetRouter.POST("/signing-key/", assetController.AttachSigningKey, neededScope([]string{"scan"}), projectScopedRBAC(core.ObjectAsset, core.ActionUpdate))

	assetRouter.POST("/in-toto/", intotoController.Create, neededScope([]string{"scan"}), projectScopedRBAC(core.ObjectAsset, core.ActionUpdate))

	assetRouter.GET("/in-toto/root.layout.json/", intotoController.RootLayout)

	assetVersionRouter.GET("/in-toto/:supplyChainId/", intotoController.Read)

	apiV1Router.GET("/verify-supply-chain/", intotoController.VerifySupplyChain)

	assetVersionRouter.GET("/components/", componentController.ListPaged)
	assetVersionRouter.GET("/components/licenses/", componentController.LicenseDistribution)

	assetVersionRouter.GET("/events/", vulnEventController.ReadEventsByAssetIDAndAssetVersionName)

	dependencyVulnRouter := assetVersionRouter.Group("/dependency-vulns")
	dependencyVulnRouter.GET("/", dependencyVulnController.ListPaged)
	dependencyVulnRouter.GET("/:dependencyVulnId/", dependencyVulnController.Read)

	dependencyVulnRouter.POST("/:dependencyVulnId/", dependencyVulnController.CreateEvent, neededScope([]string{"manage"}), projectScopedRBAC(core.ObjectAsset, core.ActionUpdate))
	dependencyVulnRouter.POST("/:dependencyVulnId/mitigate/", dependencyVulnController.Mitigate, neededScope([]string{"manage"}), projectScopedRBAC(core.ObjectAsset, core.ActionUpdate))

	dependencyVulnRouter.GET("/:dependencyVulnId/events/", vulnEventController.ReadAssetEventsByVulnID)

	firstPartyVulnRouter := assetVersionRouter.Group("/first-party-vulns")
	firstPartyVulnRouter.GET("/", firstPartyVulnController.ListPaged)
	firstPartyVulnRouter.GET("/:firstPartyVulnId/", firstPartyVulnController.Read)
	firstPartyVulnRouter.POST("/:firstPartyVulnId/", firstPartyVulnController.CreateEvent, neededScope([]string{"manage"}), projectScopedRBAC(core.ObjectAsset, core.ActionUpdate))
	firstPartyVulnRouter.POST("/:firstPartyVulnId/mitigate/", firstPartyVulnController.Mitigate, neededScope([]string{"manage"}), projectScopedRBAC(core.ObjectAsset, core.ActionUpdate))
	firstPartyVulnRouter.GET("/:firstPartyVulnId/events/", vulnEventController.ReadAssetEventsByVulnID)

	routes := server.Routes()
	sort.Slice(routes, func(i, j int) bool {
		return routes[i].Path < routes[j].Path
	})
	// print all registered routes
	for _, route := range routes {
		if route.Method != "echo_route_not_found" {
			slog.Info(route.Path, "method", route.Method)
		}
	}
	return server
}

func Start(db core.DB) {
	slog.Error("failed to start server", "err", BuildRouter(db).Start(":8080").Error())
}
