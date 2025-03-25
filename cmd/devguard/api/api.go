// Copyright (C) 2024 Tim Bastin, l3montree UG (haftungsbeschränkt)
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

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/accesscontrol"

	"github.com/l3montree-dev/devguard/internal/auth"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/asset"
	"github.com/l3montree-dev/devguard/internal/core/assetversion"
	"github.com/l3montree-dev/devguard/internal/core/dependency_vuln"
	"github.com/l3montree-dev/devguard/internal/core/events"
	"github.com/l3montree-dev/devguard/internal/core/integrations"
	"github.com/l3montree-dev/devguard/internal/core/intoto"
	"github.com/l3montree-dev/devguard/internal/core/org"
	"github.com/l3montree-dev/devguard/internal/core/pat"
	"github.com/l3montree-dev/devguard/internal/core/project"
	"github.com/l3montree-dev/devguard/internal/core/statistics"
	"github.com/l3montree-dev/devguard/internal/core/vulndb"
	"github.com/l3montree-dev/devguard/internal/core/vulndb/scan"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
	"github.com/l3montree-dev/devguard/internal/echohttp"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/labstack/echo/v4"
)

type assetRepository interface {
	ReadBySlug(projectID uuid.UUID, slug string) (models.Asset, error)
}

type assetVersionRepository interface {
	ReadBySlug(assetID uuid.UUID, slug string) (models.AssetVersion, error)
}

type orgRepository interface {
	ReadBySlug(slugOrId string) (models.Org, error)
}

type projectRepository interface {
	ReadBySlug(organizationID uuid.UUID, slug string) (models.Project, error)
}

func accessControlMiddleware(obj accesscontrol.Object, act accesscontrol.Action) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// get the rbac
			rbac := core.GetRBAC(c)
			org := core.GetTenant(c)
			// get the user
			user := core.GetSession(c).GetUserID()

			allowed, err := rbac.IsAllowed(user, string(obj), act)
			if err != nil {
				c.Response().WriteHeader(500)
				return echo.NewHTTPError(500, "could not determine if the user has access")
			}

			// check if the user has the required role
			if !allowed {
				if org.IsPublic && act == accesscontrol.ActionRead {
					core.SetIsPublicRequest(c)
				} else {
					c.Response().WriteHeader(403)
					return echo.NewHTTPError(403, "forbidden")
				}
			}

			return next(c)
		}
	}
}

func assetMiddleware(repository assetRepository) func(next echo.HandlerFunc) echo.HandlerFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		// get the project
		return func(c echo.Context) error {

			project := core.GetProject(c)

			assetSlug, err := core.GetAssetSlug(c)
			if err != nil {
				return echo.NewHTTPError(400, "invalid asset slug")
			}

			asset, err := repository.ReadBySlug(project.GetID(), assetSlug)

			if err != nil {
				return echo.NewHTTPError(404, "could not find asset").WithInternal(err)
			}

			core.SetAsset(c, asset)

			return next(c)
		}
	}
}

func assetVersionMiddleware(repository assetVersionRepository) func(next echo.HandlerFunc) echo.HandlerFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {

			asset := core.GetAsset(c)

			assetVersionSlug, err := core.GetAssetVersionSlug(c)
			if err != nil {
				return echo.NewHTTPError(400, "invalid asset version slug")
			}

			assetVersion, err := repository.ReadBySlug(asset.GetID(), assetVersionSlug)

			if err != nil {
				if assetVersionSlug == "default" {
					core.SetAssetVersion(c, models.AssetVersion{})

					return next(c)
				}
				return echo.NewHTTPError(404, "could not find asset version")
			}

			core.SetAssetVersion(c, assetVersion)

			return next(c)
		}
	}
}

func projectAccessControlFactory(projectRepository projectRepository) accesscontrol.RBACMiddleware {
	return func(obj accesscontrol.Object, act accesscontrol.Action) core.MiddlewareFunc {
		return func(next echo.HandlerFunc) echo.HandlerFunc {
			return func(c core.Context) error {
				// get the rbac
				rbac := core.GetRBAC(c)

				// get the user
				user := core.GetSession(c).GetUserID()

				// get the project id
				projectSlug, err := core.GetProjectSlug(c)
				if err != nil {
					return echo.NewHTTPError(500, "could not get project id")
				}

				// get the project by slug and tenant.
				project, err := projectRepository.ReadBySlug(core.GetTenant(c).GetID(), projectSlug)

				if err != nil {
					return echo.NewHTTPError(404, "could not get project")
				}

				allowed, err := rbac.IsAllowedInProject(project.ID.String(), user, string(obj), act)

				if err != nil {
					return echo.NewHTTPError(500, "could not determine if the user has access")
				}

				// check if the user has the required role
				if !allowed {
					if project.IsPublic && act == accesscontrol.ActionRead {
						// allow READ on all objects in the project - if access is public
						core.SetIsPublicRequest(c)
					} else {
						return echo.NewHTTPError(403, "forbidden")
					}
				}

				c.Set("project", project)

				return next(c)
			}
		}
	}
}

func projectAccessControl(projectRepository projectRepository, obj accesscontrol.Object, act accesscontrol.Action) core.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c core.Context) error {
			// get the rbac
			rbac := core.GetRBAC(c)

			// get the user
			user := core.GetSession(c).GetUserID()

			// get the project id
			projectSlug, err := core.GetProjectSlug(c)
			if err != nil {
				return echo.NewHTTPError(500, "could not get project id")
			}

			// get the project by slug and tenant.
			project, err := projectRepository.ReadBySlug(core.GetTenant(c).GetID(), projectSlug)

			if err != nil {
				return echo.NewHTTPError(404, "could not get project")
			}

			allowed, err := rbac.IsAllowedInProject(project.ID.String(), user, string(obj), act)

			if err != nil {
				return echo.NewHTTPError(500, "could not determine if the user has access")
			}

			// check if the user has the required role
			if !allowed {
				// check if public
				if project.IsPublic && act == accesscontrol.ActionRead {
					core.SetIsPublicRequest(c)
				} else {
					return echo.NewHTTPError(403, "forbidden")
				}
			}

			c.Set("project", project)

			return next(c)
		}
	}
}

func neededScope(neededScopes []string) core.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c core.Context) error {
			userScopes := core.GetSession(c).GetScopes()

			ok := utils.ContainAll(userScopes, neededScopes)
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
		return func(c core.Context) error {
			// extract the asset id from the header
			// asset name is <organization_slug>/<project_slug>/<asset_slug>
			assetName := c.Request().Header.Get("X-Asset-Name")
			if assetName == "" {
				return echo.NewHTTPError(400, "no asset id provided")
			}
			// split the asset name
			assetParts := strings.Split(assetName, "/")
			if len(assetParts) == 5 {
				// the user probably provided the full url
				// check if projects and assets is part of the asset parts - if so, remove them
				// <tenant>/projects/<project>/assets/<asset>
				if assetParts[1] == "projects" && assetParts[3] == "assets" {
					assetParts = []string{assetParts[0], assetParts[2], assetParts[4]}
				}
			}
			if len(assetParts) != 3 {
				return echo.NewHTTPError(400, "invalid asset name")
			}
			// set the project slug
			c.Set("projectSlug", assetParts[1])
			c.Set("tenant", assetParts[0])
			c.Set("assetSlug", assetParts[2])
			return next(c)
		}
	}
}

func multiTenantMiddleware(rbacProvider accesscontrol.RBACProvider, organizationRepo orgRepository) core.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c core.Context) (err error) {

			// get the tenant from the provided context
			tenant := core.GetParam(c, "tenant")
			if tenant == "" {
				// if no tenant is provided, we can't continue
				slog.Error("no tenant provided")
				return c.JSON(400, map[string]string{"error": "no tenant"})
			}

			// get the organization
			org, err := organizationRepo.ReadBySlug(tenant)

			if err != nil {
				slog.Error("tenant not found")
				return c.JSON(400, map[string]string{"error": "no tenant"})
			}

			domainRBAC := rbacProvider.GetDomainRBAC(org.ID.String())

			// check if the user is allowed to access the tenant
			session := core.GetSession(c)
			allowed := domainRBAC.HasAccess(session.GetUserID())

			if !allowed {
				if org.IsPublic {
					core.SetIsPublicRequest(c)
				} else {
					// not allowed and not a public tenant
					slog.Error("access denied")
					return c.JSON(403, map[string]string{"error": "access denied"})
				}
			}

			// set the tenant in the context
			c.Set("tenant", org)
			// set the RBAC in the context
			c.Set("rbac", domainRBAC)

			c.Set("orgSlug", tenant)
			// continue to the request
			return next(c)
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
func whoami(c echo.Context) error {
	return c.JSON(200, map[string]string{
		"userId": core.GetSession(c).GetUserID(),
	})
}

// @Summary      Health Check
// @Description  Indicating the service is running
// @Tags         health
// @Produce      json
// @Success      200  {string}  string "ok"
// @Router       /health [get]
func health(c echo.Context) error {
	return c.String(200, "ok")
}

func BuildRouter(db core.DB) *echo.Echo {
	ory := auth.GetOryApiClient(os.Getenv("ORY_KRATOS_PUBLIC"))
	oryAdmin := auth.GetOryApiClient(os.Getenv("ORY_KRATOS_ADMIN"))
	casbinRBACProvider, err := accesscontrol.NewCasbinRBACProvider(db)

	if err != nil {
		panic(err)
	}
	githubIntegration := integrations.NewGithubIntegration(db)
	gitlabIntegration := integrations.NewGitLabIntegration(db)
	thirdPartyIntegration := integrations.NewThirdPartyIntegrations(githubIntegration, gitlabIntegration)

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

	dependencyVulnService := dependency_vuln.NewService(dependencyVulnRepository, vulnEventRepository, assetRepository, cveRepository, orgRepository, projectRepository, thirdPartyIntegration)
	firstPartyVulnService := dependency_vuln.NewFirstPartyVulnService(firstPartyVulnRepository, vulnEventRepository, assetRepository)
	projectService := project.NewService(projectRepository)
	dependencyVulnController := dependency_vuln.NewHttpController(dependencyVulnRepository, dependencyVulnService, projectService)

	vulnEventController := events.NewVulnEventController(vulnEventRepository)

	assetService := asset.NewService(assetRepository, dependencyVulnRepository, dependencyVulnService)

	assetVersionService := assetversion.NewService(assetVersionRepository, componentRepository, dependencyVulnRepository, firstPartyVulnRepository, dependencyVulnService, firstPartyVulnService, assetRepository)
	statisticsService := statistics.NewService(statisticsRepository, componentRepository, assetRiskAggregationRepository, dependencyVulnRepository, assetVersionRepository, projectRepository, repositories.NewProjectRiskHistoryRepository(db))
	invitationRepository := repositories.NewInvitationRepository(db)

	intotoService := intoto.NewInTotoService(casbinRBACProvider, intotoLinkRepository, projectRepository, patRepository, supplyChainRepository)
	// init all http controllers using the repositories
	patController := pat.NewHttpController(patRepository)
	orgController := org.NewHttpController(orgRepository, casbinRBACProvider, projectService, invitationRepository)
	projectController := project.NewHttpController(projectRepository, assetRepository, project.NewService(projectRepository))
	assetController := asset.NewHttpController(assetRepository, assetService)
	scanController := scan.NewHttpController(db, cveRepository, componentRepository, assetRepository, assetVersionRepository, assetVersionService, statisticsService, dependencyVulnService)

	assetVersionController := assetversion.NewAssetVersionController(assetVersionRepository, assetVersionService, dependencyVulnRepository, componentRepository, dependencyVulnService, supplyChainRepository)

	intotoController := intoto.NewHttpController(intotoLinkRepository, supplyChainRepository, patRepository, intotoService)

	statisticsController := statistics.NewHttpController(statisticsService, assetRepository, assetVersionRepository, projectService)

	patService := pat.NewPatService(patRepository)

	vulndbController := vulndb.NewHttpController(cveRepository)

	server := echohttp.Server()

	integrationController := integrations.NewIntegrationController()

	apiV1Router := server.Group("/api/v1")

	// this makes the third party integrations available to all controllers
	apiV1Router.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c core.Context) error {
			core.SetThirdPartyIntegration(c, thirdPartyIntegration)
			return next(c)
		}
	})

	apiV1Router.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c core.Context) error {
			// set the ory admin client to the context
			core.SetAuthAdminClient(c, oryAdmin)
			return next(c)
		}
	})

	apiV1Router.POST("/webhook/", integrationController.HandleWebhook)
	// apply the health route without any session or multi tenant middleware
	apiV1Router.GET("/health/", health)

	// everything below this line is protected by the session middleware
	sessionRouter := apiV1Router.Group("", auth.SessionMiddleware(ory, patService))
	// register a simple whoami route for testing purposes
	sessionRouter.GET("/whoami/", whoami)
	sessionRouter.POST("/accept-invitation/", orgController.AcceptInvitation)

	//TODO: change "/scan/" to "/sbom-scan/"
	sessionRouter.POST("/scan/", scanController.ScanDependencyVulnFromProject, neededScope([]string{"scanAsset", "manageAsset"}), assetNameMiddleware(), multiTenantMiddleware(casbinRBACProvider, orgRepository), projectScopedRBAC(accesscontrol.ObjectAsset, accesscontrol.ActionUpdate), assetMiddleware(assetRepository))

	sessionRouter.POST("/sarif-scan/", scanController.FirstPartyVulnScan, assetNameMiddleware(), multiTenantMiddleware(casbinRBACProvider, orgRepository), projectScopedRBAC(accesscontrol.ObjectAsset, accesscontrol.ActionUpdate), assetMiddleware(assetRepository))

	patRouter := sessionRouter.Group("/pats")
	patRouter.POST("/", patController.Create)
	patRouter.GET("/", patController.List)
	patRouter.DELETE("/:tokenId/", patController.Delete)
	patRouter.POST("/revoke-by-private-key/", patController.RevokeByPrivateKey)

	cveRouter := apiV1Router.Group("/vulndb")
	cveRouter.GET("/", vulndbController.ListPaged)
	cveRouter.GET("/:cveId/", vulndbController.Read)

	orgRouter := sessionRouter.Group("/organizations")

	orgRouter.POST("/", orgController.Create)
	orgRouter.GET("/", orgController.List)

	//Api functions for interacting with an organization  ->  .../organizations/<organization-name>/...
	tenantRouter := orgRouter.Group("/:tenant", multiTenantMiddleware(casbinRBACProvider, orgRepository))
	tenantRouter.DELETE("/", orgController.Delete, accessControlMiddleware(accesscontrol.ObjectOrganization, accesscontrol.ActionDelete))
	tenantRouter.GET("/", orgController.Read, accessControlMiddleware(accesscontrol.ObjectOrganization, accesscontrol.ActionRead))

	tenantRouter.PATCH("/", orgController.Update, accessControlMiddleware(accesscontrol.ObjectOrganization, accesscontrol.ActionUpdate))

	tenantRouter.GET("/metrics/", orgController.Metrics)
	tenantRouter.GET("/content-tree/", orgController.ContentTree)
	//TODO: change it
	//tenantRouter.GET("/dependency-vulns/", dependencyVulnController.ListByOrgPaged)
	tenantRouter.GET("/flaws/", dependencyVulnController.ListByOrgPaged)

	tenantRouter.GET("/members/", orgController.Members)
	tenantRouter.POST("/members/", orgController.InviteMember, accessControlMiddleware(accesscontrol.ObjectOrganization, accesscontrol.ActionUpdate))
	tenantRouter.DELETE("/members/:userId/", orgController.RemoveMember, accessControlMiddleware(accesscontrol.ObjectOrganization, accesscontrol.ActionDelete))

	tenantRouter.PUT("/members/:userId/", orgController.ChangeRole, accessControlMiddleware(accesscontrol.ObjectOrganization, accesscontrol.ActionUpdate))

	tenantRouter.GET("/integrations/finish-installation/", integrationController.FinishInstallation)

	tenantRouter.POST("/integrations/gitlab/test-and-save/", integrationController.TestAndSaveGitLabIntegration)
	tenantRouter.DELETE("/integrations/gitlab/:gitlab_integration_id/", integrationController.DeleteGitLabAccessToken)
	tenantRouter.GET("/integrations/repositories/", integrationController.
		ListRepositories)
	tenantRouter.GET("/stats/risk-history/", statisticsController.GetOrgRiskHistory)
	tenantRouter.GET("/stats/average-fixing-time/", statisticsController.GetAverageOrgFixingTime)
	//TODO: change it
	//tenantRouter.GET("/stats/dependency-vuln-aggregation-state-and-change/", statisticsController.GetOrgDependencyVulnAggregationStateAndChange)
	tenantRouter.GET("/stats/flaw-aggregation-state-and-change/", statisticsController.GetOrgDependencyVulnAggregationStateAndChange)
	tenantRouter.GET("/stats/risk-distribution/", statisticsController.GetOrgRiskDistribution)

	tenantRouter.GET("/projects/", projectController.List, accessControlMiddleware(accesscontrol.ObjectOrganization, accesscontrol.ActionRead))
	tenantRouter.POST("/projects/", projectController.Create, accessControlMiddleware(accesscontrol.ObjectOrganization, accesscontrol.ActionUpdate))

	//Api functions for interacting with a project inside an organization  ->  .../organizations/<organization-name>/projects/<project-name>/...
	projectRouter := tenantRouter.Group("/projects/:projectSlug", projectAccessControl(projectRepository, "project", accesscontrol.ActionRead))
	projectRouter.GET("/", projectController.Read)
	//TODO: change it
	//projectRouter.GET("/dependency-vulns/", dependencyVulnController.ListByProjectPaged)
	projectRouter.GET("/flaws/", dependencyVulnController.ListByProjectPaged)

	projectRouter.PATCH("/", projectController.Update, projectScopedRBAC(accesscontrol.ObjectProject, accesscontrol.ActionUpdate))
	projectRouter.DELETE("/", projectController.Delete, projectScopedRBAC(accesscontrol.ObjectProject, accesscontrol.ActionDelete))

	projectRouter.POST("/assets/", assetController.Create, projectScopedRBAC(accesscontrol.ObjectAsset, accesscontrol.ActionCreate))

	projectRouter.GET("/assets/", assetController.List)

	projectRouter.GET("/stats/risk-distribution/", statisticsController.GetProjectRiskDistribution)
	projectRouter.GET("/stats/risk-history/", statisticsController.GetProjectRiskHistory)
	//TODO: change it
	//projectRouter.GET("/stats/dependency-vuln-aggregation-state-and-change/", statisticsController.GetProjectDependencyVulnAggregationStateAndChange)
	projectRouter.GET("/stats/flaw-aggregation-state-and-change/", statisticsController.GetProjectDependencyVulnAggregationStateAndChange)
	projectRouter.GET("/stats/average-fixing-time/", statisticsController.GetAverageProjectFixingTime)

	projectRouter.GET("/members/", projectController.Members)
	projectRouter.POST("/members/", projectController.InviteMembers, projectScopedRBAC(accesscontrol.ObjectProject, accesscontrol.ActionUpdate))
	projectRouter.DELETE("/members/:userId/", projectController.RemoveMember, projectScopedRBAC(accesscontrol.ObjectProject, accesscontrol.ActionDelete))

	projectRouter.PUT("/members/:userId/", projectController.ChangeRole, projectScopedRBAC(accesscontrol.ObjectProject, accesscontrol.ActionUpdate))

	//Api functions for interacting with an asset inside a project  ->  .../projects/<project-name>/assets/<asset-name>/...
	assetRouter := projectRouter.Group("/assets/:assetSlug", projectScopedRBAC(accesscontrol.ObjectAsset, accesscontrol.ActionRead), assetMiddleware(assetRepository))
	assetRouter.GET("/", assetController.Read)
	assetRouter.DELETE("/", assetController.Delete, projectScopedRBAC(accesscontrol.ObjectAsset, accesscontrol.ActionDelete))

	assetRouter.GET("/refs/", assetVersionController.GetAssetVersionsByAssetID)

	//Api to scan manually using an uploaded SBOM provided by the user
	assetRouter.POST("/sbom-file/", scanController.ScanSbomFile)

	//TODO: add the projectScopedRBAC middleware to the following routes
	assetVersionRouter := assetRouter.Group("/refs/:assetVersionSlug", assetVersionMiddleware(assetVersionRepository))

	assetVersionRouter.GET("/", assetVersionController.Read)
	assetVersionRouter.DELETE("/", assetVersionController.Delete) //Delete an asset version

	assetVersionRouter.GET("/metrics/", assetVersionController.Metrics)
	assetVersionRouter.GET("/dependency-graph/", assetVersionController.DependencyGraph)
	assetVersionRouter.GET("/affected-components/", assetVersionController.AffectedComponents)
	assetVersionRouter.GET("/sbom.json/", assetVersionController.SBOMJSON)
	assetVersionRouter.GET("/sbom.xml/", assetVersionController.SBOMXML)
	assetVersionRouter.GET("/vex.json/", assetVersionController.VEXJSON)
	assetVersionRouter.GET("/vex.xml/", assetVersionController.VEXXML)

	assetVersionRouter.GET("/stats/component-risk/", statisticsController.GetComponentRisk)
	assetVersionRouter.GET("/stats/risk-distribution/", statisticsController.GetAssetVersionRiskDistribution)
	assetVersionRouter.GET("/stats/risk-history/", statisticsController.GetAssetVersionRiskHistory)
	//TODO: change it
	//assetVersionRouter.GET("/stats/dependency-vuln-count-by-scanner/", statisticsController.GetDependencyVulnCountByScannerId)
	assetVersionRouter.GET("/stats/flaw-count-by-scanner/", statisticsController.GetDependencyVulnCountByScannerId)
	assetVersionRouter.GET("/stats/dependency-count-by-scan-type/", statisticsController.GetDependencyCountPerScanner)

	//TODO: change it
	//assetVersionRouter.GET("/stats/dependency-vuln-aggregation-state-and-change/", statisticsController.GetDependencyVulnAggregationStateAndChange)
	assetVersionRouter.GET("/stats/flaw-aggregation-state-and-change/", statisticsController.GetDependencyVulnAggregationStateAndChange)
	assetVersionRouter.GET("/stats/average-fixing-time/", statisticsController.GetAverageAssetVersionFixingTime)

	assetVersionRouter.GET("/versions/", assetVersionController.Versions)

	assetRouter.POST("/integrations/gitlab/autosetup/", integrationController.AutoSetup, projectScopedRBAC(accesscontrol.ObjectAsset, accesscontrol.ActionUpdate))
	assetRouter.PATCH("/", assetController.Update, projectScopedRBAC(accesscontrol.ObjectAsset, accesscontrol.ActionUpdate))

	assetRouter.POST("/signing-key/", assetController.AttachSigningKey, projectScopedRBAC(accesscontrol.ObjectAsset, accesscontrol.ActionUpdate))

	assetRouter.POST("/in-toto/", intotoController.Create, projectScopedRBAC(accesscontrol.ObjectAsset, accesscontrol.ActionUpdate))
	assetRouter.GET("/in-toto/root.layout.json/", intotoController.RootLayout)

	assetVersionRouter.GET("/in-toto/:supplyChainId/", intotoController.Read)

	apiV1Router.GET("/verify-supply-chain/", intotoController.VerifySupplyChain)

	//TODO: change it
	//dependencyVulnRouter := assetVersionRouter.Group("/dependency-vulns")
	dependencyVulnRouter := assetVersionRouter.Group("/flaws")
	dependencyVulnRouter.GET("/", dependencyVulnController.ListPaged)
	dependencyVulnRouter.GET("/:dependencyVulnId/", dependencyVulnController.Read)

	dependencyVulnRouter.POST("/:dependencyVulnId/", dependencyVulnController.CreateEvent, projectScopedRBAC(accesscontrol.ObjectAsset, accesscontrol.ActionUpdate))
	dependencyVulnRouter.POST("/:dependencyVulnId/mitigate/", dependencyVulnController.Mitigate, projectScopedRBAC(accesscontrol.ObjectAsset, accesscontrol.ActionUpdate))

	dependencyVulnRouter.GET("/:dependencyVulnId/events/", vulnEventController.ReadAssetEventsByVulnID)

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
