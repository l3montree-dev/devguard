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
	"github.com/l3montree-dev/flawfix/internal/accesscontrol"
	"github.com/l3montree-dev/flawfix/internal/auth"
	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/l3montree-dev/flawfix/internal/core/asset"
	"github.com/l3montree-dev/flawfix/internal/core/flaw"
	"github.com/l3montree-dev/flawfix/internal/core/integrations"
	"github.com/l3montree-dev/flawfix/internal/core/org"
	"github.com/l3montree-dev/flawfix/internal/core/pat"
	"github.com/l3montree-dev/flawfix/internal/core/project"
	"github.com/l3montree-dev/flawfix/internal/core/vulndb"
	"github.com/l3montree-dev/flawfix/internal/core/vulndb/scan"
	"github.com/l3montree-dev/flawfix/internal/database/models"
	"github.com/l3montree-dev/flawfix/internal/database/repositories"
	"github.com/l3montree-dev/flawfix/internal/echohttp"
	"github.com/labstack/echo/v4"
)

type assetRepository interface {
	ReadBySlug(projectID uuid.UUID, slug string) (models.Asset, error)
}

type orgRepository interface {
	ReadBySlug(slugOrId string) (models.Org, error)
}

type projectRepository interface {
	ReadBySlug(organizationID uuid.UUID, slug string) (models.Project, error)
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

			c.Set("asset", asset)

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
					return echo.NewHTTPError(403, "forbidden")
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
				return echo.NewHTTPError(403, "forbidden")
			}

			c.Set("project", project)

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
				slog.Error("access denied")
				return c.JSON(401, map[string]string{"error": "access denied"})
			}

			// set the tenant in the context
			c.Set("tenant", org)
			// set the RBAC in the context
			c.Set("rbac", domainRBAC)

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

func Start(db core.DB) {
	ory := auth.GetOryApiClient(os.Getenv("ORY_KRATOS"))
	casbinRBACProvider, err := accesscontrol.NewCasbinRBACProvider(db)

	if err != nil {
		panic(err)
	}

	// init all repositories using the provided database
	patRepository := repositories.NewPATRepository(db)
	assetRepository := repositories.NewAssetRepository(db)
	projectRepository := repositories.NewProjectRepository(db)
	componentRepository := repositories.NewComponentRepository(db)
	flawEventRepository := repositories.NewFlawEventRepository(db)
	projectScopedRBAC := projectAccessControlFactory(projectRepository)
	orgRepository := repositories.NewOrgRepository(db)
	cveRepository := repositories.NewCVERepository(db)
	flawRepository := repositories.NewFlawRepository(db)
	flawService := flaw.NewService(flawRepository, flawEventRepository, assetRepository, cveRepository)
	flawController := flaw.NewHttpController(flawRepository, flawService)
	githubAppInstallationRepository := repositories.NewGithubAppInstallationRepository(db)

	assetService := asset.NewService(assetRepository, componentRepository, flawRepository, flawService)

	// init all http controllers using the repositories
	patController := pat.NewHttpController(patRepository)
	orgController := org.NewHttpController(orgRepository, casbinRBACProvider)
	projectController := project.NewHttpController(projectRepository, assetRepository)
	assetController := asset.NewHttpController(assetRepository, componentRepository, scan.NewPurlComparer(db), flawRepository, assetService)
	scanController := scan.NewHttpController(db, cveRepository, componentRepository, assetService)

	vulndbController := vulndb.NewHttpController(cveRepository)

	server := echohttp.Server()

	githubIntegration := integrations.NewGithubIntegration(githubAppInstallationRepository)
	integrationController := integrations.NewIntegrationController(githubIntegration)

	apiV1Router := server.Group("/api/v1")

	apiV1Router.POST("/gh-webhook/", githubIntegration.Webhook)
	// apply the health route without any session or multi tenant middleware
	apiV1Router.GET("/health/", health)
	// everything below this line is protected by the session middleware
	sessionRouter := apiV1Router.Group("", auth.SessionMiddleware(ory, patRepository))
	// register a simple whoami route for testing purposes
	sessionRouter.GET("/whoami/", whoami)

	sessionRouter.POST("/scan/", scanController.Scan, assetNameMiddleware(), multiTenantMiddleware(casbinRBACProvider, orgRepository), projectScopedRBAC(accesscontrol.ObjectAsset, accesscontrol.ActionUpdate), assetMiddleware(assetRepository))

	patRouter := sessionRouter.Group("/pats")
	patRouter.POST("/", patController.Create)
	patRouter.GET("/", patController.List)
	patRouter.DELETE("/:tokenId/", patController.Delete)

	cveRouter := apiV1Router.Group("/vulndb")
	cveRouter.GET("/", vulndbController.ListPaged)
	cveRouter.GET("/:cveId/", vulndbController.Read)

	orgRouter := sessionRouter.Group("/organizations")
	orgRouter.POST("/", orgController.Create)
	orgRouter.GET("/", orgController.List)

	tenantRouter := orgRouter.Group("/:tenant", multiTenantMiddleware(casbinRBACProvider, orgRepository))
	tenantRouter.DELETE("/", orgController.Delete, core.AccessControlMiddleware("organization", accesscontrol.ActionDelete))
	tenantRouter.GET("/", orgController.Read, core.AccessControlMiddleware("organization", accesscontrol.ActionRead))

	tenantRouter.GET("/metrics/", orgController.Metrics)
	tenantRouter.GET("/integrations/github/finish-installation/", githubIntegration.FinishInstallation)
	tenantRouter.GET("/integrations/repositories/", integrationController.ListRepositories)

	tenantRouter.GET("/projects/", projectController.List, core.AccessControlMiddleware("organization", accesscontrol.ActionRead))
	tenantRouter.POST("/projects/", projectController.Create, core.AccessControlMiddleware("organization", accesscontrol.ActionUpdate))

	projectRouter := tenantRouter.Group("/projects/:projectSlug", projectAccessControl(projectRepository, "project", accesscontrol.ActionRead))
	projectRouter.GET("/", projectController.Read)
	projectRouter.POST("/assets/", assetController.Create, projectScopedRBAC(accesscontrol.ObjectAsset, accesscontrol.ActionCreate))
	projectRouter.GET("/assets/", assetController.Read)

	assetRouter := projectRouter.Group("/assets/:assetSlug", projectScopedRBAC("asset", accesscontrol.ActionRead), assetMiddleware(assetRepository))
	assetRouter.GET("/", assetController.Read)
	assetRouter.GET("/dependency-graph/", assetController.DependencyGraph)
	assetRouter.GET("/affected-packages/", assetController.AffectedPackages)
	assetRouter.GET("/sbom.json/", assetController.SBOMJSON)
	assetRouter.GET("/sbom.xml/", assetController.SBOMXML)

	assetRouter.GET("/versions/", assetController.Versions)

	assetRouter.PATCH("/", assetController.UpdateRequirements)

	flawRouter := assetRouter.Group("/flaws")
	flawRouter.GET("/", flawController.ListPaged)
	flawRouter.GET("/:flawId/", flawController.Read)

	flawRouter.POST("/:flawId/", flawController.CreateEvent, projectScopedRBAC("asset", accesscontrol.ActionUpdate))

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
	slog.Error("failed to start server", "err", server.Start(":8080").Error())
}
