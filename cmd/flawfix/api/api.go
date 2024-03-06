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

	"github.com/google/uuid"
	"github.com/l3montree-dev/flawfix/internal/accesscontrol"
	"github.com/l3montree-dev/flawfix/internal/auth"
	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/l3montree-dev/flawfix/internal/core/asset"
	"github.com/l3montree-dev/flawfix/internal/core/flaw"
	"github.com/l3montree-dev/flawfix/internal/core/org"
	"github.com/l3montree-dev/flawfix/internal/core/pat"
	"github.com/l3montree-dev/flawfix/internal/core/project"
	"github.com/l3montree-dev/flawfix/internal/core/vulndb/scan"
	"github.com/l3montree-dev/flawfix/internal/echohttp"
	"github.com/labstack/echo/v4"
)

type assetRepository interface {
	ReadBySlug(projectID uuid.UUID, slug string) (asset.Model, error)
}

type orgRepository interface {
	ReadBySlug(slug string) (org.Model, error)
}

type projectRepository interface {
	ReadBySlug(organizationID uuid.UUID, slug string) (project.Model, error)
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

func multiTenantMiddleware(rbacProvider accesscontrol.RBACProvider, organizationRepo orgRepository) core.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c core.Context) (err error) {
			// get the tenant from the provided context
			tenant := c.Param("tenant")
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

func Start(db core.DB) {
	ory := auth.GetOryApiClient(os.Getenv("ORY_KRATOS"))
	casbinRBACProvider, err := accesscontrol.NewCasbinRBACProvider(db)

	if err != nil {
		panic(err)
	}

	// init all repositories using the provided database
	patRepository := pat.NewGormRepository(db)
	assetRepository := asset.NewGormRepository(db)
	projectRepository := project.NewGormRepository(db)
	projectScopedRBAC := projectAccessControlFactory(projectRepository)
	orgRepository := org.NewGormRepository(db)
	flawRepository := flaw.NewGormRepository(db)
	flawController := flaw.NewHttpController(flawRepository)

	// init all http controllers using the repositories
	patController := pat.NewHttpController(patRepository)
	orgController := org.NewHttpController(orgRepository, casbinRBACProvider)
	projectController := project.NewHttpController(projectRepository, assetRepository)
	assetController := asset.NewHttpController(assetRepository)
	scanController := scan.NewHttpController(db)

	server := echohttp.Server()

	apiV1Router := server.Group("/api/v1")
	// apply the health route without any session or multi tenant middleware
	apiV1Router.GET("/health/", func(c echo.Context) error {
		return c.String(200, "ok")
	})
	// everything below this line is protected by the session middleware
	sessionRouter := apiV1Router.Group("", auth.SessionMiddleware(ory, patRepository))
	// register a simple whoami route for testing purposes
	sessionRouter.GET("/whoami/", func(c echo.Context) error {
		return c.JSON(200, map[string]string{
			"userId": core.GetSession(c).GetUserID(),
		})
	})

	apiV1Router.POST("/scan/", scanController.Scan)

	patRouter := sessionRouter.Group("/pats")
	patRouter.POST("/", patController.Create)
	patRouter.GET("/", patController.List)
	patRouter.DELETE("/:tokenId/", patController.Delete)

	orgRouter := sessionRouter.Group("/organizations")
	orgRouter.POST("/", orgController.Create)
	orgRouter.GET("/", orgController.List)

	tenantRouter := orgRouter.Group("/:tenant", multiTenantMiddleware(casbinRBACProvider, orgRepository))
	tenantRouter.DELETE("/", orgController.Delete, core.AccessControlMiddleware("organization", accesscontrol.ActionDelete))
	tenantRouter.GET("/", orgController.Read, core.AccessControlMiddleware("organization", accesscontrol.ActionRead))

	tenantRouter.GET("/projects/", projectController.List, core.AccessControlMiddleware("organization", accesscontrol.ActionRead))
	tenantRouter.POST("/projects/", projectController.Create, core.AccessControlMiddleware("organization", accesscontrol.ActionUpdate))

	projectRouter := tenantRouter.Group("/projects/:projectSlug", projectAccessControl(projectRepository, "project", accesscontrol.ActionRead))
	projectRouter.GET("/", projectController.Read)
	projectRouter.POST("/assets/", assetController.Create, projectScopedRBAC(accesscontrol.ObjectAsset, accesscontrol.ActionCreate))
	projectRouter.GET("/assets/", assetController.Read)

	assetRouter := projectRouter.Group("/assets/:assetSlug", projectScopedRBAC("asset", accesscontrol.ActionRead), assetMiddleware(assetRepository))
	assetRouter.GET("/", assetController.Read)

	flawRouter := assetRouter.Group("/flaws")
	flawRouter.GET("/", flawController.ListPaged)
	flawRouter.GET("/:flawId/", flawController.Read)

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
