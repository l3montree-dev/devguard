package org

import (
	"log/slog"

	accesscontrol "github.com/l3montree-dev/flawfix/internal/accesscontrol"
	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/labstack/echo/v4"
)

func multiTenantMiddleware(rbacProvider accesscontrol.RBACProvider, organizationRepo repository) core.MiddlewareFunc {
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

func RegisterHttpHandler(database core.DB, server core.Server, rbacProvider accesscontrol.RBACProvider) core.Server {
	if err := database.AutoMigrate(&Model{}); err != nil {
		panic(err)
	}

	repository := NewGormRepository(database)
	controller := NewHttpController(repository, rbacProvider)

	orgRouter := server.Group("/organizations")

	orgRouter.POST("/", controller.Create)
	orgRouter.GET("/", controller.List)

	tenantRouter := orgRouter.Group("/:tenant", multiTenantMiddleware(rbacProvider, repository))

	tenantRouter.DELETE("/", controller.Delete, core.AccessControlMiddleware("organization", accesscontrol.ActionDelete))
	tenantRouter.GET("/", controller.Read, core.AccessControlMiddleware("organization", accesscontrol.ActionRead))

	return tenantRouter
}
