// Copyright (C) 2023 Tim Bastin, l3montree UG (haftungsbeschränkt)
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

package middleware

import (
	"log/slog"

	accesscontrol "github.com/l3montree-dev/flawfix/internal/accesscontrol"
	"github.com/l3montree-dev/flawfix/internal/helpers"
	"github.com/l3montree-dev/flawfix/internal/repositories"
	"github.com/labstack/echo/v4"
)

func MultiTenantMiddleware(rbacProvider accesscontrol.CasbinRBACProvider, organizationRepo *repositories.GormOrganizationRepository) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) (err error) {
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
			session := helpers.GetSession(c)
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
