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
	"github.com/google/uuid"
	accesscontrol "github.com/l3montree-dev/flawfix/internal/accesscontrol"
	"github.com/l3montree-dev/flawfix/internal/helpers"
	"github.com/l3montree-dev/flawfix/internal/repositories"
	"github.com/labstack/echo/v4"
	"github.com/labstack/gommon/log"
)

func MultiTenantMiddleware(rbacProvider accesscontrol.CasbinRBACProvider, organizationRepo *repositories.GormOrganizationRepository) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) (err error) {
			// get the tenant from the provided context
			tenant := c.Param("tenant")
			if tenant == "" {
				// if no tenant is provided, we can't continue
				log.Errorf("no tenant provided")
				return c.JSON(400, map[string]string{"error": "no tenant"})
			}

			domainRBAC := rbacProvider.GetDomainRBAC(tenant)

			// check if the user is allowed to access the tenant
			session := helpers.GetSession(c)
			allowed := domainRBAC.HasAccess(session.GetUserID())

			if !allowed {
				log.Errorf("access denied")
				return c.JSON(401, map[string]string{"error": "access denied"})
			}

			// fetch the tenant from the database
			tenantUuid, err := uuid.FromBytes([]byte(tenant))
			if err != nil {
				log.Errorf("not a valid tenant uuid - but access was granted")
				return c.JSON(500, map[string]string{"error": "tenant not found"})
			}

			tenantObj, err := organizationRepo.Read(tenantUuid)
			if err != nil {
				log.Errorf("tenant not found - but access was granted")
				return c.JSON(500, map[string]string{"error": "tenant not found"})
			}

			// set the tenant in the context
			c.Set("tenant", tenantObj)
			// set the RBAC in the context
			c.Set("rbac", domainRBAC)

			// continue to the request
			return next(c)
		}
	}
}
