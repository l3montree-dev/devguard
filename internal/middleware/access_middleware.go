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

	"github.com/l3montree-dev/flawfix/internal/accesscontrol"
	"github.com/l3montree-dev/flawfix/internal/helpers"
	"github.com/labstack/echo/v4"
)

func AccessControlMiddleware(obj string, act accesscontrol.Action) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// get the rbac
			rbac := helpers.GetRBAC(c)

			// get the user
			user := helpers.GetSession(c).GetUserID()
			slog.Debug("checking permission", "user", user, "obj", obj, "act", act)
			allowed, err := rbac.IsAllowed(user, obj, act)
			if err != nil {
				return echo.NewHTTPError(500, "could not determine if the user has access")
			}

			// check if the user has the required role
			if !allowed {
				return echo.NewHTTPError(403, "forbidden")
			}

			return next(c)
		}
	}
}

func ProjectAccessControl(obj string, act accesscontrol.Action) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// get the rbac
			rbac := helpers.GetRBAC(c)

			// get the user
			user := helpers.GetSession(c).GetUserID()

			// get the project id
			projectID, err := helpers.GetProjectID(c)
			if err != nil {
				return echo.NewHTTPError(500, "could not get project id")
			}

			allowed, err := rbac.IsAllowedInProject(projectID.String(), user, obj, act)
			if err != nil {
				return echo.NewHTTPError(500, "could not determine if the user has access")
			}

			// check if the user has the required role
			if !allowed {
				return echo.NewHTTPError(403, "forbidden")
			}

			return next(c)
		}
	}
}
