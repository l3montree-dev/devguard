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
	"github.com/l3montree-dev/flawfix/internal/helpers"
	"github.com/labstack/echo/v4"
	"github.com/labstack/gommon/log"
)

func AccessControlDecorator(obj string, act string, next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) (err error) {
		// get the rbac
		rbac := helpers.GetRBAC(c)

		// get the user
		user := helpers.GetSession(c).GetUserID()

		allowed, err := rbac.IsAllowed(user, obj, act)
		if err != nil {
			log.Errorf("could not determine if the user has access", err)
			return c.JSON(500, map[string]string{"error": "internal server error"})
		}

		// check if the user has the required role
		if !allowed {
			return c.JSON(403, map[string]string{"error": "forbidden"})
		}

		return next(c)
	}
}
