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

package helpers

import (
	"fmt"

	"github.com/google/uuid"
	"github.com/l3montree-dev/flawfix/internal/accesscontrol"
	"github.com/l3montree-dev/flawfix/internal/auth"
	"github.com/l3montree-dev/flawfix/internal/models"
	"github.com/labstack/echo/v4"
)

func GetRBAC(c echo.Context) accesscontrol.AccessControl {
	return c.Get("rbac").(accesscontrol.AccessControl)
}

func GetTenant(c echo.Context) models.Organization {
	return c.Get("tenant").(models.Organization)
}

func GetSession(ctx echo.Context) auth.AuthSession {
	return ctx.Get("session").(auth.AuthSession)
}

func GetProjectID(c echo.Context) (uuid.UUID, error) {
	projectID := c.Param("projectID")
	if projectID == "" {
		return uuid.UUID{}, fmt.Errorf("could not get project id")
	}
	return uuid.Parse(projectID)
}

func GetApplicationID(c echo.Context) (uuid.UUID, error) {
	applicationID := c.Param("applicationID")
	if applicationID == "" {
		return uuid.UUID{}, fmt.Errorf("could not get application id")
	}
	return uuid.Parse(applicationID)
}
