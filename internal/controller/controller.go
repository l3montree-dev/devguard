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
package controller

import (
	"fmt"

	"github.com/go-playground/validator/v10"
	"github.com/l3montree-dev/flawfix/internal/accesscontrol"
	"github.com/l3montree-dev/flawfix/internal/auth"
	"github.com/l3montree-dev/flawfix/internal/models"
	"github.com/labstack/echo/v4"
)

var v = validator.New()

func GetRBAC(c echo.Context) accesscontrol.AccessControl {
	return c.Get("rbac").(accesscontrol.AccessControl)
}

func GetTenant(c echo.Context) models.Organization {
	return c.Get("tenant").(models.Organization)
}

func GetSession(ctx echo.Context) auth.AuthSession {
	return ctx.Get("session").(auth.AuthSession)
}

func GetProjectSlug(c echo.Context) (string, error) {
	projectID := c.Param("projectSlug")
	if projectID == "" {
		return "", fmt.Errorf("could not get project id")
	}
	return projectID, nil
}

func GetApplicationSlug(c echo.Context) (string, error) {
	applicationSlug := c.Param("applicationSlug")
	if applicationSlug == "" {
		return "", fmt.Errorf("could not get application slug")
	}
	return applicationSlug, nil
}

func GetProject(c echo.Context) (models.Project, error) {
	project, ok := c.Get("project").(models.Project)
	if !ok {
		return models.Project{}, fmt.Errorf("could not get project")
	}

	return project, nil
}
