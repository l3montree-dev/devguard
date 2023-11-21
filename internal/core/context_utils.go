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
package core

import (
	"fmt"

	"github.com/google/uuid"
	"github.com/l3montree-dev/flawfix/internal/accesscontrol"
	"github.com/l3montree-dev/flawfix/internal/auth"
)

type Project interface {
	GetID() uuid.UUID
}

type Tenant interface {
	GetID() uuid.UUID
}

func GetRBAC(c Context) accesscontrol.AccessControl {
	return c.Get("rbac").(accesscontrol.AccessControl)
}

func GetTenant(c Context) Tenant {
	return c.Get("tenant").(Tenant)
}

func GetSession(ctx Context) auth.AuthSession {
	return ctx.Get("session").(auth.AuthSession)
}

func GetProjectSlug(c Context) (string, error) {
	projectID := c.Param("projectSlug")
	if projectID == "" {
		return "", fmt.Errorf("could not get project id")
	}
	return projectID, nil
}

func GetApplicationSlug(c Context) (string, error) {
	applicationSlug := c.Param("applicationSlug")
	if applicationSlug == "" {
		return "", fmt.Errorf("could not get application slug")
	}
	return applicationSlug, nil
}

func GetProject(c Context) Project {
	return c.Get("project").(Project)
}

func GetEnvSlug(c Context) (string, error) {
	envSlug := c.Param("envSlug")
	if envSlug == "" {
		return "", fmt.Errorf("could not get env slug")
	}
	return envSlug, nil
}
