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
	"log/slog"
	"strings"

	"github.com/google/uuid"
	"github.com/l3montree-dev/flawfix/internal/accesscontrol"
	"github.com/l3montree-dev/flawfix/internal/dto"
	"github.com/l3montree-dev/flawfix/internal/models"
	"github.com/l3montree-dev/flawfix/internal/repositories"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
)

type ProjectController struct {
	projectRepository repositories.Repository[uuid.UUID, models.Project, *gorm.DB]
	applicationRepository
}

func NewProjectController(repository repositories.Repository[uuid.UUID, models.Project, *gorm.DB], appRepository applicationRepository) *ProjectController {
	return &ProjectController{
		projectRepository:     repository,
		applicationRepository: appRepository,
	}
}

func (p *ProjectController) Create(c echo.Context) error {
	var req dto.ProjectCreateRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(400, "unable to process request").WithInternal(err)
	}

	if err := v.Struct(req); err != nil {
		return echo.NewHTTPError(400, err.Error())
	}

	model := req.ToModel()
	// add the organization id
	model.OrganizationID = GetTenant(c).ID

	err := p.projectRepository.Create(nil, &model)

	if err != nil {
		return err
	}

	p.bootstrapProject(c, model)

	return c.JSON(200, model)
}

func (p *ProjectController) bootstrapProject(c echo.Context, project models.Project) {
	// get the rbac object
	rbac := GetRBAC(c)
	// make sure to keep the organization roles in sync
	// let the organization admin role inherit all permissions from the project admin
	rbac.LinkDomainAndProjectRole("admin", "admin", project.ID.String())
	rbac.InheritProjectRole("admin", "member", project.ID.String())

	rbac.AllowRoleInProject(project.ID.String(), "admin", "user", []accesscontrol.Action{
		accesscontrol.ActionCreate,
		accesscontrol.ActionDelete,
		accesscontrol.ActionUpdate,
	})

	rbac.AllowRoleInProject(project.ID.String(), "admin", "application", []accesscontrol.Action{
		accesscontrol.ActionCreate,
		accesscontrol.ActionDelete,
		accesscontrol.ActionUpdate,
	})

	rbac.AllowRoleInProject(project.ID.String(), "member", "project", []accesscontrol.Action{
		accesscontrol.ActionRead,
	})

	rbac.AllowRoleInProject(project.ID.String(), "member", "application", []accesscontrol.Action{
		accesscontrol.ActionRead,
	})
}

func (p *ProjectController) Delete(c echo.Context) error {
	projectID, err := uuid.Parse(c.Param("projectID"))
	if err != nil {
		return echo.NewHTTPError(400, "invalid project id").WithInternal(err)
	}

	err = p.projectRepository.Delete(nil, projectID)
	if err != nil {
		return err
	}

	return c.NoContent(200)
}

func (p *ProjectController) Read(c echo.Context) error {

	// just get the project from the context
	project, err := GetProject(c)
	if err != nil {
		return echo.NewHTTPError(500, "this should never happen").WithInternal(err)
	}

	// lets fetch the applications related to this project
	applications, err := p.GetByProjectID(project.ID)
	if err != nil {
		return err
	}

	project.Applications = applications

	return c.JSON(200, project)
}

func (p *ProjectController) List(c echo.Context) error {
	// get all projects the user has at least read access to
	rbac := GetRBAC(c)
	roles := rbac.GetAllRoles(GetSession(c).GetUserID())

	// extract the project ids from the roles
	projectIDs := make([]uuid.UUID, 0)
	for _, role := range roles {
		if !strings.HasPrefix(role, "role::project::") {
			continue // not a project role
		}
		// extract everything between the prefix and a "|"
		projectID, err := uuid.Parse(strings.Split(strings.TrimPrefix(role, "role::project::"), "|")[0])
		if err != nil {
			slog.Error("could not parse project id from role", "role", role)
			continue
		}
		projectIDs = append(projectIDs, projectID)
	}
	projects, err := p.projectRepository.List(projectIDs)
	if err != nil {
		return err
	}

	return c.JSON(200, projects)
}
