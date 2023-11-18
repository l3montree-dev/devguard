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

	"github.com/google/uuid"
	"github.com/l3montree-dev/flawfix/internal/accesscontrol"
	"github.com/l3montree-dev/flawfix/internal/dto"
	"github.com/l3montree-dev/flawfix/internal/helpers"
	"github.com/l3montree-dev/flawfix/internal/models"
	"github.com/labstack/echo/v4"
)

type projectRepository interface {
	Create(*models.Project) error
	Delete(uuid.UUID) error
	Read(uuid.UUID) (models.Project, error)
	Update(*models.Project) error
	List([]uuid.UUID) ([]models.Project, error)
}

type ProjectController struct {
	projectRepository
}

func NewProjectController(repository projectRepository) *ProjectController {
	return &ProjectController{
		projectRepository: repository,
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

	err := p.projectRepository.Create(&model)

	if err != nil {
		return err
	}

	p.bootstrapProject(c, model)

	return c.JSON(200, model)
}

func (p *ProjectController) bootstrapProject(c echo.Context, project models.Project) {
	// get the rbac object
	rbac := helpers.GetRBAC(c)
	// make sure to keep the organization roles in sync
	// let the organization admin role inherit all permissions from the project admin
	rbac.InheritRole("admin", rbac.GetProjectRoleName(project.ID.String(), "admin"))
	rbac.InheritRole(rbac.GetProjectRoleName(project.ID.String(), "admin"), rbac.GetProjectRoleName(project.ID.String(), "member"))

	rbac.AllowRoleInProject(project.ID.String(), "admin", "user", []accesscontrol.Action{
		accesscontrol.ActionCreate,
		accesscontrol.ActionDelete,
	})

	rbac.AllowRoleInProject(project.ID.String(), "member", "project", []accesscontrol.Action{
		accesscontrol.ActionRead, // project:read will be used to check all other permissions
	})
}

func (p *ProjectController) Delete(c echo.Context) error {
	projectID, err := uuid.Parse(c.Param("projectID"))
	if err != nil {
		return echo.NewHTTPError(400, "invalid project id").WithInternal(err)
	}

	err = p.projectRepository.Delete(projectID)
	if err != nil {
		return err
	}

	return c.NoContent(200)
}

func (p *ProjectController) Read(c echo.Context) error {
	projectID, err := uuid.Parse(c.Param("projectID"))
	if err != nil {
		return echo.NewHTTPError(400, "invalid project id").WithInternal(err)
	}

	project, err := p.projectRepository.Read(projectID)
	if err != nil {
		return err
	}

	return c.JSON(200, project)
}

func (p *ProjectController) List(c echo.Context) error {
	// get all projects the user has at least read access to
	rbac := helpers.GetRBAC(c)
	fmt.Println(rbac.GetAllRoles(helpers.GetSession(c).GetUserID()))

	return c.JSON(200, []models.Project{})
}
