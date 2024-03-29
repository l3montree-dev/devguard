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

package project

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/flawfix/internal/accesscontrol"
	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/l3montree-dev/flawfix/internal/database/models"
	"github.com/l3montree-dev/flawfix/internal/database/repositories"

	"github.com/labstack/echo/v4"
)

type projectRepository interface {
	repositories.Repository[uuid.UUID, models.Project, core.DB]
	ReadBySlug(organizationID uuid.UUID, slug string) (models.Project, error)
}

type assetRepository interface {
	GetByProjectID(projectID uuid.UUID) ([]models.Asset, error)
}

type Controller struct {
	projectRepository projectRepository
	assetRepository   assetRepository
}

func NewHttpController(repository projectRepository, assetRepository assetRepository) *Controller {
	return &Controller{
		projectRepository: repository,
		assetRepository:   assetRepository,
	}
}

func (p *Controller) Create(c core.Context) error {
	var req CreateRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(400, "unable to process request").WithInternal(err)
	}

	if err := core.V.Struct(req); err != nil {
		return echo.NewHTTPError(400, err.Error())
	}

	model := req.ToModel()
	// add the organization id
	model.OrganizationID = core.GetTenant(c).GetID()

	if err := p.projectRepository.Create(nil, &model); err != nil {
		return echo.NewHTTPError(500, "could not create project").WithInternal(err)
	}

	if err := p.bootstrapProject(c, model); err != nil {
		return echo.NewHTTPError(500, "could not bootstrap project").WithInternal(err)
	}

	return c.JSON(200, model)
}

func (p *Controller) bootstrapProject(c core.Context, project models.Project) error {
	// get the rbac object
	rbac := core.GetRBAC(c)
	// make sure to keep the organization roles in sync
	// let the organization admin role inherit all permissions from the project admin
	if err := rbac.LinkDomainAndProjectRole("admin", "admin", project.ID.String()); err != nil {
		return err
	}

	if err := rbac.InheritProjectRole("admin", "member", project.ID.String()); err != nil {
		return err
	}

	if err := rbac.AllowRoleInProject(project.ID.String(), "admin", "user", []accesscontrol.Action{
		accesscontrol.ActionCreate,
		accesscontrol.ActionDelete,
		accesscontrol.ActionUpdate,
	}); err != nil {
		return err
	}

	if err := rbac.AllowRoleInProject(project.ID.String(), "admin", "asset", []accesscontrol.Action{
		accesscontrol.ActionCreate,
		accesscontrol.ActionDelete,
		accesscontrol.ActionUpdate,
	}); err != nil {
		return err
	}

	if err := rbac.AllowRoleInProject(project.ID.String(), "member", "project", []accesscontrol.Action{
		accesscontrol.ActionRead,
	}); err != nil {
		return err
	}

	if err := rbac.AllowRoleInProject(project.ID.String(), "member", "asset", []accesscontrol.Action{
		accesscontrol.ActionRead,
	}); err != nil {
		return err
	}
	return nil
}

func (p *Controller) Delete(c core.Context) error {
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

func (p *Controller) Read(c core.Context) error {
	// just get the project from the context
	project := core.GetProject(c)

	// lets fetch the assets related to this project
	assets, err := p.assetRepository.GetByProjectID(project.ID)
	if err != nil {
		return err
	}

	project.Assets = assets

	return c.JSON(200, project)
}

func (p *Controller) List(c core.Context) error {
	// get all projects the user has at least read access to
	rbac := core.GetRBAC(c)
	projectsIdsStr := rbac.GetAllProjectsForUser(core.GetSession(c).GetUserID())

	// extract the project ids from the roles
	projectIDs := make([]uuid.UUID, 0)
	for _, project := range projectsIdsStr {
		projectID := uuid.MustParse(project)
		projectIDs = append(projectIDs, projectID)
	}

	projects, err := p.projectRepository.List(projectIDs)

	if err != nil {
		return err
	}

	return c.JSON(200, projects)
}
