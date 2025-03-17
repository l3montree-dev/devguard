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
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/l3montree-dev/devguard/internal/accesscontrol"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/labstack/echo/v4"
	"github.com/ory/client-go"
)

type Controller struct {
	projectRepository core.ProjectRepository
	assetRepository   core.AssetRepository
	projectService    core.ProjectService
}

func NewHttpController(repository core.ProjectRepository, assetRepository core.AssetRepository, projectService core.ProjectService) *Controller {
	return &Controller{
		projectRepository: repository,
		assetRepository:   assetRepository,
		projectService:    projectService,
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
	model.OrganizationID = core.GetOrganization(c).GetID()

	if err := p.projectRepository.Create(nil, &model); err != nil {
		// check if duplicate key error
		if database.IsDuplicateKeyError(err) {
			// get the project by slug and project id unscoped
			project, err := p.projectRepository.ReadBySlugUnscoped(core.GetOrganization(c).GetID(), model.Slug)
			if err != nil {
				return echo.NewHTTPError(500, "could not create asset").WithInternal(err)
			}

			if err = p.projectRepository.Activate(nil, project.GetID()); err != nil {
				return echo.NewHTTPError(500, "could not activate asset").WithInternal(err)
			}

			slog.Info("project activated", "projectSlug", model.Slug, "projectID", project.GetID())

			model = project
		} else {
			return echo.NewHTTPError(500, "could not create project").WithInternal(err)
		}
	}

	if err := p.bootstrapProject(c, model); err != nil {
		return echo.NewHTTPError(500, "could not bootstrap project").WithInternal(err)
	}

	return c.JSON(200, model)
}

func FetchMembersOfProject(ctx core.Context) ([]core.User, error) {
	project := core.GetProject(ctx)
	// get rbac
	rbac := core.GetRBAC(ctx)

	members, err := rbac.GetAllMembersOfProject(project.ID.String())
	if err != nil {
		return nil, echo.NewHTTPError(500, "could not get members of project").WithInternal(err)
	}

	// get the auth admin client from the context
	authAdminClient := core.GetAuthAdminClient(ctx)
	// fetch the users from the auth service
	m, _, err := authAdminClient.IdentityAPI.ListIdentitiesExecute(client.IdentityAPIListIdentitiesRequest{}.Ids(members))

	if err != nil {
		return nil, echo.NewHTTPError(500, "could not get members").WithInternal(err)
	}

	users := utils.Map(m, func(i client.Identity) core.User {
		nameMap := i.Traits.(map[string]any)["name"].(map[string]any)
		var name string
		if nameMap != nil {
			if nameMap["first"] != nil {
				name += nameMap["first"].(string)
			}
			if nameMap["last"] != nil {
				name += " " + nameMap["last"].(string)
			}
		}
		role, err := rbac.GetProjectRole(i.Id, project.ID.String())
		if err != nil {
			return core.User{
				ID:   i.Id,
				Name: name,
			}
		}
		return core.User{
			ID:   i.Id,
			Name: name,
			Role: role,
		}
	})

	return users, nil
}

func (p *Controller) Members(c core.Context) error {
	members, err := FetchMembersOfProject(c)
	if err != nil {
		return err
	}

	return c.JSON(200, members)
}

func (p *Controller) InviteMembers(c core.Context) error {
	project := core.GetProject(c)

	// get rbac
	rbac := core.GetRBAC(c)

	var req inviteToProjectRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(400, "unable to process request").WithInternal(err)
	}

	if err := core.V.Struct(req); err != nil {
		return echo.NewHTTPError(400, err.Error())
	}

	members, err := rbac.GetAllMembersOfOrganization()
	if err != nil {
		return echo.NewHTTPError(500, "could not get members of organization").WithInternal(err)
	}

	for _, newMemberId := range req.Ids {
		if !utils.Contains(members, newMemberId) {
			return echo.NewHTTPError(400, "user is not a member of the organization")
		}

		if err := rbac.GrantRoleInProject(newMemberId, "member", project.ID.String()); err != nil {
			return err
		}
	}
	return c.NoContent(200)
}

func (p *Controller) RemoveMember(c core.Context) error {
	project := core.GetProject(c)

	// get rbac
	rbac := core.GetRBAC(c)

	userId := c.Param("userId")
	if userId == "" {
		return echo.NewHTTPError(400, "userId is required")
	}

	// revoke admin and member role
	rbac.RevokeRoleInProject(userId, "admin", project.ID.String())  // nolint:errcheck // we don't care if the user is not an admin
	rbac.RevokeRoleInProject(userId, "member", project.ID.String()) // nolint:errcheck // we don't care if the user is not a member

	return c.NoContent(200)
}

func (p *Controller) ChangeRole(c core.Context) error {
	project := core.GetProject(c)

	// get rbac
	rbac := core.GetRBAC(c)

	var req changeRoleRequest

	userId := c.Param("userId")
	if userId == "" {
		return echo.NewHTTPError(400, "userId is required")
	}

	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(400, "unable to process request").WithInternal(err)
	}

	if err := core.V.Struct(req); err != nil {
		return echo.NewHTTPError(400, err.Error())
	}

	// check if role is valid
	if role := req.Role; role != "admin" && role != "member" {
		return echo.NewHTTPError(400, "invalid role")
	}

	members, err := rbac.GetAllMembersOfOrganization()
	if err != nil {
		return echo.NewHTTPError(500, "could not get members of organization").WithInternal(err)
	}

	if !utils.Contains(members, userId) {
		return echo.NewHTTPError(400, "user is not a member of the organization")
	}

	rbac.RevokeRoleInProject(userId, "admin", project.ID.String()) // nolint:errcheck // we don't care if the user is not an admin

	rbac.RevokeRoleInProject(userId, "member", project.ID.String()) // nolint:errcheck // we don't care if the user is not a member

	if err := rbac.GrantRoleInProject(userId, req.Role, project.ID.String()); err != nil {
		return err
	}

	return c.NoContent(200)
}

func (p *Controller) bootstrapProject(c core.Context, project models.Project) error {
	// get the rbac object
	rbac := core.GetRBAC(c)
	// make sure to keep the organization roles in sync
	// let the organization admin role inherit all permissions from the project admin
	if err := rbac.LinkDomainAndProjectRole("admin", "admin", project.ID.String()); err != nil {
		return err
	}

	// give the admin of a project all member permissions
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

	if err := rbac.AllowRoleInProject(project.ID.String(), "admin", "project", []accesscontrol.Action{
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

	// check if there is a parent project - if so, we need to further inherit the roles
	if project.ParentID != nil {
		// make a parent project admin an admin of the child project
		if err := rbac.InheritProjectRolesAcrossProjects(accesscontrol.ProjectRole{
			Role:    "admin",
			Project: (*project.ParentID).String(),
		}, accesscontrol.ProjectRole{
			Role:    "admin",
			Project: project.ID.String(),
		}); err != nil {
			return err
		}

		// make a parent project member a member of the child project
		if err := rbac.InheritProjectRolesAcrossProjects(accesscontrol.ProjectRole{
			Role:    "member",
			Project: (*project.ParentID).String(),
		}, accesscontrol.ProjectRole{
			Role:    "member",
			Project: project.ID.String(),
		}); err != nil {
			return err
		}
	}

	return nil
}

func (p *Controller) Delete(c core.Context) error {
	project := core.GetProject(c)

	err := p.projectRepository.Delete(nil, project.ID)
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

	// lets fetch the members of the project
	members, err := FetchMembersOfProject(c)
	if err != nil {
		return err
	}

	project.Assets = assets

	resp := projectDetailsDTO{
		ProjectDTO: fromModel(project),
		Members:    members,
	}

	return c.JSON(200, resp)
}

func (p *Controller) List(c core.Context) error {
	// get all projects the user has at least read access to - might be public projects as well
	projects, err := p.projectService.ListAllowedProjects(c)

	if err != nil {
		return err
	}

	return c.JSON(200, projects)
}

func (p *Controller) Update(c core.Context) error {
	req := c.Request().Body
	defer req.Close()
	var patchRequest patchRequest
	err := json.NewDecoder(req).Decode(&patchRequest)
	if err != nil {
		return fmt.Errorf("could not decode request: %w", err)
	}

	project := core.GetProject(c)

	updated := patchRequest.applyToModel(&project)
	if updated {
		err = p.projectRepository.Update(nil, &project)
		if err != nil {
			return fmt.Errorf("could not update project: %w", err)
		}
	}
	// lets fetch the assets related to this project
	assets, err := p.assetRepository.GetByProjectID(project.ID)
	if err != nil {
		return err
	}

	// lets fetch the members of the project
	members, err := FetchMembersOfProject(c)
	if err != nil {
		return err
	}

	project.Assets = assets

	resp := projectDetailsDTO{
		ProjectDTO: fromModel(project),
		Members:    members,
	}
	return c.JSON(200, resp)
}
