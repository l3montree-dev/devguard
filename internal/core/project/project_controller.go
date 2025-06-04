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

	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/labstack/echo/v4"
	"github.com/ory/client-go"
	"gorm.io/gorm/clause"
)

type controller struct {
	projectRepository core.ProjectRepository
	assetRepository   core.AssetRepository
	projectService    core.ProjectService
}

func NewHttpController(repository core.ProjectRepository, assetRepository core.AssetRepository, projectService core.ProjectService) *controller {
	return &controller{
		projectRepository: repository,
		assetRepository:   assetRepository,
		projectService:    projectService,
	}
}

func (p *controller) Create(ctx core.Context) error {
	var req CreateRequest
	if err := ctx.Bind(&req); err != nil {
		return echo.NewHTTPError(400, "unable to process request").WithInternal(err)
	}

	if err := core.V.Struct(req); err != nil {
		return echo.NewHTTPError(400, err.Error())
	}

	newProject := req.ToModel()

	// add the organization id
	newProject.OrganizationID = core.GetOrg(ctx).GetID()

	err := p.projectService.CreateProject(ctx, &newProject)
	if err != nil {
		return echo.NewHTTPError(409, "could not create project").WithInternal(err)
	}

	return ctx.JSON(200, newProject)
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
	m, err := authAdminClient.ListUser(client.IdentityAPIListIdentitiesRequest{}.Ids(members))

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

func (p *controller) Members(c core.Context) error {
	members, err := FetchMembersOfProject(c)
	if err != nil {
		return err
	}

	return c.JSON(200, members)
}

func (p *controller) InviteMembers(c core.Context) error {
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

func (p *controller) RemoveMember(c core.Context) error {
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

func (p *controller) ChangeRole(c core.Context) error {
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

func (p *controller) Delete(c core.Context) error {
	project := core.GetProject(c)

	err := p.projectRepository.Delete(nil, project.ID)
	if err != nil {
		return err
	}

	return c.NoContent(200)
}

func (p *controller) Read(c core.Context) error {
	// just get the project from the context
	project := core.GetProject(c)
	if project.IsExternalEntity() {
		// we need to fetch the assets for this project
		thirdpartyIntegration := core.GetThirdPartyIntegration(c)
		assets, err := thirdpartyIntegration.ListProjects(c, core.GetSession(c).GetUserID(), *project.ExternalEntityProviderID, *project.ExternalEntityID)
		if err != nil {
			return echo.NewHTTPError(500, "could not fetch assets for project").WithInternal(err)
		}
		// ensure the assets exist in the database
		toUpsert := make([]*models.Asset, 0, len(assets))
		for i := range assets {
			assets[i].ProjectID = project.ID
			toUpsert = append(toUpsert, &assets[i])
		}

		if err := p.assetRepository.Upsert(&toUpsert, &[]clause.Column{
			{Name: "external_entity_provider_id"},
			{Name: "external_entity_id"},
		}); err != nil {
			return echo.NewHTTPError(500, "could not upsert assets").WithInternal(err)
		}
		// set the assets on the project
		project.Assets = assets
	} else {
		// lets fetch the assets related to this project
		assets, err := p.assetRepository.GetByProjectID(project.ID)
		if err != nil {
			return err
		}

		project.Assets = assets
	}

	// lets fetch the members of the project
	members, err := FetchMembersOfProject(c)
	if err != nil {
		return err
	}

	resp := projectDetailsDTO{
		ProjectDTO: fromModel(project),
		Members:    members,
	}

	return c.JSON(200, resp)
}

func (p *controller) List(c core.Context) error {
	// get all projects the user has at least read access to - might be public projects as well
	projects, err := p.projectService.ListAllowedProjects(c)

	if err != nil {
		return err
	}

	return c.JSON(200, projects)
}

func (p *controller) Update(c core.Context) error {
	req := c.Request().Body
	defer req.Close()
	var patchRequest patchRequest
	err := json.NewDecoder(req).Decode(&patchRequest)
	if err != nil {
		return fmt.Errorf("could not decode request: %w", err)
	}

	project := core.GetProject(c)

	updated := patchRequest.applyToModel(&project)

	if project.Name == "" || project.Slug == "" {
		return echo.NewHTTPError(409, "projects with an empty name or an empty slug are not allowed").WithInternal(fmt.Errorf("projects with an empty name or an empty slug are not allowed"))
	}

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

func (o *controller) GetConfigFile(ctx core.Context) error {
	organization := core.GetOrg(ctx)
	project := core.GetProject(ctx)
	configID := ctx.Param("config-file")

	configContent, ok := project.ConfigFiles[configID]
	if !ok { //if we have no config files in this project we want to look in the corresponding organization
		configContent, ok = organization.ConfigFiles[configID]
		if !ok {
			return ctx.NoContent(404)
		}
		return ctx.JSON(200, configContent)
	}
	return ctx.JSON(200, configContent)
}
