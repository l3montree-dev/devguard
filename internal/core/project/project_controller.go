// Copyright (C) 2023 Tim Bastin, l3montree GmbH
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

	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/labstack/echo/v4"
	"github.com/ory/client-go"
)

type controller struct {
	projectRepository core.ProjectRepository
	assetRepository   core.AssetRepository
	projectService    core.ProjectService
	webhookRepository core.WebhookIntegrationRepository
}

func NewHTTPController(repository core.ProjectRepository, assetRepository core.AssetRepository, projectService core.ProjectService, webhookRepository core.WebhookIntegrationRepository) *controller {
	return &controller{
		projectRepository: repository,
		assetRepository:   assetRepository,
		projectService:    projectService,
		webhookRepository: webhookRepository,
	}
}

func (projectController *controller) Create(ctx core.Context) error {
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

	err := projectController.projectService.CreateProject(ctx, &newProject)
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
			Role: string(role),
		}
	})

	return users, nil
}

func (projectController *controller) Members(c core.Context) error {
	members, err := FetchMembersOfProject(c)
	if err != nil {
		return err
	}

	return c.JSON(200, members)
}

func (projectController *controller) InviteMembers(c core.Context) error {
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

	for _, newMemberID := range req.Ids {
		if !utils.Contains(members, newMemberID) {
			return echo.NewHTTPError(400, "user is not a member of the organization")
		}

		if err := rbac.GrantRoleInProject(newMemberID, core.RoleMember, project.ID.String()); err != nil {
			return err
		}
	}
	return c.NoContent(200)
}

func (projectController *controller) RemoveMember(c core.Context) error {
	project := core.GetProject(c)

	// get rbac
	rbac := core.GetRBAC(c)

	userID := c.Param("userID")
	if userID == "" {
		return echo.NewHTTPError(400, "userID is required")
	}

	// revoke admin and member role
	rbac.RevokeRoleInProject(userID, core.RoleAdmin, project.ID.String())  // nolint:errcheck // we don't care if the user is not an admin
	rbac.RevokeRoleInProject(userID, core.RoleMember, project.ID.String()) // nolint:errcheck // we don't care if the user is not a member

	return c.NoContent(200)
}

func (projectController *controller) ChangeRole(c core.Context) error {
	project := core.GetProject(c)

	// get rbac
	rbac := core.GetRBAC(c)

	var req changeRoleRequest

	userID := c.Param("userID")
	if userID == "" {
		return echo.NewHTTPError(400, "userID is required")
	}

	if userID == core.GetSession(c).GetUserID() {
		return echo.NewHTTPError(400, "cannot change your own role")
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

	if !utils.Contains(members, userID) {
		return echo.NewHTTPError(400, "user is not a member of the organization")
	}

	rbac.RevokeRoleInProject(userID, core.RoleAdmin, project.ID.String()) // nolint:errcheck // we don't care if the user is not an admin

	rbac.RevokeRoleInProject(userID, core.RoleMember, project.ID.String()) // nolint:errcheck // we don't care if the user is not a member

	if err := rbac.GrantRoleInProject(userID, core.Role(req.Role), project.ID.String()); err != nil {
		return err
	}

	return c.NoContent(200)
}

func (projectController *controller) Delete(c core.Context) error {
	project := core.GetProject(c)

	err := projectController.projectRepository.Delete(nil, project.ID)
	if err != nil {
		return err
	}

	return c.NoContent(200)
}

func (projectController *controller) Read(c core.Context) error {
	// just get the project from the context
	project := core.GetProject(c)
	rbac := core.GetRBAC(c)
	allowedAssetIDs, err := rbac.GetAllAssetsForUser(core.GetSession(c).GetUserID())
	if err != nil {
		return err
	}
	// lets fetch the assets related to this project
	assets, err := projectController.assetRepository.GetAllowedAssetsByProjectID(allowedAssetIDs, project.ID)
	if err != nil {
		return err
	}

	for _, asset := range assets {
		slog.Debug("asset in project", "assetID", asset.ID.String(), "assetName", asset.Name)
	}

	project.Assets = assets

	// lets fetch the members of the project
	members, err := FetchMembersOfProject(c)
	if err != nil {
		return err
	}

	//get the webhooks
	webhooks, err := projectController.getWebhooks(c)
	if err != nil {
		return echo.NewHTTPError(500, "could not fetch webhooks").WithInternal(err)
	}

	resp := projectDetailsDTO{
		ProjectDTO: FromModel(project),
		Members:    members,
		Webhooks:   webhooks,
	}

	return c.JSON(200, resp)
}

func (projectController *controller) getWebhooks(c core.Context) ([]common.WebhookIntegrationDTO, error) {

	orgID := core.GetOrg(c).GetID()
	projectID := core.GetProject(c).GetID()

	webhooks, err := projectController.webhookRepository.GetProjectWebhooks(orgID, projectID)
	if err != nil {
		return nil, fmt.Errorf("could not fetch webhooks: %w", err)
	}

	return utils.Map(webhooks, func(w models.WebhookIntegration) common.WebhookIntegrationDTO {
		return common.WebhookIntegrationDTO{
			ID:          w.ID.String(),
			Name:        *w.Name,
			Description: *w.Description,
			URL:         w.URL,
			SbomEnabled: w.SbomEnabled,
			VulnEnabled: w.VulnEnabled,
		}
	}), nil
}

func (projectController *controller) List(c core.Context) error {
	// get all projects the user has at least read access to - might be public projects as well
	projects, err := projectController.projectService.ListAllowedProjectsPaged(c)

	if err != nil {
		return err
	}

	return c.JSON(200, projects)
}

func (projectController *controller) Update(c core.Context) error {
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
		err = projectController.projectRepository.Update(nil, &project)
		if err != nil {
			return fmt.Errorf("could not update project: %w", err)
		}
	}
	// get rbac
	rbac := core.GetRBAC(c)
	allowedAssetIDs, err := rbac.GetAllAssetsForUser(core.GetSession(c).GetUserID())

	// lets fetch the assets related to this project
	assets, err := projectController.assetRepository.GetAllowedAssetsByProjectID(allowedAssetIDs, project.ID)
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
		ProjectDTO: FromModel(project),
		Members:    members,
	}
	return c.JSON(200, resp)
}

func (projectController *controller) GetConfigFile(ctx core.Context) error {
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
