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

package controllers

import (
	"encoding/json"
	"fmt"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/labstack/echo/v4"
	"github.com/ory/client-go"
)

type ProjectController struct {
	projectRepository shared.ProjectRepository
	assetRepository   shared.AssetRepository
	projectService    shared.ProjectService
	webhookRepository shared.WebhookIntegrationRepository
}

func NewProjectController(repository shared.ProjectRepository, assetRepository shared.AssetRepository, projectService shared.ProjectService, webhookRepository shared.WebhookIntegrationRepository) *ProjectController {
	return &ProjectController{
		projectRepository: repository,
		assetRepository:   assetRepository,
		projectService:    projectService,
		webhookRepository: webhookRepository,
	}
}

// @Summary Create project
// @Security CookieAuth
// @Security ApiKeyAuth
// @Param organization path string true "Organization slug"
// @Param body body dtos.ProjectCreateRequest true "Request body"
// @Success 200 {object} models.Project
// @Router /organizations/{organization}/projects [post]
func (ProjectController *ProjectController) Create(ctx shared.Context) error {
	var req dtos.ProjectCreateRequest
	if err := ctx.Bind(&req); err != nil {
		return echo.NewHTTPError(400, "unable to process request").WithInternal(err)
	}

	if err := shared.V.Struct(req); err != nil {
		return echo.NewHTTPError(400, fmt.Sprintf("could not validate request: %s", err.Error()))
	}

	newProject := transformer.ProjectCreateRequestToModel(req)

	// add the organization id
	newProject.OrganizationID = shared.GetOrg(ctx).GetID()

	err := ProjectController.projectService.CreateProject(ctx, &newProject)
	if err != nil {
		return echo.NewHTTPError(409, "could not create project").WithInternal(err)
	}

	return ctx.JSON(200, newProject)
}

func FetchMembersOfProject(ctx shared.Context) ([]dtos.UserDTO, error) {
	project := shared.GetProject(ctx)
	// get rbac
	rbac := shared.GetRBAC(ctx)

	members, err := rbac.GetAllMembersOfProject(project.ID.String())
	if err != nil {
		return nil, echo.NewHTTPError(500, "could not get members of project").WithInternal(err)
	}
	if len(members) == 0 {
		return []dtos.UserDTO{}, nil
	}
	// get the auth admin client from the context
	authAdminClient := shared.GetAuthAdminClient(ctx)
	// fetch the users from the auth service
	m, err := authAdminClient.ListUser(client.IdentityAPIListIdentitiesRequest{}.Ids(members))

	if err != nil {
		return nil, echo.NewHTTPError(500, "could not get members").WithInternal(err)
	}

	users := utils.Map(m, func(i client.Identity) dtos.UserDTO {
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
			return dtos.UserDTO{
				ID:   i.Id,
				Name: name,
			}
		}
		return dtos.UserDTO{
			ID:   i.Id,
			Name: name,
			Role: string(role),
		}
	})

	return users, nil
}

// @Summary List project members
// @Security CookieAuth
// @Security ApiKeyAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Success 200 {array} dtos.UserDTO
// @Router /organizations/{organization}/projects/{projectSlug}/members [get]
func (ProjectController *ProjectController) Members(c shared.Context) error {
	members, err := FetchMembersOfProject(c)
	if err != nil {
		return err
	}

	return c.JSON(200, members)
}

// @Summary Invite members to project
// @Security CookieAuth
// @Security ApiKeyAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param body body dtos.ProjectInviteRequest true "Request body"
// @Success 200
// @Router /organizations/{organization}/projects/{projectSlug}/members [post]
func (ProjectController *ProjectController) InviteMembers(c shared.Context) error {
	project := shared.GetProject(c)

	// get rbac
	rbac := shared.GetRBAC(c)

	var req dtos.ProjectInviteRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(400, "unable to process request").WithInternal(err)
	}

	if err := shared.V.Struct(req); err != nil {
		return echo.NewHTTPError(400, fmt.Sprintf("could not validate request: %s", err.Error()))
	}

	members, err := rbac.GetAllMembersOfOrganization()
	if err != nil {
		return echo.NewHTTPError(500, "could not get members of organization").WithInternal(err)
	}

	for _, newMemberID := range req.Ids {
		if !utils.Contains(members, newMemberID) {
			return echo.NewHTTPError(400, "user is not a member of the organization")
		}

		if err := rbac.GrantRoleInProject(newMemberID, shared.RoleMember, project.ID.String()); err != nil {
			return err
		}
	}
	return c.NoContent(200)
}

func (ProjectController *ProjectController) RemoveMember(c shared.Context) error {
	project := shared.GetProject(c)

	// get rbac
	rbac := shared.GetRBAC(c)

	userID := c.Param("userID")
	if userID == "" {
		return echo.NewHTTPError(400, "userID is required")
	}

	// revoke admin and member role
	rbac.RevokeRoleInProject(userID, shared.RoleAdmin, project.ID.String())  // nolint:errcheck // we don't care if the user is not an admin
	rbac.RevokeRoleInProject(userID, shared.RoleMember, project.ID.String()) // nolint:errcheck // we don't care if the user is not a member

	return c.NoContent(200)
}

func (ProjectController *ProjectController) ChangeRole(c shared.Context) error {
	project := shared.GetProject(c)

	// get rbac
	rbac := shared.GetRBAC(c)

	var req dtos.ProjectChangeRoleRequest

	userID := c.Param("userID")
	if userID == "" {
		return echo.NewHTTPError(400, "userID is required")
	}

	if userID == shared.GetSession(c).GetUserID() {
		return echo.NewHTTPError(400, "cannot change your own role")
	}

	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(400, "unable to process request").WithInternal(err)
	}

	if err := shared.V.Struct(req); err != nil {
		return echo.NewHTTPError(400, fmt.Sprintf("could not validate request: %s", err.Error()))
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

	rbac.RevokeRoleInProject(userID, shared.RoleAdmin, project.ID.String()) // nolint:errcheck // we don't care if the user is not an admin

	rbac.RevokeRoleInProject(userID, shared.RoleMember, project.ID.String()) // nolint:errcheck // we don't care if the user is not a member

	if err := rbac.GrantRoleInProject(userID, shared.Role(req.Role), project.ID.String()); err != nil {
		return err
	}

	return c.NoContent(200)
}

// @Summary Delete project
// @Security CookieAuth
// @Security ApiKeyAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Success 200
// @Router /organizations/{organization}/projects/{projectSlug} [delete]
func (ProjectController *ProjectController) Delete(c shared.Context) error {
	project := shared.GetProject(c)

	err := ProjectController.projectRepository.Delete(nil, project.ID)
	if err != nil {
		return err
	}

	return c.NoContent(200)
}

// @Summary Get project details
// @Security CookieAuth
// @Security ApiKeyAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Success 200 {object} dtos.ProjectDetailsDTO
// @Router /organizations/{organization}/projects/{projectSlug} [get]
func (ProjectController *ProjectController) Read(c shared.Context) error {
	// just get the project from the context
	project := shared.GetProject(c)
	rbac := shared.GetRBAC(c)
	allowedAssetIDs, err := rbac.GetAllAssetsForUser(shared.GetSession(c).GetUserID())
	if err != nil {
		return err
	}
	// lets fetch the assets related to this project
	assets, err := ProjectController.assetRepository.GetAllowedAssetsByProjectID(allowedAssetIDs, project.ID)
	if err != nil {
		return err
	}

	project.Assets = assets

	// lets fetch the members of the project
	members, err := FetchMembersOfProject(c)
	if err != nil {
		return err
	}

	//get the webhooks
	webhooks, err := ProjectController.getWebhooks(c)
	if err != nil {
		return echo.NewHTTPError(500, "could not fetch webhooks").WithInternal(err)
	}

	resp := dtos.ProjectDetailsDTO{
		ProjectDTO: transformer.ProjectModelToDTO(project),
		Members:    members,
		Webhooks:   webhooks,
	}

	return c.JSON(200, resp)
}

func (ProjectController *ProjectController) getWebhooks(c shared.Context) ([]dtos.WebhookIntegrationDTO, error) {

	orgID := shared.GetOrg(c).GetID()
	projectID := shared.GetProject(c).GetID()

	webhooks, err := ProjectController.webhookRepository.GetProjectWebhooks(orgID, projectID)
	if err != nil {
		return nil, fmt.Errorf("could not fetch webhooks: %w", err)
	}

	return utils.Map(webhooks, func(w models.WebhookIntegration) dtos.WebhookIntegrationDTO {
		return dtos.WebhookIntegrationDTO{
			ID:          w.ID.String(),
			Name:        *w.Name,
			Description: *w.Description,
			URL:         w.URL,
			SbomEnabled: w.SbomEnabled,
			VulnEnabled: w.VulnEnabled,
		}
	}), nil
}

// @Summary List projects
// @Security CookieAuth
// @Security ApiKeyAuth
// @Param organization path string true "Organization slug"
// @Success 200 {array} models.Project
// @Router /organizations/{organization}/projects [get]
func (ProjectController *ProjectController) List(c shared.Context) error {
	// get all projects the user has at least read access to - might be public projects as well
	projects, err := ProjectController.projectService.ListAllowedProjectsPaged(c)

	if err != nil {
		return err
	}

	return c.JSON(200, projects)
}

// @Summary Update project
// @Security CookieAuth
// @Security ApiKeyAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param body body dtos.ProjectPatchRequest true "Request body"
// @Success 200 {object} dtos.ProjectDetailsDTO
// @Router /organizations/{organization}/projects/{projectSlug} [patch]
func (ProjectController *ProjectController) Update(c shared.Context) error {
	req := c.Request().Body
	defer req.Close()
	var patchRequest dtos.ProjectPatchRequest
	err := json.NewDecoder(req).Decode(&patchRequest)
	if err != nil {
		return fmt.Errorf("could not decode request: %w", err)
	}

	project := shared.GetProject(c)

	updated := transformer.ApplyProjectPatchRequestToModel(patchRequest, &project)

	if project.Name == "" || project.Slug == "" {
		return echo.NewHTTPError(409, "projects with an empty name or an empty slug are not allowed").WithInternal(fmt.Errorf("projects with an empty name or an empty slug are not allowed"))
	}

	if updated {
		err = ProjectController.projectRepository.Update(nil, &project)
		if err != nil {
			return fmt.Errorf("could not update project: %w", err)
		}
	}
	// get rbac
	rbac := shared.GetRBAC(c)
	allowedAssetIDs, err := rbac.GetAllAssetsForUser(shared.GetSession(c).GetUserID())
	if err != nil {
		return err
	}

	// lets fetch the assets related to this project
	assets, err := ProjectController.assetRepository.GetAllowedAssetsByProjectID(allowedAssetIDs, project.ID)
	if err != nil {
		return err
	}

	// lets fetch the members of the project
	members, err := FetchMembersOfProject(c)
	if err != nil {
		return err
	}

	project.Assets = assets

	resp := dtos.ProjectDetailsDTO{
		ProjectDTO: transformer.ProjectModelToDTO(project),
		Members:    members,
	}
	return c.JSON(200, resp)
}

func (ProjectController *ProjectController) GetConfigFile(ctx shared.Context) error {
	organization := shared.GetOrg(ctx)
	project := shared.GetProject(ctx)
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
