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

package org

import (
	"encoding/json"
	"fmt"
	"maps"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/ory/client-go"

	"github.com/labstack/echo/v4"
)

type httpController struct {
	organizationRepository core.OrganizationRepository
	orgService             core.OrgService
	rbacProvider           core.RBACProvider
	projectService         core.ProjectService
	invitationRepository   core.InvitationRepository
}

func NewHTTPController(repository core.OrganizationRepository, orgService core.OrgService, rbacProvider core.RBACProvider, projectService core.ProjectService, invitationRepository core.InvitationRepository) *httpController {
	return &httpController{
		organizationRepository: repository,
		orgService:             orgService,
		rbacProvider:           rbacProvider,
		projectService:         projectService,
		invitationRepository:   invitationRepository,
	}
}

func (controller *httpController) Create(ctx core.Context) error {

	var req createRequest
	if err := ctx.Bind(&req); err != nil {
		return err
	}

	if err := core.V.Struct(req); err != nil {
		return echo.NewHTTPError(400, err.Error())
	}

	organization := req.toModel()
	if organization.Slug == "" {
		return echo.NewHTTPError(400, "slug is required")
	}

	err := controller.orgService.CreateOrganization(ctx, &organization)
	if err != nil {
		return err
	}

	return ctx.JSON(200, organization)
}

func (controller *httpController) Update(ctx core.Context) error {
	organization := core.GetOrg(ctx)
	members, err := FetchMembersOfOrganization(ctx)
	if err != nil {
		return echo.NewHTTPError(500, "could not get members of organization").WithInternal(err)
	}

	req := ctx.Request().Body

	defer req.Close()

	var patchRequest patchRequest
	err = json.NewDecoder(req).Decode(&patchRequest)
	if err != nil {
		return echo.NewHTTPError(400, "could not decode request").WithInternal(err)
	}

	updated := patchRequest.applyToModel(&organization)

	if organization.Name == "" || organization.Slug == "" {
		return echo.NewHTTPError(409, "organizations with an empty name or an empty slug are not allowed").WithInternal(fmt.Errorf("organizations with an empty name or an empty slug are not allowed"))
	}

	if updated {
		err := controller.organizationRepository.Update(nil, &organization)
		if err != nil {
			return echo.NewHTTPError(500, "could not update organization").WithInternal(err)
		}
	}

	resp := orgDetailsDTO{
		OrgDTO:  FromModel(organization),
		Members: members,
	}

	return ctx.JSON(200, resp)
}

func (controller *httpController) Delete(ctx core.Context) error {
	// get the id of the organization
	organizationID := core.GetOrg(ctx).GetID()

	// delete the organization
	err := controller.organizationRepository.Delete(nil, organizationID)
	if err != nil {
		return echo.NewHTTPError(500, "could not delete organization").WithInternal(err)
	}

	return ctx.NoContent(200)
}

func (controller *httpController) ContentTree(ctx core.Context) error {
	// get the whole content tree of the organization
	// this means all projects and their corresponding assets

	// get the organization from the context
	organization := core.GetOrg(ctx)

	ps, err := controller.projectService.ListAllowedProjects(
		ctx)
	if err != nil {
		return echo.NewHTTPError(500, "could not get projects").WithInternal(err)
	}

	projects := utils.Map(ps, func(p models.Project) string {
		return p.ID.String()
	})

	return ctx.JSON(200, controller.organizationRepository.ContentTree(organization.GetID(), projects))
}

func (controller *httpController) AcceptInvitation(ctx core.Context) error {
	// get the code and the org id from the path
	var req acceptInvitationRequest
	if err := ctx.Bind(&req); err != nil {
		return echo.NewHTTPError(400, "could not bind request").WithInternal(err)
	}

	if err := core.V.Struct(req); err != nil {
		return echo.NewHTTPError(400, err.Error())
	}

	code := req.Code

	// find the invitation
	invitation, err := controller.invitationRepository.FindByCode(code)
	if err != nil {
		return echo.NewHTTPError(404, "invitation not found").WithInternal(err)
	}

	// get the user id from the session
	userID := core.GetSession(ctx).GetUserID()
	// get the email of that user
	// get the auth admin client from the context
	authAdminClient := core.GetAuthAdminClient(ctx)
	// fetch the users from the auth service
	m, err := authAdminClient.GetIdentity(ctx.Request().Context(), userID)
	if err != nil {
		return echo.NewHTTPError(500, "could not get user").WithInternal(err)
	}

	email := m.Traits.(map[string]any)["email"].(string)
	if email != invitation.Email {
		return echo.NewHTTPError(401, "email does not match")
	}

	// get the rbac from the context
	rbac := controller.rbacProvider.GetDomainRBAC((invitation.OrganizationID).String())
	// grant the user the role of member
	err = rbac.GrantRole(userID, "member")
	if err != nil {
		return echo.NewHTTPError(500, "could not grant role").WithInternal(err)
	}

	// delete the invitation
	err = controller.invitationRepository.Delete(nil, invitation.ID)
	if err != nil {
		return echo.NewHTTPError(500, "could not delete invitation").WithInternal(err)
	}

	return ctx.JSON(200,
		FromModel(invitation.Organization),
	)
}

func (controller *httpController) InviteMember(ctx core.Context) error {
	// we expect an email address in the request.
	// afterwards we create a new invitation model and a code corresponding to the invitation
	var req inviteRequest
	if err := ctx.Bind(&req); err != nil {
		return err
	}

	if err := core.V.Struct(req); err != nil {
		return echo.NewHTTPError(400, err.Error())
	}

	// get the organization from the context
	organization := core.GetOrg(ctx)

	model := models.Invitation{
		OrganizationID: organization.GetID(),
		Email:          req.Email,
		Code:           uuid.NewString(),
	}

	// save the model
	err := controller.invitationRepository.Save(nil, &model)
	if err != nil {
		return echo.NewHTTPError(500, "could not save invitation").WithInternal(err)
	}

	return ctx.JSON(200, model) // for now return the model - later on we should send an email
}

func (controller *httpController) ChangeRole(ctx core.Context) error {
	// get the user id from the request
	var req changeRoleRequest

	userID := ctx.Param("userID")
	if userID == "" {
		return echo.NewHTTPError(400, "userID is required")
	}

	if err := ctx.Bind(&req); err != nil {
		return echo.NewHTTPError(400, "could not bind request").WithInternal(err)
	}

	if err := core.V.Struct(req); err != nil {
		return echo.NewHTTPError(400, err.Error())
	}

	// get the rbac from the context
	rbac := core.GetRBAC(ctx)

	//
	rbac.RevokeRole(userID, "member") // nolint:errcheck// we do not care if the user is not a member
	rbac.RevokeRole(userID, "admin")  // nolint:errcheck// we do not care if the user is not a member

	if err := rbac.GrantRole(userID, core.Role(req.Role)); err != nil {
		return echo.NewHTTPError(500, "could not grant role").WithInternal(err)
	}

	return ctx.NoContent(200)
}

func (controller *httpController) RemoveMember(ctx core.Context) error {
	// get the user id from the request
	userID := ctx.Param("userID")

	// get the rbac from the context
	rbac := core.GetRBAC(ctx)

	//
	rbac.RevokeRole(userID, "member") // nolint:errcheck// we do not care if the user is not a member
	rbac.RevokeRole(userID, "admin")  // nolint:errcheck// we do not care if the user is not an admin

	// remove member from all projects
	projects, err := controller.projectService.ListProjectsByOrganizationID(core.GetOrg(ctx).GetID())
	if err != nil {
		return echo.NewHTTPError(500, "could not get projects").WithInternal(err)
	}

	for _, project := range projects {
		rbac.RevokeRoleInProject(userID, "member", project.ID.String()) // nolint:errcheck// we do not care if the user is not a member
		rbac.RevokeRoleInProject(userID, "admin", project.ID.String())  // nolint:errcheck// we do not care if the user is not an admin
	}

	return ctx.NoContent(200)
}

func FetchMembersOfOrganization(ctx core.Context) ([]core.User, error) {
	// get all members from the organization
	organization := core.GetOrg(ctx)
	accessControl := core.GetRBAC(ctx)

	members, err := accessControl.GetAllMembersOfOrganization()

	if err != nil {
		return nil, err
	}

	users := make([]core.User, 0, len(members))
	if len(members) > 0 {
		// get the auth admin client from the context
		authAdminClient := core.GetAuthAdminClient(ctx)
		// fetch the users from the auth service
		m, err := authAdminClient.ListUser(client.IdentityAPIListIdentitiesRequest{}.Ids(members))
		if err != nil {
			return nil, err
		}

		// get the roles for the members
		errGroup := utils.ErrGroup[map[string]core.Role](10)
		for _, member := range m {
			errGroup.Go(func() (map[string]core.Role, error) {
				role, err := accessControl.GetDomainRole(member.Id)
				if err != nil {
					return map[string]core.Role{member.Id: core.RoleUnknown}, nil
				}
				return map[string]core.Role{member.Id: role}, nil
			})
		}

		roles, err := errGroup.WaitAndCollect()
		if err != nil {
			return nil, err
		}

		roleMap := utils.Reduce(roles, func(acc map[string]core.Role, r map[string]core.Role) map[string]core.Role {
			maps.Copy(acc, r)
			return acc
		}, make(map[string]core.Role))

		for _, member := range m {
			nameMap := member.Traits.(map[string]any)["name"].(map[string]any)
			var name string
			if nameMap != nil {
				if nameMap["first"] != nil {
					name += nameMap["first"].(string)
				}
				if nameMap["last"] != nil {
					name += " " + nameMap["last"].(string)
				}
			}

			users = append(users, core.User{
				ID:   member.Id,
				Name: name,
				Role: string(roleMap[member.Id]),
			})
		}
	}

	// fetch all members from third party integrations
	thirdPartyIntegrations := core.GetThirdPartyIntegration(ctx)
	users = append(users, thirdPartyIntegrations.GetUsers(organization)...)
	return users, nil
}

func (controller *httpController) Members(ctx core.Context) error {
	users, err := FetchMembersOfOrganization(ctx)
	if err != nil {
		return echo.NewHTTPError(500, "could not get members of organization").WithInternal(err)
	}

	return ctx.JSON(200, users)
}

func (controller *httpController) Read(ctx core.Context) error {
	// get the organization from the context
	organization := core.GetOrg(ctx)
	// fetch the regular members of the current organization
	members, err := FetchMembersOfOrganization(ctx)

	if err != nil {
		return echo.NewHTTPError(500, "could not get members of organization").WithInternal(err)
	}

	resp := orgDetailsDTO{
		OrgDTO:  FromModel(organization),
		Members: members,
	}

	return ctx.JSON(200, resp)
}

func (controller *httpController) List(ctx core.Context) error {
	// get all organizations the user has access to
	userID := core.GetSession(ctx).GetUserID()

	domains, err := controller.rbacProvider.DomainsOfUser(userID)

	if err != nil {
		return echo.NewHTTPError(500, "could not get domains of user").WithInternal(err)
	}

	// transform the domains to organization ids
	organizationIDs := make([]uuid.UUID, len(domains))
	for i, domain := range domains {
		id, err := uuid.Parse(domain)
		if err != nil {
			continue
		}
		organizationIDs[i] = id
	}

	// get the organizations from the database
	organizations, err := controller.organizationRepository.List(organizationIDs)
	if err != nil {
		return echo.NewHTTPError(500, "could not read organizations").WithInternal(err)
	}

	return ctx.JSON(200, organizations)
}

func (controller *httpController) Metrics(ctx core.Context) error {
	owner, err := core.GetRBAC(ctx).GetOwnerOfOrganization()
	if err != nil {
		return echo.NewHTTPError(500, "could not get owner of organization").WithInternal(err)
	}
	return ctx.JSON(200, map[string]string{"ownerId": owner})
}

func (controller *httpController) GetConfigFile(ctx core.Context) error {
	organization := core.GetOrg(ctx)
	configID := ctx.Param("config-file")

	configContent, ok := organization.ConfigFiles[configID]
	if !ok {
		return ctx.NoContent(404)
	}
	return ctx.JSON(200, configContent)
}
