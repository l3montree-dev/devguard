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

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/services"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/l3montree-dev/devguard/utils"

	"github.com/labstack/echo/v4"
)

type OrgController struct {
	organizationRepository shared.OrganizationRepository
	orgService             shared.OrgService
	rbacProvider           shared.RBACProvider
	projectService         shared.ProjectService
	invitationRepository   shared.InvitationRepository
}

func NewOrganizationController(repository shared.OrganizationRepository, orgService shared.OrgService, rbacProvider shared.RBACProvider, projectService shared.ProjectService, invitationRepository shared.InvitationRepository) *OrgController {
	return &OrgController{
		organizationRepository: repository,
		orgService:             orgService,
		rbacProvider:           rbacProvider,
		projectService:         projectService,
		invitationRepository:   invitationRepository,
	}
}

func (controller *OrgController) Create(ctx shared.Context) error {

	var req dtos.OrgCreateRequest
	if err := ctx.Bind(&req); err != nil {
		return err
	}

	if err := shared.V.Struct(req); err != nil {
		return echo.NewHTTPError(400, fmt.Sprintf("could not validate request: %s", err.Error()))
	}

	organization := transformer.OrgCreateRequestToModel(req)
	if organization.Slug == "" {
		return echo.NewHTTPError(400, "slug is required")
	}

	err := controller.orgService.CreateOrganization(ctx, &organization)
	if err != nil {
		return err
	}

	return ctx.JSON(200, organization)
}

func (controller *OrgController) Update(ctx shared.Context) error {
	organization := shared.GetOrg(ctx)
	members, err := FetchMembersOfOrganization(ctx)
	if err != nil {
		return echo.NewHTTPError(500, "could not get members of organization").WithInternal(err)
	}

	req := ctx.Request().Body

	defer req.Close()

	var patchRequest dtos.OrgPatchRequest
	err = json.NewDecoder(req).Decode(&patchRequest)
	if err != nil {
		return echo.NewHTTPError(400, "could not decode request").WithInternal(err)
	}

	updated := transformer.ApplyOrgPatchRequestToModel(patchRequest, &organization)

	if organization.Name == "" || organization.Slug == "" {
		return echo.NewHTTPError(409, "organizations with an empty name or an empty slug are not allowed").WithInternal(fmt.Errorf("organizations with an empty name or an empty slug are not allowed"))
	}

	if updated {
		err := controller.organizationRepository.Update(nil, &organization)
		if err != nil {
			return echo.NewHTTPError(500, "could not update organization").WithInternal(err)
		}
	}

	resp := dtos.OrgDetailsDTO{
		OrgDTO:  transformer.OrgDTOFromModel(organization),
		Members: members,
	}

	return ctx.JSON(200, resp)
}

func (controller *OrgController) Delete(ctx shared.Context) error {
	// get the id of the organization
	organizationID := shared.GetOrg(ctx).GetID()

	// delete the organization
	err := controller.organizationRepository.Delete(nil, organizationID)
	if err != nil {
		return echo.NewHTTPError(500, "could not delete organization").WithInternal(err)
	}

	return ctx.NoContent(200)
}

func (controller *OrgController) ContentTree(ctx shared.Context) error {
	// get the whole content tree of the organization
	// this means all projects and their corresponding assets

	// get the organization from the context
	organization := shared.GetOrg(ctx)

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

func (controller *OrgController) AcceptInvitation(ctx shared.Context) error {
	// get the code and the org id from the path
	var req dtos.AcceptInvitationRequest
	if err := ctx.Bind(&req); err != nil {
		return echo.NewHTTPError(400, "could not bind request").WithInternal(err)
	}

	if err := shared.V.Struct(req); err != nil {
		return echo.NewHTTPError(400, fmt.Sprintf("could not validate request: %s", err.Error()))
	}

	code := req.Code

	// find the invitation
	invitation, err := controller.invitationRepository.FindByCode(code)
	if err != nil {
		return echo.NewHTTPError(404, "invitation not found").WithInternal(err)
	}

	// get the user id from the session
	userID := shared.GetSession(ctx).GetUserID()
	// get the email of that user
	// get the auth admin client from the context
	authAdminClient := shared.GetAuthAdminClient(ctx)
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
		transformer.OrgDTOFromModel(invitation.Organization),
	)
}

func (controller *OrgController) InviteMember(ctx shared.Context) error {
	// we expect an email address in the request.
	// afterwards we create a new invitation model and a code corresponding to the invitation
	var req dtos.InviteRequest
	if err := ctx.Bind(&req); err != nil {
		return err
	}

	if err := shared.V.Struct(req); err != nil {
		return echo.NewHTTPError(400, fmt.Sprintf("could not validate request: %s", err.Error()))
	}

	// get the organization from the context
	organization := shared.GetOrg(ctx)

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

func (controller *OrgController) ChangeRole(ctx shared.Context) error {
	// get the user id from the request
	var req dtos.OrgChangeRoleRequest

	userID := ctx.Param("userID")
	if userID == "" {
		return echo.NewHTTPError(400, "userID is required")
	}
	currentUserID := shared.GetSession(ctx).GetUserID()
	if userID == currentUserID {
		return echo.NewHTTPError(400, "you cannot change your own role")
	}

	if err := ctx.Bind(&req); err != nil {
		return echo.NewHTTPError(400, "could not bind request").WithInternal(err)
	}

	if err := shared.V.Struct(req); err != nil {
		return echo.NewHTTPError(400, fmt.Sprintf("could not validate request: %s", err.Error()))
	}

	// get the rbac from the context
	rbac := shared.GetRBAC(ctx)

	//
	rbac.RevokeRole(userID, "member") // nolint:errcheck// we do not care if the user is not a member
	rbac.RevokeRole(userID, "admin")  // nolint:errcheck// we do not care if the user is not a member

	if err := rbac.GrantRole(userID, shared.Role(req.Role)); err != nil {
		return echo.NewHTTPError(500, "could not grant role").WithInternal(err)
	}

	return ctx.NoContent(200)
}

func (controller *OrgController) RemoveMember(ctx shared.Context) error {
	// get the user id from the request
	userID := ctx.Param("userID")

	// get the rbac from the context
	rbac := shared.GetRBAC(ctx)

	//
	rbac.RevokeRole(userID, "member") // nolint:errcheck// we do not care if the user is not a member
	rbac.RevokeRole(userID, "admin")  // nolint:errcheck// we do not care if the user is not an admin

	// remove member from all projects
	projects, err := controller.projectService.ListProjectsByOrganizationID(shared.GetOrg(ctx).GetID())
	if err != nil {
		return echo.NewHTTPError(500, "could not get projects").WithInternal(err)
	}

	for _, project := range projects {
		rbac.RevokeRoleInProject(userID, "member", project.ID.String()) // nolint:errcheck// we do not care if the user is not a member
		rbac.RevokeRoleInProject(userID, "admin", project.ID.String())  // nolint:errcheck// we do not care if the user is not an admin
	}

	return ctx.NoContent(200)
}

func (controller *OrgController) Metrics(ctx shared.Context) error {
	owner, err := shared.GetRBAC(ctx).GetOwnerOfOrganization()
	if err != nil {
		return echo.NewHTTPError(500, "could not get owner of organization").WithInternal(err)
	}
	return ctx.JSON(200, map[string]string{"ownerId": owner})
}

func (controller *OrgController) GetConfigFile(ctx shared.Context) error {
	organization := shared.GetOrg(ctx)
	configID := ctx.Param("config-file")

	configContent, ok := organization.ConfigFiles[configID]
	if !ok {
		return ctx.NoContent(404)
	}
	return ctx.JSON(200, configContent)
}

func (controller *OrgController) Members(ctx shared.Context) error {
	users, err := services.FetchMembersOfOrganization(ctx)
	if err != nil {
		return echo.NewHTTPError(500, "could not get members of organization").WithInternal(err)
	}

	return ctx.JSON(200, users)
}

func (controller *OrgController) Read(ctx shared.Context) error {
	// get the organization from the context
	organization := shared.GetOrg(ctx)
	// fetch the regular members of the current organization
	members, err := services.FetchMembersOfOrganization(ctx)

	if err != nil {
		return echo.NewHTTPError(500, "could not get members of organization").WithInternal(err)
	}

	resp := dtos.OrgDetailsDTO{
		OrgDTO:  transformer.OrgDTOFromModel(organization),
		Members: members,
	}

	return ctx.JSON(200, resp)
}

func (controller *OrgController) List(ctx shared.Context) error {
	// get all organizations the user has access to
	userID := shared.GetSession(ctx).GetUserID()

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
