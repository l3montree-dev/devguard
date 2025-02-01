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

package org

import (
	"encoding/json"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/accesscontrol"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
	"github.com/l3montree-dev/devguard/internal/obj"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/ory/client-go"

	"github.com/labstack/echo/v4"
)

type repository interface {
	repositories.Repository[uuid.UUID, models.Org, core.DB]
	// ReadBySlug reads an organization by its slug
	ReadBySlug(slug string) (models.Org, error)
	Update(tx core.DB, organization *models.Org) error
	ContentTree(orgID uuid.UUID, projects []string) []obj.ContentTreeElement
}

type invitationRepository interface {
	Save(tx core.DB, invitation *models.Invitation) error
	FindByCode(code string) (models.Invitation, error)
	Delete(tx core.DB, id uuid.UUID) error
}

type projectService interface {
	ListAllowedProjects(c core.Context) ([]models.Project, error)
}
type httpController struct {
	organizationRepository repository
	rbacProvider           accesscontrol.RBACProvider
	projectService         projectService
	invitationRepository   invitationRepository
}

func NewHttpController(repository repository, rbacProvider accesscontrol.RBACProvider, projectService projectService, invitationRepository invitationRepository) *httpController {
	return &httpController{
		organizationRepository: repository,
		rbacProvider:           rbacProvider,
		projectService:         projectService,
		invitationRepository:   invitationRepository,
	}
}

func (o *httpController) Create(c core.Context) error {

	var req createRequest
	if err := c.Bind(&req); err != nil {
		return err
	}

	if err := core.V.Struct(req); err != nil {
		return echo.NewHTTPError(400, err.Error())
	}

	org := req.toModel()

	err := o.organizationRepository.Create(nil, &org)
	if err != nil {
		return echo.NewHTTPError(500, "could not create organization").WithInternal(err)
	}

	if err = o.bootstrapOrg(c, org); err != nil {
		return echo.NewHTTPError(500, "could not bootstrap organization").WithInternal(err)
	}

	return c.JSON(200, org)
}

func (o *httpController) bootstrapOrg(c core.Context, organization models.Org) error {
	// create the permissions for the organization
	rbac := o.rbacProvider.GetDomainRBAC(organization.ID.String())
	userId := core.GetSession(c).GetUserID()

	if err := rbac.GrantRole(userId, "owner"); err != nil {
		return err
	}
	if err := rbac.InheritRole("owner", "admin"); err != nil { // an owner is an admin
		return err
	}
	if err := rbac.InheritRole("admin", "member"); err != nil { // an admin is a member
		return err
	}

	if err := rbac.AllowRole("owner", "organization", []accesscontrol.Action{
		accesscontrol.ActionDelete,
	}); err != nil {
		return err
	}

	if err := rbac.AllowRole("admin", "organization", []accesscontrol.Action{
		accesscontrol.ActionUpdate,
	}); err != nil {
		return err
	}

	if err := rbac.AllowRole("admin", "project", []accesscontrol.Action{
		accesscontrol.ActionCreate,
		accesscontrol.ActionRead, // listing all projects
		accesscontrol.ActionUpdate,
		accesscontrol.ActionDelete,
	}); err != nil {
		return err
	}

	if err := rbac.AllowRole("member", "organization", []accesscontrol.Action{
		accesscontrol.ActionRead,
	}); err != nil {
		return err
	}

	c.Set("rbac", rbac)
	return nil
}

func (o *httpController) Update(ctx core.Context) error {
	organization := core.GetTenant(ctx)
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
	if updated {
		err := o.organizationRepository.Update(nil, &organization)
		if err != nil {
			return echo.NewHTTPError(500, "could not update organization").WithInternal(err)
		}
	}

	resp := orgDetails{
		OrgDTO:  fromModel(organization),
		Members: members,
	}

	return ctx.JSON(200, resp)
}

func (o *httpController) Delete(c core.Context) error {
	// get the id of the organization
	organizationID := core.GetTenant(c).GetID()

	// delete the organization
	err := o.organizationRepository.Delete(nil, organizationID)
	if err != nil {
		return echo.NewHTTPError(500, "could not delete organization").WithInternal(err)
	}

	return c.NoContent(200)
}

func (c *httpController) ContentTree(ctx core.Context) error {
	// get the whole content tree of the organization
	// this means all projects and their corresponding assets

	// get the organization from the context
	organization := core.GetTenant(ctx)

	ps, err := c.projectService.ListAllowedProjects(ctx)
	if err != nil {
		return echo.NewHTTPError(500, "could not get projects").WithInternal(err)
	}

	projects := utils.Map(ps, func(p models.Project) string {
		return p.ID.String()
	})

	return ctx.JSON(200, c.organizationRepository.ContentTree(organization.GetID(), projects))
}

func (c *httpController) AcceptInvitation(ctx core.Context) error {
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
	invitation, err := c.invitationRepository.FindByCode(code)
	if err != nil {
		return echo.NewHTTPError(404, "invitation not found").WithInternal(err)
	}

	// get the user id from the session
	userID := core.GetSession(ctx).GetUserID()
	// get the email of that user
	// get the auth admin client from the context
	authAdminClient := core.GetAuthAdminClient(ctx)
	// fetch the users from the auth service
	m, _, err := authAdminClient.IdentityAPI.GetIdentity(ctx.Request().Context(), userID).Execute()
	if err != nil {
		return echo.NewHTTPError(500, "could not get user").WithInternal(err)
	}

	email := m.Traits.(map[string]any)["email"].(string)
	if email != invitation.Email {
		return echo.NewHTTPError(401, "email does not match")
	}

	// get the rbac from the context
	rbac := c.rbacProvider.GetDomainRBAC((invitation.OrganizationID).String())
	// grant the user the role of member
	err = rbac.GrantRole(userID, "member")
	if err != nil {
		return echo.NewHTTPError(500, "could not grant role").WithInternal(err)
	}

	// delete the invitation
	err = c.invitationRepository.Delete(nil, invitation.ID)
	if err != nil {
		return echo.NewHTTPError(500, "could not delete invitation").WithInternal(err)
	}

	return ctx.JSON(200,
		fromModel(invitation.Organization),
	)
}

func (c *httpController) InviteMember(ctx core.Context) error {
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
	organization := core.GetTenant(ctx)

	model := models.Invitation{
		OrganizationID: organization.GetID(),
		Email:          req.Email,
		Code:           uuid.NewString(),
	}

	// save the model
	err := c.invitationRepository.Save(nil, &model)
	if err != nil {
		return echo.NewHTTPError(500, "could not save invitation").WithInternal(err)
	}

	return ctx.JSON(200, model) // for now return the model - later on we should send an email
}

func (c *httpController) ChangeRole(ctx core.Context) error {
	// get the user id from the request
	var req changeRoleRequest

	if err := ctx.Bind(&req); err != nil {
		return echo.NewHTTPError(400, "could not bind request").WithInternal(err)
	}

	if err := core.V.Struct(req); err != nil {
		return echo.NewHTTPError(400, err.Error())
	}

	// get the rbac from the context
	rbac := core.GetRBAC(ctx)

	//
	rbac.RevokeRole(req.UserID, "member") // nolint:errcheck// we do not care if the user is not a member
	rbac.RevokeRole(req.UserID, "admin")  // nolint:errcheck// we do not care if the user is not a member

	if err := rbac.GrantRole(req.UserID, req.Role); err != nil {
		return echo.NewHTTPError(500, "could not grant role").WithInternal(err)
	}

	return ctx.NoContent(200)
}

func (c *httpController) RemoveMember(ctx core.Context) error {
	// get the user id from the request
	userId := ctx.Param("userId")

	// get the rbac from the context
	rbac := core.GetRBAC(ctx)

	//
	rbac.RevokeRole(userId, "member") // nolint:errcheck// we do not care if the user is not a member
	rbac.RevokeRole(userId, "admin")  // nolint:errcheck// we do not care if the user is not a member

	return ctx.NoContent(200)
}

func FetchMembersOfOrganization(ctx core.Context) ([]core.User, error) {
	// get all members from the organization
	organization := core.GetTenant(ctx)
	accessControl := core.GetRBAC(ctx)

	members, err := accessControl.GetAllMembersOfOrganization()

	if err != nil {
		return nil, err
	}

	// get the auth admin client from the context
	authAdminClient := core.GetAuthAdminClient(ctx)
	// fetch the users from the auth service
	m, _, err := authAdminClient.IdentityAPI.ListIdentitiesExecute(client.IdentityAPIListIdentitiesRequest{}.Ids(members))
	if err != nil {
		return nil, err
	}

	// get the roles for the members
	errGroup := utils.ErrGroup[map[string]string](10)
	for _, member := range m {
		errGroup.Go(func() (map[string]string, error) {
			role, err := accessControl.GetDomainRole(member.Id)
			if err != nil {
				return nil, err
			}
			return map[string]string{member.Id: role}, nil
		})
	}

	roles, err := errGroup.WaitAndCollect()
	if err != nil {
		return nil, err
	}

	roleMap := utils.Reduce(roles, func(acc map[string]string, r map[string]string) map[string]string {
		for k, v := range r {
			acc[k] = v
		}
		return acc
	}, make(map[string]string))

	users := make([]core.User, len(m))
	for i, member := range m {
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

		users[i] = core.User{
			ID:   member.Id,
			Name: name,
			Role: roleMap[member.Id],
		}
	}

	// get the role of the users in the organization

	// fetch all members from third party integrations
	thirdPartyIntegrations := core.GetThirdPartyIntegration(ctx)
	users = append(users, thirdPartyIntegrations.GetUsers(organization)...)
	return users, nil
}

func (o *httpController) Members(c core.Context) error {
	users, err := FetchMembersOfOrganization(c)
	if err != nil {
		return echo.NewHTTPError(500, "could not get members of organization").WithInternal(err)
	}

	return c.JSON(200, users)
}

func (o *httpController) Read(c core.Context) error {
	// get the organization from the context
	organization := core.GetTenant(c)
	// fetch the regular members of the current organization
	members, err := FetchMembersOfOrganization(c)

	if err != nil {
		return echo.NewHTTPError(500, "could not get members of organization").WithInternal(err)
	}

	resp := orgDetails{
		OrgDTO:  fromModel(organization),
		Members: members,
	}

	return c.JSON(200, resp)
}

func (o *httpController) List(c core.Context) error {
	// get all organizations the user has access to
	userID := core.GetSession(c).GetUserID()

	domains, err := o.rbacProvider.DomainsOfUser(userID)

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
	organizations, err := o.organizationRepository.List(organizationIDs)

	if err != nil {
		return echo.NewHTTPError(500, "could not read organizations").WithInternal(err)
	}

	return c.JSON(200, organizations)
}

func (o *httpController) Metrics(c core.Context) error {
	owner, err := core.GetRBAC(c).GetOwnerOfOrganization()
	if err != nil {
		return echo.NewHTTPError(500, "could not get owner of organization").WithInternal(err)
	}
	return c.JSON(200, map[string]string{"ownerId": owner})
}
