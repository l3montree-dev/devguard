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
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/ory/client-go"

	"github.com/labstack/echo/v4"
)

type repository interface {
	repositories.Repository[uuid.UUID, models.Org, core.DB]
	// ReadBySlug reads an organization by its slug
	ReadBySlug(slug string) (models.Org, error)
	Update(tx core.DB, organization *models.Org) error
}
type httpController struct {
	organizationRepository repository
	rbacProvider           accesscontrol.RBACProvider
}

func NewHttpController(repository repository, rbacProvider accesscontrol.RBACProvider) *httpController {
	return &httpController{
		organizationRepository: repository,
		rbacProvider:           rbacProvider,
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
	members, err := fetchMembersOfOrganization(ctx)
	if err != nil {
		return echo.NewHTTPError(500, "could not get members of organization").WithInternal(err)
	}

	// get all members from any third party integrations
	thirdPartyIntegrations := core.GetThirdPartyIntegration(ctx)
	users := thirdPartyIntegrations.GetUsers(organization)

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
		Org: organization,
		Members: append(users, utils.Map(
			members, func(i client.Identity) core.User {
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
				return core.User{
					ID:   i.Id,
					Name: name,
				}
			})...),
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

func fetchMembersOfOrganization(ctx core.Context) ([]client.Identity, error) {
	// get all members from the organization
	organization := core.GetTenant(ctx)
	accessControl := core.GetRBAC(ctx)

	members, err := accessControl.GetAllMembersOfOrganization(organization.GetID().String())

	if err != nil {
		return nil, err
	}

	// get the auth admin client from the context
	authAdminClient := core.GetAuthAdminClient(ctx)
	// fetch the users from the auth service
	users, _, err := authAdminClient.IdentityAPI.ListIdentitiesExecute(client.IdentityAPIListIdentitiesRequest{}.Ids(members))

	return users, err
}

func (o *httpController) Members(c core.Context) error {
	users, err := fetchMembersOfOrganization(c)
	if err != nil {
		return echo.NewHTTPError(500, "could not get members of organization").WithInternal(err)
	}

	return c.JSON(200, users)
}

func (o *httpController) Read(c core.Context) error {
	// get the organization from the context
	organization := core.GetTenant(c)
	// fetch the regular members of the current organization
	members, err := fetchMembersOfOrganization(c)
	// get all members from any third party integrations
	thirdPartyIntegrations := core.GetThirdPartyIntegration(c)
	users := thirdPartyIntegrations.GetUsers(organization)

	if err != nil {
		return echo.NewHTTPError(500, "could not get members of organization").WithInternal(err)
	}

	resp := orgDetails{
		Org: organization,
		Members: append(users, utils.Map(
			members, func(i client.Identity) core.User {
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
				return core.User{
					ID:   i.Id,
					Name: name,
				}
			})...),
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
	orgID := core.GetTenant(c).GetID().String()
	owner, err := core.GetRBAC(c).GetOwnerOfOrganization(orgID)
	if err != nil {
		return echo.NewHTTPError(500, "could not get owner of organization").WithInternal(err)
	}
	return c.JSON(200, map[string]string{"ownerId": owner})
}
