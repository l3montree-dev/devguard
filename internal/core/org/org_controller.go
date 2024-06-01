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
	"github.com/google/uuid"
	"github.com/l3montree-dev/flawfix/internal/accesscontrol"
	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/l3montree-dev/flawfix/internal/database/models"
	"github.com/l3montree-dev/flawfix/internal/database/repositories"

	"github.com/labstack/echo/v4"
)

type repository interface {
	repositories.Repository[uuid.UUID, models.Org, core.DB]
	// ReadBySlug reads an organization by its slug
	ReadBySlug(slug string) (models.Org, error)
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

func (o *httpController) Update(c core.Context) error {
	return nil
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

func (o *httpController) Read(c core.Context) error {
	// get the organization from the context
	organization := core.GetTenant(c)
	return c.JSON(200, organization)
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
