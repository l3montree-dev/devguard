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

package controller

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/flawfix/internal/accesscontrol"
	"github.com/l3montree-dev/flawfix/internal/dto"
	"github.com/l3montree-dev/flawfix/internal/helpers"
	"github.com/l3montree-dev/flawfix/internal/models"
	"github.com/labstack/echo/v4"
)

type organizationRepository interface {
	Create(*models.Organization) error
	Delete(uuid.UUID) error
	Read(uuid.UUID) (models.Organization, error)
	Update(*models.Organization) error
	List([]uuid.UUID) ([]models.Organization, error)
}

type OrganizationController struct {
	organizationRepository
	rbacProvider accesscontrol.RBACProvider
}

func NewOrganizationController(repository organizationRepository, rbacProvider accesscontrol.RBACProvider) *OrganizationController {
	return &OrganizationController{
		organizationRepository: repository,
		rbacProvider:           rbacProvider,
	}
}

func (o *OrganizationController) Create(c echo.Context) error {
	var req dto.OrganizationCreateRequest
	if err := c.Bind(&req); err != nil {
		return err
	}

	if err := v.Struct(req); err != nil {
		return echo.NewHTTPError(400, err.Error())
	}

	org := req.ToModel()

	err := o.organizationRepository.Create(&org)
	o.bootstrapOrg(c, org)

	if err != nil {
		return err
	}

	return c.JSON(200, org)
}

func (o *OrganizationController) bootstrapOrg(c echo.Context, organization models.Organization) {
	// create the permissions for the organization
	rbac := o.rbacProvider.GetDomainRBAC(organization.ID.String())
	userId := helpers.GetSession(c).GetUserID()

	rbac.GrantRole(userId, "owner")
	rbac.InheritRole("admin", "owner")
	rbac.InheritRole("member", "admin")

	rbac.AllowRole("owner", "organization", []accesscontrol.Action{
		accesscontrol.ActionDelete,
	})

	rbac.AllowRole("admin", "organization", []accesscontrol.Action{
		accesscontrol.ActionUpdate,
	})

	rbac.AllowRole("admin", "project", []accesscontrol.Action{
		accesscontrol.ActionCreate,
		accesscontrol.ActionRead, // listing all projects
		accesscontrol.ActionUpdate,
		accesscontrol.ActionDelete,
	})

	rbac.AllowRole("member", "organization", []accesscontrol.Action{
		accesscontrol.ActionRead,
	})

	c.Set("rbac", rbac)
}

func (o *OrganizationController) Update(c echo.Context) error {
	return nil
}

func (o *OrganizationController) Delete(c echo.Context) error {
	// get the id of the organization
	organizationID := helpers.GetTenant(c).ID

	// delete the organization
	err := o.organizationRepository.Delete(organizationID)
	if err != nil {
		return echo.NewHTTPError(500, "could not delete organization").WithInternal(err)
	}

	return c.NoContent(200)
}

func (o *OrganizationController) Read(c echo.Context) error {
	// get the organization from the context
	organization := helpers.GetTenant(c)
	return c.JSON(200, organization)
}

func (o *OrganizationController) List(c echo.Context) error {

	// get all organizations the user has access to
	userID := helpers.GetSession(c).GetUserID()

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
