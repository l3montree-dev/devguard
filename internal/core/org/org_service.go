// Copyright 2025 l3montree UG (haftungsbeschraenkt).
// SPDX-License-Identifier: 	AGPL-3.0-or-later
package org

import (
	"fmt"
	"strings"

	"github.com/l3montree-dev/devguard/internal/accesscontrol"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/labstack/echo/v4"
)

type orgService struct {
	organizationRepository core.OrganizationRepository
	rbacProvider           accesscontrol.RBACProvider
}

func NewService(organizationRepository core.OrganizationRepository, rbacProvider accesscontrol.RBACProvider) *orgService {
	return &orgService{
		organizationRepository: organizationRepository,
		rbacProvider:           rbacProvider,
	}
}

func (o *orgService) CreateOrganization(ctx core.Context, organization models.Org) error {
	if organization.Name == "" || organization.Slug == "" {
		return echo.NewHTTPError(409, "organizations with an empty name or an empty slug are not allowed").WithInternal(fmt.Errorf("organizations with an empty name or an empty slug are not allowed"))
	}

	err := o.organizationRepository.Create(nil, &organization)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key value") { //Check the returned error of Create Function
			return echo.NewHTTPError(409, "organization with that name already exists").WithInternal(err) //Error Code 409: conflict in current state of the resource
		}
		return echo.NewHTTPError(500, "could not create organization").WithInternal(err)
	}

	if err = o.bootstrapOrg(ctx, organization); err != nil {
		return echo.NewHTTPError(500, "could not bootstrap organization").WithInternal(err)
	}
	return nil
}

func (o *orgService) bootstrapOrg(ctx core.Context, organization models.Org) error {
	// create the permissions for the organization
	rbac := o.rbacProvider.GetDomainRBAC(organization.ID.String())
	userId := core.GetSession(ctx).GetUserID()

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

	ctx.Set("rbac", rbac)
	return nil
}

func (o *orgService) ReadBySlug(ctx core.Context, slug string) (*models.Org, error) {
	if slug == "" {
		return nil, echo.NewHTTPError(400, "slug is required")
	}

	org, err := o.organizationRepository.ReadBySlug(slug)
	if err != nil {
		if strings.Contains(err.Error(), "no rows in result set") {
			return nil, echo.NewHTTPError(404, "organization not found").WithInternal(err)
		}
		return nil, echo.NewHTTPError(500, "could not get organization").WithInternal(err)
	}

	return &org, nil
}
