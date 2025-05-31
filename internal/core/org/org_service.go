// Copyright 2025 l3montree UG (haftungsbeschraenkt).
// SPDX-License-Identifier: 	AGPL-3.0-or-later
package org

import (
	"fmt"
	"strings"

	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/labstack/echo/v4"
)

type orgService struct {
	organizationRepository core.OrganizationRepository
	rbacProvider           core.RBACProvider
}

func NewService(organizationRepository core.OrganizationRepository, rbacProvider core.RBACProvider) *orgService {
	return &orgService{
		organizationRepository: organizationRepository,
		rbacProvider:           rbacProvider,
	}
}
func (o *orgService) CreateExternalEntityOrganization(ctx core.Context, externalEntitySlug core.ExternalEntitySlug) (*models.Org, error) {
	// try to create the organization on the fly
	thirdPartyIntegration := core.GetThirdPartyIntegration(ctx)

	orgs, err := thirdPartyIntegration.ListOrgs(ctx)
	if err != nil {
		return nil, echo.NewHTTPError(500, "could not list organizations from third party integration").WithInternal(err)
	}
	// find the correct one - slug needs to match
	var orgToCreate models.Org
	for _, org := range orgs {
		if externalEntitySlug.SameAs(org.Slug) {
			// we found the organization
			orgToCreate = org
			break
		}
	}
	if orgToCreate.Slug == "" {
		return nil, echo.NewHTTPError(404, "organization not found in third party integration").WithInternal(fmt.Errorf("organization with slug %s not found", externalEntitySlug.Slug()))
	}

	// create the organization in the database
	// but DO NOT BOOTSTRAP IT
	if err := o.organizationRepository.Create(nil, &orgToCreate); err != nil {
		if strings.Contains(err.Error(), "duplicate key value") {
			return nil, echo.NewHTTPError(409, "organization with that slug already exists").WithInternal(err)
		}
		return nil, echo.NewHTTPError(500, "could not create organization").WithInternal(err)
	}
	return &orgToCreate, nil
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

	if err := rbac.AllowRole("owner", "organization", []core.Action{
		core.ActionDelete,
	}); err != nil {
		return err
	}

	if err := rbac.AllowRole("admin", "organization", []core.Action{
		core.ActionUpdate,
	}); err != nil {
		return err
	}

	if err := rbac.AllowRole("admin", "project", []core.Action{
		core.ActionCreate,
		core.ActionRead, // listing all projects
		core.ActionUpdate,
		core.ActionDelete,
	}); err != nil {
		return err
	}

	if err := rbac.AllowRole("member", "organization", []core.Action{
		core.ActionRead,
	}); err != nil {
		return err
	}

	ctx.Set("rbac", rbac)
	return nil
}

func (o *orgService) ReadBySlug(slug string) (*models.Org, error) {
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
