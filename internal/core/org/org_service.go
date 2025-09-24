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

func (o *orgService) CreateOrganization(ctx core.Context, organization *models.Org) error {
	if organization.Name == "" || organization.Slug == "" {
		return echo.NewHTTPError(409, "organizations with an empty name or an empty slug are not allowed").WithInternal(fmt.Errorf("organizations with an empty name or an empty slug are not allowed"))
	}

	if organization.Name == "opencode" || organization.Name == "gitlab" || organization.Name == "github" {
		return echo.NewHTTPError(409, "organizations named opencode, github or gitlab are not allowed").WithInternal(fmt.Errorf("organizations named opencode, github or gitlab are not allowed"))
	}

	err := o.organizationRepository.Create(nil, organization)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key value") { //Check the returned error of Create Function
			return echo.NewHTTPError(409, "organization with that name already exists").WithInternal(err) //Error Code 409: conflict in current state of the resource
		}
		return echo.NewHTTPError(500, "could not create organization").WithInternal(err)
	}

	rbac := o.rbacProvider.GetDomainRBAC(organization.ID.String())
	userID := core.GetSession(ctx).GetUserID()
	if err = core.BootstrapOrg(rbac, userID, core.RoleOwner); err != nil {
		return echo.NewHTTPError(500, "could not bootstrap organization roles").WithInternal(err)
	}
	ctx.Set("rbac", rbac)

	return nil
}

func (o *orgService) ReadBySlug(slug string) (*models.Org, error) {
	if slug == "" {
		return nil, echo.NewHTTPError(400, "slug is required")
	}

	org, err := o.organizationRepository.ReadBySlug(slug)
	return &org, err
}
