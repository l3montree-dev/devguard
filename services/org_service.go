// Copyright 2025 l3montree UG (haftungsbeschraenkt).
// SPDX-License-Identifier: 	AGPL-3.0-or-later
package services

import (
	"fmt"
	"maps"
	"strings"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/labstack/echo/v4"
	"github.com/ory/client-go"
)

type OrgService struct {
	organizationRepository shared.OrganizationRepository
	rbacProvider           shared.RBACProvider
}

func NewOrgService(organizationRepository shared.OrganizationRepository, rbacProvider shared.RBACProvider) *OrgService {
	return &OrgService{
		organizationRepository: organizationRepository,
		rbacProvider:           rbacProvider,
	}
}

func (o *OrgService) CreateOrganization(ctx shared.Context, organization *models.Org) error {
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
	userID := shared.GetSession(ctx).GetUserID()
	if err = shared.BootstrapOrg(rbac, userID, shared.RoleOwner); err != nil {
		return echo.NewHTTPError(500, "could not bootstrap organization roles").WithInternal(err)
	}
	ctx.Set("rbac", rbac)

	return nil
}

func (o *OrgService) ReadBySlug(slug string) (*models.Org, error) {
	if slug == "" {
		return nil, echo.NewHTTPError(400, "slug is required")
	}

	org, err := o.organizationRepository.ReadBySlug(slug)
	return &org, err
}

func FetchMembersOfOrganization(ctx shared.Context) ([]dtos.UserDTO, error) {
	// get all members from the organization
	organization := shared.GetOrg(ctx)
	accessControl := shared.GetRBAC(ctx)

	members, err := accessControl.GetAllMembersOfOrganization()

	if err != nil {
		return nil, err
	}

	users := make([]dtos.UserDTO, 0, len(members))
	if len(members) > 0 {
		// get the auth admin client from the context
		authAdminClient := shared.GetAuthAdminClient(ctx)
		// fetch the users from the auth service
		m, err := authAdminClient.ListUser(client.IdentityAPIListIdentitiesRequest{}.Ids(members))
		if err != nil {
			return nil, err
		}

		// get the roles for the members
		errGroup := utils.ErrGroup[map[string]shared.Role](10)
		for _, member := range m {
			errGroup.Go(func() (map[string]shared.Role, error) {
				role, err := accessControl.GetDomainRole(member.Id)
				if err != nil {
					return map[string]shared.Role{member.Id: shared.RoleUnknown}, nil
				}
				return map[string]shared.Role{member.Id: role}, nil
			})
		}

		roles, err := errGroup.WaitAndCollect()
		if err != nil {
			return nil, err
		}

		roleMap := utils.Reduce(roles, func(acc map[string]shared.Role, r map[string]shared.Role) map[string]shared.Role {
			maps.Copy(acc, r)
			return acc
		}, make(map[string]shared.Role))

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

			users = append(users, dtos.UserDTO{
				ID:   member.Id,
				Name: name,
				Role: string(roleMap[member.Id]),
			})
		}
	}

	// fetch all members from third party integrations
	thirdPartyIntegrations := shared.GetThirdPartyIntegration(ctx)
	users = append(users, thirdPartyIntegrations.GetUsers(organization)...)
	return users, nil
}
