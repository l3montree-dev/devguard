// Copyright (C) 2025 l3montree GmbH
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
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package accesscontrol

import (
	"maps"

	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/ory/client-go"
)

// FetchMembersOfOrganization retrieves all members of an organization including their roles
// from both the RBAC system and third-party integrations
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
			users = append(users, dtos.UserDTO{
				ID:   member.Id,
				Name: shared.IdentityName(member.Traits),
				Role: string(roleMap[member.Id]),
			})
		}
	}

	// fetch all members from third party integrations
	thirdPartyIntegrations := shared.GetThirdPartyIntegration(ctx)
	users = append(users, thirdPartyIntegrations.GetUsers(organization)...)
	return users, nil
}
