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

package testutils

import (
	"github.com/l3montree-dev/flawfix/internal/accesscontrol"
)

type RBACProviderMock struct {
}

type RBACMock struct {
	roles map[string][]string
	rules map[string][]string
}

func (r *RBACMock) HasAccess(subject string) bool {
	return true
}

func (r *RBACMock) GrantRole(subject, role string) error {
	if _, ok := r.roles[subject]; !ok {
		r.roles[subject] = []string{}
	}
	r.roles[subject] = append(r.roles[subject], role)
	return nil
}

func (r *RBACMock) InheritRole(roleWhichGetsPermissions, roleWhichProvidesPermissions string) error {
	return r.GrantRole(roleWhichGetsPermissions, roleWhichProvidesPermissions)
}

func (r *RBACMock) GetProjectRoleName(project string, role string) string {
	return project + "|" + string(role)
}

func (r *RBACMock) RevokeRole(subject string, role string) error {
	if _, ok := r.roles[subject]; !ok {
		return nil
	}
	for i, v := range r.roles[subject] {
		if v == string(role) {
			r.roles[subject] = append(r.roles[subject][:i], r.roles[subject][i+1:]...)
			return nil
		}
	}
	return nil
}

func (r *RBACMock) GrantRoleInProject(subject string, role string, project string) error {
	r.GrantRole(subject, project+"|"+string(role))
	return nil
}

func (r *RBACMock) RevokeRoleInProject(subject string, role string, project string) error {
	r.RevokeRole(subject, project+"|"+role)
	return nil
}

func (r *RBACMock) AllowRole(role string, object string, action []accesscontrol.Action) error {
	if _, ok := r.rules[string(role)]; !ok {
		r.rules[string(role)] = []string{}
	}
	for _, v := range action {
		r.rules[string(role)] = append(r.rules[string(role)], string(object)+"|"+string(v))
	}
	return nil
}

func (r *RBACMock) getRolesOf(subject string) []string {
	if _, ok := r.roles[subject]; !ok {
		return []string{}
	}

	roles := []string{}

	for _, v := range r.roles[subject] {
		otherRoles := r.getRolesOf(v)
		roles = append(roles, otherRoles...)
		roles = append(roles, v)
	}
	return roles
}

func (r *RBACMock) IsAllowed(subject, object string, action accesscontrol.Action) (bool, error) {
	// recursively gather all roles
	roles := r.getRolesOf(subject)
	// get all permissions for roles
	for _, v := range roles {
		if _, ok := r.rules[v]; !ok {
			continue
		}
		for _, w := range r.rules[v] {
			if w == object+"|"+string(action) {
				return true, nil
			}
		}
	}
	return false, nil
}

func (r *RBACMock) IsAllowedInProject(project, user, object string, action accesscontrol.Action) (bool, error) {
	return r.IsAllowed(user, project+"|"+object, action)
}

func (r *RBACMock) AllowRoleInProject(project, role string, object string, action []accesscontrol.Action) error {
	return r.AllowRole(project+"|"+role, project+"|"+object, action)
}

func (r *RBACMock) GetAllRoles(user string) []string {
	return []string{"role::" + user}
}

func (r *RBACMock) LinkDomainAndProjectRole(domainRoleWhichGetsPermission, projectRoleWhichProvidesPermissions, project string) error {
	return nil
}

func (r *RBACMock) InheritProjectRole(roleWhichGetsPermissions, roleWhichProvidesPermissions, project string) error {
	return nil
}

func (r RBACProviderMock) GetDomainRBAC(domain string) accesscontrol.AccessControl {
	return &RBACMock{
		roles: map[string][]string{},
		rules: map[string][]string{},
	}
}

func (r RBACMock) GetAllProjectsForUser(user string) []string {
	return []string{}
}

func (r RBACProviderMock) DomainsOfUser(user string) ([]string, error) {
	return []string{"domain::" + user}, nil
}

func NewRBACProviderMock() accesscontrol.RBACProvider {
	return &RBACProviderMock{}
}
