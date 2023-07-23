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

import "github.com/l3montree-dev/flawfix/internal/accesscontrol"

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

func (r *RBACMock) RevokeRole(subject, role string) error {
	if _, ok := r.roles[subject]; !ok {
		return nil
	}
	for i, v := range r.roles[subject] {
		if v == role {
			r.roles[subject] = append(r.roles[subject][:i], r.roles[subject][i+1:]...)
			return nil
		}
	}
	return nil
}

func (r *RBACMock) GrantRoleInProject(subject, role, project string) error {
	r.GrantRole(subject, project+"|"+role)
	return nil
}

func (r *RBACMock) RevokeRoleInProject(subject, role, project string) error {
	r.RevokeRole(subject, project+"|"+role)
	return nil
}

func (r *RBACMock) AllowRole(role, object string, action []string) error {
	if _, ok := r.rules[role]; !ok {
		r.rules[role] = []string{}
	}
	for _, v := range action {
		r.rules[role] = append(r.rules[role], object+"|"+v)
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

func (r *RBACMock) IsAllowed(subject, object, action string) (bool, error) {
	// recursively gather all roles
	roles := r.getRolesOf(subject)
	// get all permissions for roles
	for _, v := range roles {
		if _, ok := r.rules[v]; !ok {
			continue
		}
		for _, w := range r.rules[v] {
			if w == object+"|"+action {
				return true, nil
			}
		}
	}
	return false, nil
}

func (r RBACProviderMock) GetDomainRBAC(domain string) accesscontrol.AccessControl {
	return &RBACMock{
		roles: map[string][]string{},
		rules: map[string][]string{},
	}
}

func NewRBACProviderMock() accesscontrol.RBACProvider {
	return &RBACProviderMock{}
}
