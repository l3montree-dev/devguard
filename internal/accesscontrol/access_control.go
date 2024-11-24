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

package accesscontrol

import "github.com/labstack/echo/v4"

const (
	RoleOwner  = "owner"
	RoleAdmin  = "admin"
	RoleMember = "member"
)

type Action string

const (
	ActionCreate Action = "create"
	ActionRead   Action = "read"
	ActionUpdate Action = "update"
	ActionDelete Action = "delete"
)

type Object string

const (
	ObjectProject Object = "project"
	ObjectAsset   Object = "asset"
)

type AccessControl interface {
	HasAccess(subject string) bool

	InheritRole(roleWhichGetsPermissions, roleWhichProvidesPermissions string) error

	GetAllRoles(user string) []string

	GrantRole(subject string, role string) error
	RevokeRole(subject string, role string) error

	GrantRoleInProject(subject string, role string, project string) error
	RevokeRoleInProject(subject string, role string, project string) error
	InheritProjectRole(roleWhichGetsPermissions, roleWhichProvidesPermissions string, project string) error

	LinkDomainAndProjectRole(domainRoleWhichGetsPermission, projectRoleWhichProvidesPermissions string, project string) error

	AllowRole(role string, object string, action []Action) error
	IsAllowed(subject string, object string, action Action) (bool, error)

	IsAllowedInProject(project, user string, object string, action Action) (bool, error)
	AllowRoleInProject(project string, role string, object string, action []Action) error

	GetAllProjectsForUser(user string) []string

	GetOwnerOfOrganization(organizationID string) (string, error)

	GetAllMembersOfOrganization(organizationID string) ([]string, error)

	GetAllMembersOfProject(organizationID, projectID string) ([]string, error)
}

type RBACProvider interface {
	GetDomainRBAC(domain string) AccessControl
	DomainsOfUser(user string) ([]string, error)
}

type RBACMiddleware = func(obj Object, act Action) echo.MiddlewareFunc
