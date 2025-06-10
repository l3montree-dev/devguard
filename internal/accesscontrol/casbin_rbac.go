// Copyright (C) 2023 Tim Bastin, l3montree GmbH
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

import (
	"fmt"
	"log"
	"log/slog"
	"strings"

	gormadapter "github.com/casbin/gorm-adapter/v3"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"

	"github.com/casbin/casbin/v2"
	"gorm.io/gorm"
)

var _ core.AccessControl = &casbinRBAC{}
var casbinEnforcer *casbin.Enforcer

type casbinRBAC struct {
	domain   string // scopes this to a specific domain - or organization
	enforcer *casbin.Enforcer
}

type casbinRBACProvider struct {
	enforcer *casbin.Enforcer
}

func (c casbinRBACProvider) GetDomainRBAC(domain string) core.AccessControl {
	return &casbinRBAC{
		domain:   domain,
		enforcer: c.enforcer,
	}
}

func (c *casbinRBAC) GetOwnerOfOrganization() (string, error) {
	listOfUsers := c.enforcer.GetUsersForRoleInDomain("role::owner", "domain::"+c.domain)
	if len(listOfUsers) == 0 {
		// TODO: Add alerting
		return "", fmt.Errorf("no owner found for organization")
	}
	if len(listOfUsers) > 1 {
		// TODO: Add alerting
		return "", fmt.Errorf("more than one owner found for organization")
	}
	return strings.TrimPrefix(listOfUsers[0], "user::"), nil
}

func (c *casbinRBAC) GetAllMembersOfOrganization() ([]string, error) {
	users, err := c.enforcer.GetAllUsersByDomain("domain::" + c.domain)
	if err != nil {
		return nil, err
	}
	return utils.Map(utils.Filter(users, func(u string) bool {
		return strings.HasPrefix(u, "user::")
	}), func(u string) string {
		return strings.TrimPrefix(u, "user::")
	}), nil
}

func (c *casbinRBAC) GetAllMembersOfProject(projectID string) ([]string, error) {
	users, err := c.enforcer.GetImplicitUsersForRole("project::"+projectID+"|role::member", "domain::"+c.domain)
	if err != nil {
		return nil, err
	}

	return utils.Map(utils.Filter(users, func(u string) bool {
		return strings.HasPrefix(u, "user::")
	}), func(u string) string {
		return strings.TrimPrefix(u, "user::")
	}), nil
}

func (c *casbinRBAC) HasAccess(user string) (bool, error) {
	roles := c.enforcer.GetRolesForUserInDomain("user::"+user, "domain::"+c.domain)
	return len(roles) > 0, nil
}

func (c *casbinRBAC) GetAllProjectsForUser(user string) (any, error) {
	projectIDs := []string{}

	roles, _ := c.enforcer.GetImplicitRolesForUser("user::"+user, "domain::"+c.domain)

	for _, role := range roles {
		if !strings.HasPrefix(role, "project::") || !strings.Contains(role, "role::") {
			continue // not a project role
		}
		// extract everything between the prefix and a "|"
		projectIDs = append(projectIDs, strings.Split(strings.TrimPrefix(role, "project::"), "|")[0])
	}
	return projectIDs, nil
}

func (c *casbinRBAC) GetAllRoles(user string) []string {
	roles, err := c.enforcer.GetImplicitRolesForUser("user::"+user, "domain::"+c.domain)

	if err != nil {
		slog.Error("GetAllRoles failed", "err", err)
		return []string{}
	}

	return roles
}

func (c *casbinRBAC) GetDomainRole(user string) (string, error) {
	roles := c.GetAllRoles(user)
	// filter the roles to only get the domain roles
	roles = utils.Map(utils.Filter(roles, func(r string) bool {
		return strings.HasPrefix(r, "role::")
	}), func(r string) string {
		return strings.TrimPrefix(r, "role::")
	})

	return getMostPowerfulRole(roles)
}

func getMostPowerfulRole(roles []string) (string, error) {
	if utils.Contains(roles, "owner") {
		return "owner", nil
	}

	if utils.Contains(roles, "admin") {
		return "admin", nil
	}

	if utils.Contains(roles, "member") {
		return "member", nil
	}

	return "", fmt.Errorf("no domain role found for user")
}

func (c *casbinRBAC) GetProjectRole(user string, project string) (string, error) {
	roles := c.GetAllRoles(user)
	// filter the roles to only get the project roles
	roles = utils.Map(utils.Filter(roles, func(r string) bool {
		return strings.HasPrefix(r, "project::"+project+"|role::")
	}), func(r string) string {
		return strings.TrimPrefix(r, "project::"+project+"|role::")
	})

	return getMostPowerfulRole(roles)
}

func (c *casbinRBAC) GrantRole(user string, role string) error {
	_, err := c.enforcer.AddRoleForUserInDomain("user::"+user, "role::"+string(role), "domain::"+c.domain)
	return err
}

// both roles are treated as projects roles.
func (c *casbinRBAC) InheritProjectRole(roleWhichGetsPermissions, roleWhichProvidesPermissions string, project string) error {
	_, err := c.enforcer.AddRoleForUserInDomain(c.getProjectRoleName(roleWhichGetsPermissions, project), c.getProjectRoleName(roleWhichProvidesPermissions, project), "domain::"+c.domain)
	return err
}

func (c *casbinRBAC) InheritProjectRolesAcrossProjects(roleWhichGetsPermissions, roleWhichProvidesPermissions core.ProjectRole) error {
	_, err := c.enforcer.AddRoleForUserInDomain(c.getProjectRoleName(roleWhichGetsPermissions.Role, roleWhichGetsPermissions.Project), c.getProjectRoleName(roleWhichProvidesPermissions.Role, roleWhichProvidesPermissions.Project), "domain::"+c.domain)
	return err
}

func (c *casbinRBAC) InheritRole(roleWhichGetsPermissions, roleWhichProvidesPermissions string) error {
	_, err := c.enforcer.AddRoleForUserInDomain("role::"+string(roleWhichGetsPermissions), "role::"+string(roleWhichProvidesPermissions), "domain::"+c.domain)
	return err
}

func (c *casbinRBAC) LinkDomainAndProjectRole(domainRoleWhichGetsPermission, projectRoleWhichProvidesPermissions string, project string) error {
	_, err := c.enforcer.AddRoleForUserInDomain("role::"+string(domainRoleWhichGetsPermission), c.getProjectRoleName(projectRoleWhichProvidesPermissions, project), "domain::"+c.domain)
	return err
}

func (c *casbinRBAC) getProjectRoleName(role string, project string) string {
	return "project::" + project + "|role::" + string(role)
}

func (c *casbinRBAC) RevokeRole(user string, role string) error {
	_, err := c.enforcer.DeleteRoleForUserInDomain("user::"+user, "role::"+string(role), "domain::"+c.domain)
	return err
}

func (c *casbinRBAC) AllowRole(role string, object core.Object, action []core.Action) error {
	policies := make([][]string, len(action))
	for i, ac := range action {
		policies[i] = []string{"role::" + string(role), "domain::" + c.domain, "obj::" + string(object), "act::" + string(ac)}
	}

	_, err := c.enforcer.AddPolicies(policies)
	return err
}

func (c *casbinRBAC) AllowRoleInProject(project string, role string, object core.Object, action []core.Action) error {
	policies := make([][]string, len(action))
	for i, ac := range action {
		policies[i] = []string{"project::" + project + "|role::" + string(role), "domain::" + c.domain, "project::" + project + "|obj::" + string(object), "act::" + string(ac)}
	}
	_, err := c.enforcer.AddPolicies(policies)
	return err
}

func (c *casbinRBAC) GrantRoleInProject(user string, role string, project string) error {
	_, err := c.enforcer.AddRoleForUserInDomain("user::"+user, "project::"+project+"|role::"+string(role), "domain::"+c.domain)
	return err
}

func (c *casbinRBAC) RevokeRoleInProject(user string, role string, project string) error {
	_, err := c.enforcer.DeleteRoleForUserInDomain("user::"+user, "project::"+project+"|role::"+string(role), "domain::"+c.domain)
	return err
}

func (c *casbinRBAC) IsAllowed(user string, object core.Object, action core.Action) (bool, error) {
	permissions, err := c.enforcer.GetImplicitPermissionsForUser("user::"+user, "domain::"+c.domain)
	if err != nil {
		return false, err
	}

	// check for the permissions
	for _, p := range permissions {
		if p[2] == "obj::"+string(object) && p[3] == "act::"+string(action) {
			return true, nil
		}
	}
	return false, nil
}

func (c *casbinRBAC) IsAllowedInProject(project *models.Project, user string, object core.Object, action core.Action) (bool, error) {
	permissions, err := c.enforcer.GetImplicitPermissionsForUser("user::"+user, "domain::"+c.domain)
	if err != nil {
		return false, err
	}

	// check for the permissions
	for _, p := range permissions {
		if p[2] == "project::"+project.ID.String()+"|obj::"+string(object) && p[3] == "act::"+string(action) {
			return true, nil
		}
	}
	return false, nil
}

func (c casbinRBACProvider) DomainsOfUser(user string) ([]string, error) {
	domains, err := c.enforcer.GetDomainsForUser("user::" + user)
	if err != nil {
		return nil, err
	}
	// slice the "domain::" prefix
	for i, d := range domains {
		domains[i] = d[8:]
	}
	return domains, nil
}

// the provider can be used to create domain specific RBAC instances
func NewCasbinRBACProvider(db *gorm.DB) (casbinRBACProvider, error) {
	enforcer, err := buildEnforcer(db)
	if err != nil {
		return casbinRBACProvider{}, err
	}
	return casbinRBACProvider{
		enforcer: enforcer,
	}, nil
}

func buildEnforcer(db *gorm.DB) (*casbin.Enforcer, error) {
	if casbinEnforcer != nil {
		return casbinEnforcer, nil
	}
	// Initialize an adapter and use it in a Casbin enforcer:
	// The adapter will use the SQLite3 table name "casbin_rule_test",
	// the default table name is "casbin_rule".
	// If it doesn't exist, the adapter will create it automatically.
	a, err := gormadapter.NewAdapterByDB(db)
	if err != nil {
		return nil, err
	}

	e, err := casbin.NewEnforcer("config/rbac_model.conf", a)
	if err != nil {
		return nil, err
	}

	e.EnableLog(false)

	// Load the policy from DB.
	if err = e.LoadPolicy(); err != nil {
		log.Println("LoadPolicy failed, err: ", err)
	}

	casbinEnforcer = e

	return e, nil
}
