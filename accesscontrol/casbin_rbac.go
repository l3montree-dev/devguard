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
	"os"
	"strings"

	"github.com/casbin/casbin/v2"
	gormadapter "github.com/casbin/gorm-adapter/v3"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"gorm.io/gorm"
)

var _ shared.AccessControl = &casbinRBAC{}
var casbinEnforcer *casbin.SyncedEnforcer

type casbinRBAC struct {
	domain   string // scopes this to a specific domain - or organization
	enforcer *casbin.SyncedEnforcer
}

type casbinRBACProvider struct {
	enforcer *casbin.SyncedEnforcer
}

func (c casbinRBACProvider) GetDomainRBAC(domain string) shared.AccessControl {
	return &casbinRBAC{
		domain:   domain,
		enforcer: c.enforcer,
	}
}

func (c *casbinRBAC) GetExternalEntityProviderID() *string {
	// this is the provider ID for the external entity provider
	// it is used to identify the provider in the database
	return nil
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

func (c *casbinRBAC) GetAllMembersOfAsset(assetID string) ([]string, error) {
	users, err := c.enforcer.GetImplicitUsersForRole("asset::"+assetID+"|role::member", "domain::"+c.domain)
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

func (c *casbinRBAC) GetAllProjectsForUser(user string) ([]string, error) {
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

func (c *casbinRBAC) GetAllAssetsForUser(user string) ([]string, error) {
	assetIDs := []string{}

	roles, _ := c.enforcer.GetImplicitRolesForUser("user::"+user, "domain::"+c.domain)

	for _, role := range roles {
		if !strings.HasPrefix(role, "asset::") || !strings.Contains(role, "role::") {
			continue // not a asset role
		}
		// extract everything between the prefix and a "|"
		assetIDs = append(assetIDs, strings.Split(strings.TrimPrefix(role, "asset::"), "|")[0])
	}
	return assetIDs, nil
}

func (c *casbinRBAC) GetAllRoles(user string) []string {
	roles, err := c.enforcer.GetImplicitRolesForUser("user::"+user, "domain::"+c.domain)

	if err != nil {
		slog.Error("GetAllRoles failed", "err", err)
		return []string{}
	}

	return roles
}

func (c *casbinRBAC) GetDomainRole(user string) (shared.Role, error) {
	dbRoles := c.GetAllRoles(user)
	// filter the roles to only get the domain roles
	roles := utils.Map(utils.Filter(dbRoles, func(r string) bool {
		return strings.HasPrefix(r, "role::")
	}), func(r string) string {
		return strings.TrimPrefix(r, "role::")
	})

	// transform the roles to shared.Role
	r := utils.Map(roles, func(r string) shared.Role {
		return shared.Role(r)
	})

	role, err := getMostPowerfulRole(r)
	if err != nil {
		slog.Warn("GetDomainRole: no domain role found for user", "user", user, "roles", roles, "dbRoles", dbRoles, "domain", c.domain)
	}
	return role, err
}

func getMostPowerfulRole(roles []shared.Role) (shared.Role, error) {
	if utils.Contains(roles, shared.RoleOwner) {
		return shared.RoleOwner, nil
	}

	if utils.Contains(roles, shared.RoleAdmin) {
		return shared.RoleAdmin, nil
	}
	if utils.Contains(roles, shared.RoleMember) {
		return shared.RoleMember, nil
	}

	return "", fmt.Errorf("no domain role found for user. Roles from user: %v", roles)
}

func (c *casbinRBAC) GetProjectRole(user string, project string) (shared.Role, error) {
	roles := c.GetAllRoles(user)
	// filter the roles to only get the project roles
	roles = utils.Map(utils.Filter(roles, func(r string) bool {
		return strings.HasPrefix(r, "project::"+project+"|role::")
	}), func(r string) string {
		return strings.TrimPrefix(r, "project::"+project+"|role::")
	})

	// transform the roles to shared.Role
	r := utils.Map(roles, func(r string) shared.Role {
		return shared.Role(r)
	})

	return getMostPowerfulRole(r)
}

func (c *casbinRBAC) GetAssetRole(user string, asset string) (shared.Role, error) {
	roles := c.GetAllRoles(user)
	// filter the roles to only get the asset roles
	roles = utils.Map(utils.Filter(roles, func(r string) bool {
		return strings.HasPrefix(r, "asset::"+asset+"|role::")
	}), func(r string) string {
		return strings.TrimPrefix(r, "asset::"+asset+"|role::")
	})

	// transform the roles to shared.Role
	r := utils.Map(roles, func(r string) shared.Role {
		return shared.Role(r)
	})

	return getMostPowerfulRole(r)
}

func (c *casbinRBAC) GrantRole(user string, role shared.Role) error {
	_, err := c.enforcer.AddRoleForUserInDomain("user::"+user, "role::"+string(role), "domain::"+c.domain)
	return err
}

// both roles are treated as projects roles.
func (c *casbinRBAC) InheritProjectRole(roleWhichGetsPermissions, roleWhichProvidesPermissions shared.Role, project string) error {
	_, err := c.enforcer.AddRoleForUserInDomain(c.getProjectRoleName(roleWhichGetsPermissions, project), c.getProjectRoleName(roleWhichProvidesPermissions, project), "domain::"+c.domain)
	return err
}

func (c *casbinRBAC) InheritAssetRole(roleWhichGetsPermissions, roleWhichProvidesPermissions shared.Role, asset string) error {
	_, err := c.enforcer.AddRoleForUserInDomain(c.getAssetRoleName(roleWhichGetsPermissions, asset), c.getAssetRoleName(roleWhichProvidesPermissions, asset), "domain::"+c.domain)
	return err
}

func (c *casbinRBAC) InheritProjectRolesAcrossProjects(roleWhichGetsPermissions, roleWhichProvidesPermissions shared.ProjectRole) error {
	_, err := c.enforcer.AddRoleForUserInDomain(c.getProjectRoleName(roleWhichGetsPermissions.Role, roleWhichGetsPermissions.Project), c.getProjectRoleName(roleWhichProvidesPermissions.Role, roleWhichProvidesPermissions.Project), "domain::"+c.domain)
	return err
}

func (c *casbinRBAC) InheritRole(roleWhichGetsPermissions, roleWhichProvidesPermissions shared.Role) error {
	_, err := c.enforcer.AddRoleForUserInDomain("role::"+string(roleWhichGetsPermissions), "role::"+string(roleWhichProvidesPermissions), "domain::"+c.domain)
	return err
}

func (c *casbinRBAC) LinkDomainAndProjectRole(domainRoleWhichGetsPermission, projectRoleWhichProvidesPermissions shared.Role, project string) error {
	_, err := c.enforcer.AddRoleForUserInDomain("role::"+string(domainRoleWhichGetsPermission), c.getProjectRoleName(projectRoleWhichProvidesPermissions, project), "domain::"+c.domain)
	return err
}

func (c *casbinRBAC) LinkProjectAndAssetRole(
	projectRoleWhichGetsPermission, assetRoleWhichProvidesPermissions shared.Role, project string, asset string,
) error {
	_, err := c.enforcer.AddRoleForUserInDomain(c.getProjectRoleName(projectRoleWhichGetsPermission, project), c.getAssetRoleName(assetRoleWhichProvidesPermissions, asset), "domain::"+c.domain)
	return err
}

func (c *casbinRBAC) getProjectRoleName(role shared.Role, project string) string {
	return "project::" + project + "|role::" + string(role)
}

func (c *casbinRBAC) getAssetRoleName(role shared.Role, asset string) string {
	return "asset::" + asset + "|role::" + string(role)
}

func (c *casbinRBAC) RevokeRole(user string, role shared.Role) error {
	_, err := c.enforcer.DeleteRoleForUserInDomain("user::"+user, "role::"+string(role), "domain::"+c.domain)

	return err
}

func (c *casbinRBAC) RevokeAllRolesInProjectForUser(user string, project string) error {
	for _, role := range []shared.Role{shared.RoleOwner, shared.RoleAdmin, shared.RoleMember} {
		err := c.RevokeRoleInProject(user, role, project)
		if err != nil {
			return fmt.Errorf("could not revoke role %s for user %s in project %s: %w", role, user, project, err)
		}
	}
	return nil
}

func (c *casbinRBAC) RevokeAllRolesInAssetForUser(user string, asset string) error {
	for _, role := range []shared.Role{shared.RoleOwner, shared.RoleAdmin, shared.RoleMember} {
		err := c.RevokeRoleInAsset(user, role, asset)
		if err != nil {
			return fmt.Errorf("could not revoke role %s for user %s in project %s: %w", role, user, asset, err)
		}
	}
	return nil
}

func (c *casbinRBAC) AllowRole(role shared.Role, object shared.Object, action []shared.Action) error {
	policies := make([][]string, len(action))
	for i, ac := range action {
		policies[i] = []string{"role::" + string(role), "domain::" + c.domain, "obj::" + string(object), "act::" + string(ac)}
	}

	_, err := c.enforcer.AddPolicies(policies)
	return err
}

func (c *casbinRBAC) AllowRoleInProject(project string, role shared.Role, object shared.Object, action []shared.Action) error {
	policies := make([][]string, len(action))
	for i, ac := range action {
		policies[i] = []string{"project::" + project + "|role::" + string(role), "domain::" + c.domain, "project::" + project + "|obj::" + string(object), "act::" + string(ac)}
	}
	_, err := c.enforcer.AddPolicies(policies)
	return err
}

func (c *casbinRBAC) AllowRoleInAsset(asset string, role shared.Role, object shared.Object, action []shared.Action) error {
	policies := make([][]string, len(action))
	for i, ac := range action {
		policies[i] = []string{"asset::" + asset + "|role::" + string(role), "domain::" + c.domain, "asset::" + asset + "|obj::" + string(object), "act::" + string(ac)}
	}
	_, err := c.enforcer.AddPolicies(policies)
	return err
}

func (c *casbinRBAC) GrantRoleInProject(user string, role shared.Role, project string) error {
	_, err := c.enforcer.AddRoleForUserInDomain("user::"+user, "project::"+project+"|role::"+string(role), "domain::"+c.domain)
	return err
}

func (c *casbinRBAC) GrantRoleInAsset(user string, role shared.Role, asset string) error {
	_, err := c.enforcer.AddRoleForUserInDomain("user::"+user, "asset::"+asset+"|role::"+string(role), "domain::"+c.domain)
	return err
}

func (c *casbinRBAC) RevokeRoleInProject(user string, role shared.Role, project string) error {
	_, err := c.enforcer.DeleteRoleForUserInDomain("user::"+user, "project::"+project+"|role::"+string(role), "domain::"+c.domain)
	return err
}

func (c *casbinRBAC) RevokeRoleInAsset(user string, role shared.Role, project string) error {
	_, err := c.enforcer.DeleteRoleForUserInDomain("user::"+user, "asset::"+project+"|role::"+string(role), "domain::"+c.domain)
	return err
}

func (c *casbinRBAC) IsAllowed(user string, object shared.Object, action shared.Action) (bool, error) {
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

func (c *casbinRBAC) IsAllowedInProject(project *models.Project, user string, object shared.Object, action shared.Action) (bool, error) {
	permissions, err := c.enforcer.GetImplicitPermissionsForUser("user::"+user, "domain::"+c.domain)
	if err != nil {
		return false, err
	}

	projectID := project.ID.String()
	// check for the permissions
	for _, p := range permissions {
		if p[2] == "project::"+projectID+"|obj::"+string(object) && p[3] == "act::"+string(action) {
			return true, nil
		}
	}
	return false, nil
}

func (c *casbinRBAC) IsAllowedInAsset(asset *models.Asset, user string, object shared.Object, action shared.Action) (bool, error) {
	permissions, err := c.enforcer.GetImplicitPermissionsForUser("user::"+user, "domain::"+c.domain)
	if err != nil {
		return false, err
	}

	assetID := asset.ID.String()
	// check for the permissions
	for _, p := range permissions {
		if p[2] == "asset::"+assetID+"|obj::"+string(object) && p[3] == "act::"+string(action) {
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
func NewCasbinRBACProvider(db *gorm.DB, broker shared.PubSubBroker) (casbinRBACProvider, error) {
	enforcer, err := buildEnforcer(db, broker)
	if err != nil {
		return casbinRBACProvider{}, err
	}
	return casbinRBACProvider{
		enforcer: enforcer,
	}, nil
}

func buildEnforcer(db *gorm.DB, broker shared.PubSubBroker) (*casbin.SyncedEnforcer, error) {
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
	path := os.Getenv("RBAC_CONFIG_PATH")
	if path == "" {
		path = "config/rbac_model.conf"
	}

	e, err := casbin.NewSyncedEnforcer(path, a)
	if err != nil {
		return nil, err
	}

	e.EnableLog(false)
	// make sure to publish a pub sub message when the policy changes
	watcher := newCasbinPubSubWatcher(broker)
	err = e.SetWatcher(watcher)
	if err != nil {
		return nil, fmt.Errorf("could not set watcher: %w", err)
	}
	// make sure to set the update callback
	err = watcher.SetUpdateCallback(func(string) {
		err := e.LoadPolicy()
		if err != nil {
			slog.Error("error while loading policy after update", "err", err)
		} else {
			slog.Debug("policy successfully reloaded after update")
		}
	})
	if err != nil {
		return nil, fmt.Errorf("could not set update callback: %w", err)
	}

	// Load the policy from DB.
	if err = e.LoadPolicy(); err != nil {
		log.Println("LoadPolicy failed, err: ", err)
	}

	casbinEnforcer = e

	return e, nil
}
