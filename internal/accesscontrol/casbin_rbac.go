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

import (
	"log"

	gormadapter "github.com/casbin/gorm-adapter/v3"

	"github.com/casbin/casbin/v2"
	"gorm.io/gorm"
)

var _ AccessControl = &CasbinRBAC{}
var casbinEnforcer *casbin.Enforcer

type CasbinRBAC struct {
	domain   string // scopes this to a specific domain - or tenant
	enforcer *casbin.Enforcer
}

type CasbinRBACProvider struct {
	enforcer *casbin.Enforcer
}

func (c *CasbinRBACProvider) GetDomainRBAC(domain string) CasbinRBAC {
	return CasbinRBAC{
		domain:   domain,
		enforcer: c.enforcer,
	}
}

func (c *CasbinRBAC) HasAccess(user string) bool {
	roles := c.enforcer.GetRolesForUserInDomain("user::"+user, "domain::"+c.domain)
	return len(roles) > 0
}

func (c *CasbinRBAC) GrantRole(user, role string) error {
	_, err := c.enforcer.AddRoleForUserInDomain("user::"+user, "role::"+role, "domain::"+c.domain)
	return err
}

func (c *CasbinRBAC) RevokeRole(user, role string) error {
	_, err := c.enforcer.DeleteRoleForUserInDomain("user::"+user, "role::"+role, "domain::"+c.domain)
	return err
}

func (c *CasbinRBAC) IsAllowed(user, object, action string) (bool, error) {
	return c.enforcer.Enforce("user::"+user, "domain::"+c.domain, "obj::"+object, "act::"+action)
}

// the provider can be used to create domain specific RBAC instances
func NewCasbinRBACProvider(db *gorm.DB) (CasbinRBACProvider, error) {
	enforcer, err := buildEnforcer(db)
	if err != nil {
		return CasbinRBACProvider{}, err
	}
	return CasbinRBACProvider{
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

	// Load the policy from DB.
	if err = e.LoadPolicy(); err != nil {
		log.Println("LoadPolicy failed, err: ", err)
	}

	casbinEnforcer = e

	return e, nil
}
