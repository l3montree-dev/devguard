package accesscontrol

import (
	"context"

	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
)

type externalEntityProviderRBAC struct {
	thirdPartyIntegration    core.ThirdPartyIntegration
	externalEntityProviderID string
	externalEntityID         string
	adminToken               string
	ctx                      core.Context
}

func isRoleAllowedToPerformAction(role string, action core.Action) bool {
	switch action {
	case core.ActionRead:
		return role == core.RoleMember || role == core.RoleAdmin || role == core.RoleOwner
	case core.ActionUpdate:
		return role == core.RoleAdmin || role == core.RoleOwner
	case core.ActionDelete:
		return role == core.RoleOwner
	case core.ActionCreate:
		return role == core.RoleAdmin || role == core.RoleOwner
	}
	return false
}

func NewExternalEntityProviderRBAC(ctx core.Context, thirdPartyIntegration core.ThirdPartyIntegration, externalEntityProviderID string, adminToken string) core.AccessControl {
	return &externalEntityProviderRBAC{
		thirdPartyIntegration:    thirdPartyIntegration,
		externalEntityProviderID: externalEntityProviderID,
		adminToken:               adminToken,
		ctx:                      ctx,
	}
}

func (e *externalEntityProviderRBAC) GetExternalEntityProviderID() *string {
	return &e.externalEntityProviderID
}

/*
	HasAccess(subject string) bool

	InheritRole(roleWhichGetsPermissions, roleWhichProvidesPermissions string) error

	GetAllRoles(user string) []string

	GrantRole(subject string, role string) error
	RevokeRole(subject string, role string) error

	GrantRoleInProject(subject string, role string, project string) error
	RevokeRoleInProject(subject string, role string, project string) error
	InheritProjectRole(roleWhichGetsPermissions, roleWhichProvidesPermissions string, project string) error

	InheritProjectRolesAcrossProjects(roleWhichGetsPermissions, roleWhichProvidesPermissions ProjectRole) error

	LinkDomainAndProjectRole(domainRoleWhichGetsPermission, projectRoleWhichProvidesPermissions string, project string) error

	AllowRole(role string, object string, action []Action) error
	IsAllowed(subject string, object string, action Action) (bool, error)

	IsAllowedInProject(project, user string, object string, action Action) (bool, error)
	AllowRoleInProject(project string, role string, object string, action []Action) error

	GetAllProjectsForUser(user string) []string

	GetOwnerOfOrganization() (string, error)

	GetAllMembersOfOrganization() ([]string, error)

	GetAllMembersOfProject(projectID string) ([]string, error)

	GetDomainRole(user string) (string, error)
	GetProjectRole(user string, project string) (string, error)
*/

func (e *externalEntityProviderRBAC) HasAccess(userID string) (bool, error) {
	if userID == e.adminToken {
		return true, nil
	}
	return e.thirdPartyIntegration.HasAccessToExternalEntityProvider(e.ctx, e.externalEntityProviderID)
}

func (e *externalEntityProviderRBAC) InheritRole(roleWhichGetsPermissions, roleWhichProvidesPermissions string) error {
	return nil
}

func (e *externalEntityProviderRBAC) GetAllRoles(user string) []string {
	return []string{}
}
func (e *externalEntityProviderRBAC) GrantRole(subject string, role string) error {
	return nil
}
func (e *externalEntityProviderRBAC) RevokeRole(subject string, role string) error {
	return nil
}
func (e *externalEntityProviderRBAC) GrantRoleInProject(subject string, role string, project string) error {
	return nil
}
func (e *externalEntityProviderRBAC) RevokeRoleInProject(subject string, role string, project string) error {
	return nil
}
func (e *externalEntityProviderRBAC) InheritProjectRole(roleWhichGetsPermissions, roleWhichProvidesPermissions string, project string) error {
	return nil
}
func (e *externalEntityProviderRBAC) InheritProjectRolesAcrossProjects(roleWhichGetsPermissions, roleWhichProvidesPermissions core.ProjectRole) error {
	return nil
}
func (e *externalEntityProviderRBAC) LinkDomainAndProjectRole(domainRoleWhichGetsPermission, projectRoleWhichProvidesPermissions string, project string) error {
	return nil
}
func (e *externalEntityProviderRBAC) AllowRole(role string, object core.Object, action []core.Action) error {
	return nil
}
func (e *externalEntityProviderRBAC) IsAllowed(userID string, object core.Object, action core.Action) (bool, error) {
	if userID == e.adminToken && action == core.ActionRead {
		return true, nil
	}
	if object == core.ObjectOrganization {
		// all users have read only access to this organization
		if action == core.ActionRead {
			return true, nil
		}
	}
	role, err := e.thirdPartyIntegration.GetRoleInProject(context.TODO(), userID, e.externalEntityProviderID, e.externalEntityID)
	if err != nil {
		return false, err
	}

	return isRoleAllowedToPerformAction(role, action), nil
}

func (e *externalEntityProviderRBAC) IsAllowedInProject(project *models.Project, user string, object core.Object, action core.Action) (bool, error) {
	// check for external entity provider ids
	if project.ExternalEntityProviderID == nil || project.ExternalEntityID == nil {
		return false, nil
	}
	if user == e.adminToken && action == core.ActionRead {
		return true, nil
	}

	role, err := e.thirdPartyIntegration.GetRoleInGroup(context.TODO(), user, *project.ExternalEntityProviderID, *project.ExternalEntityID)
	if err != nil {
		return false, err
	}

	return isRoleAllowedToPerformAction(role, action), nil
}

func (e *externalEntityProviderRBAC) AllowRoleInProject(project string, role string, object core.Object, action []core.Action) error {
	// This method is not applicable for external entity provider RBAC
	return nil
}

func (e *externalEntityProviderRBAC) GetAllProjectsForUser(user string) (any, error) {
	// This method is not applicable for external entity provider RBAC
	return e.thirdPartyIntegration.ListGroups(e.ctx, user, e.externalEntityProviderID)
}

func (e *externalEntityProviderRBAC) GetOwnerOfOrganization() (string, error) {
	// This method is not applicable for external entity provider RBAC
	return "", nil
}

func (e *externalEntityProviderRBAC) GetAllMembersOfOrganization() ([]string, error) {
	// This method is not applicable for external entity provider RBAC
	return []string{}, nil
}

func (e *externalEntityProviderRBAC) GetAllMembersOfProject(projectID string) ([]string, error) {
	// This method is not applicable for external entity provider RBAC
	return []string{}, nil
}

func (e *externalEntityProviderRBAC) GetDomainRole(user string) (string, error) {
	// This method is not applicable for external entity provider RBAC
	return "", nil
}

func (e *externalEntityProviderRBAC) GetProjectRole(user string, project string) (string, error) {
	// This method is not applicable for external entity provider RBAC
	return "", nil
}
