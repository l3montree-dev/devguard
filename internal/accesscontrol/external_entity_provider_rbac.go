package accesscontrol

import (
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
)

type externalEntityProviderRBAC struct {
	thirdPartyIntegration    core.ThirdPartyIntegration
	externalEntityProviderID string
	adminToken               *string
	ctx                      core.Context

	rootAccessControl core.AccessControl
}

var _ core.AccessControl = (*externalEntityProviderRBAC)(nil)

func NewExternalEntityProviderRBAC(ctx core.Context, rootAccessControl core.AccessControl, thirdPartyIntegration core.ThirdPartyIntegration, externalEntityProviderID string, adminToken *string) *externalEntityProviderRBAC {
	return &externalEntityProviderRBAC{
		thirdPartyIntegration:    thirdPartyIntegration,
		externalEntityProviderID: externalEntityProviderID,
		adminToken:               adminToken,
		ctx:                      ctx,
		rootAccessControl:        rootAccessControl,
	}
}

func (e *externalEntityProviderRBAC) GetExternalEntityProviderID() *string {
	return &e.externalEntityProviderID
}

func (e *externalEntityProviderRBAC) HasAccess(userID string) (bool, error) {
	if e.adminToken != nil && userID == *e.adminToken {
		return true, nil
	}
	return e.thirdPartyIntegration.HasAccessToExternalEntityProvider(e.ctx, e.externalEntityProviderID)
}

func (e *externalEntityProviderRBAC) RevokeAllRolesInProjectForUser(user string, project string) error {
	return e.rootAccessControl.RevokeAllRolesInProjectForUser(user, project)
}

func (e *externalEntityProviderRBAC) InheritRole(roleWhichGetsPermissions, roleWhichProvidesPermissions core.Role) error {
	return e.rootAccessControl.InheritRole(roleWhichGetsPermissions, roleWhichProvidesPermissions)
}

func (e *externalEntityProviderRBAC) GetAllRoles(user string) []string {
	return e.rootAccessControl.GetAllRoles(user)
}
func (e *externalEntityProviderRBAC) GrantRole(subject string, role core.Role) error {
	return e.rootAccessControl.GrantRole(subject, role)
}
func (e *externalEntityProviderRBAC) RevokeRole(subject string, role core.Role) error {
	return e.rootAccessControl.RevokeRole(subject, role)
}
func (e *externalEntityProviderRBAC) GrantRoleInProject(subject string, role core.Role, project string) error {
	return e.rootAccessControl.GrantRoleInProject(subject, role, project)
}
func (e *externalEntityProviderRBAC) RevokeRoleInProject(subject string, role core.Role, project string) error {
	return e.rootAccessControl.RevokeRoleInProject(subject, role, project)
}
func (e *externalEntityProviderRBAC) InheritProjectRole(roleWhichGetsPermissions, roleWhichProvidesPermissions core.Role, project string) error {
	return e.rootAccessControl.InheritProjectRole(roleWhichGetsPermissions, roleWhichProvidesPermissions, project)
}
func (e *externalEntityProviderRBAC) InheritProjectRolesAcrossProjects(roleWhichGetsPermissions, roleWhichProvidesPermissions core.ProjectRole) error {
	return e.rootAccessControl.InheritProjectRolesAcrossProjects(roleWhichGetsPermissions, roleWhichProvidesPermissions)
}
func (e *externalEntityProviderRBAC) LinkDomainAndProjectRole(domainRoleWhichGetsPermission, projectRoleWhichProvidesPermissions core.Role, project string) error {
	return e.rootAccessControl.LinkDomainAndProjectRole(domainRoleWhichGetsPermission, projectRoleWhichProvidesPermissions, project)
}
func (e *externalEntityProviderRBAC) AllowRole(role core.Role, object core.Object, action []core.Action) error {
	return e.rootAccessControl.AllowRole(role, object, action)
}
func (e *externalEntityProviderRBAC) IsAllowed(userID string, object core.Object, action core.Action) (bool, error) {
	if e.adminToken != nil && userID == *e.adminToken {
		if action == core.ActionRead {
			return true, nil
		}
		return false, nil
	}

	// ALLOW ORG read access for all users - this is pretty much the same as HasAccess.
	if object == core.ObjectOrganization && action == core.ActionRead {
		return true, nil
	}

	return e.rootAccessControl.IsAllowed(userID, object, action)
}

func (e *externalEntityProviderRBAC) IsAllowedInProject(project *models.Project, user string, object core.Object, action core.Action) (bool, error) {
	// check for external entity provider ids
	if project.ExternalEntityProviderID == nil || project.ExternalEntityID == nil {
		return false, nil
	}
	if e.adminToken != nil && user == *e.adminToken && action == core.ActionRead {
		return true, nil
	}

	return e.rootAccessControl.IsAllowedInProject(project, user, object, action)
}

func (e *externalEntityProviderRBAC) AllowRoleInProject(project string, role core.Role, object core.Object, action []core.Action) error {
	return e.rootAccessControl.AllowRoleInProject(project, role, object, action)
}

func (e *externalEntityProviderRBAC) GetAllProjectsForUser(user string) ([]string, error) {
	// This method is not applicable for external entity provider RBAC
	return e.rootAccessControl.GetAllProjectsForUser(user)
}

func (e *externalEntityProviderRBAC) GetOwnerOfOrganization() (string, error) {
	return e.rootAccessControl.GetOwnerOfOrganization()
}

func (e *externalEntityProviderRBAC) GetAllMembersOfOrganization() ([]string, error) {
	return e.rootAccessControl.GetAllMembersOfOrganization()
}

func (e *externalEntityProviderRBAC) GetAllMembersOfProject(projectID string) ([]string, error) {
	return e.rootAccessControl.GetAllMembersOfProject(projectID)
}

func (e *externalEntityProviderRBAC) GetDomainRole(user string) (core.Role, error) {
	return e.rootAccessControl.GetDomainRole(user)
}

func (e *externalEntityProviderRBAC) GetProjectRole(user string, project string) (core.Role, error) {
	return e.rootAccessControl.GetProjectRole(user, project)
}
