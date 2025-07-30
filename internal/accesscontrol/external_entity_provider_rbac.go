package accesscontrol

import (
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
)

type externalEntityProviderRBAC struct {
	thirdPartyIntegration    core.ThirdPartyIntegration
	externalEntityProviderID string
	externalEntityID         string
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

func (e *externalEntityProviderRBAC) InheritRole(roleWhichGetsPermissions, roleWhichProvidesPermissions core.Role) error {
	return nil
}

func (e *externalEntityProviderRBAC) GetAllRoles(user string) []string {
	return []string{}
}
func (e *externalEntityProviderRBAC) GrantRole(subject string, role core.Role) error {
	return nil
}
func (e *externalEntityProviderRBAC) RevokeRole(subject string, role core.Role) error {
	return nil
}
func (e *externalEntityProviderRBAC) GrantRoleInProject(subject string, role core.Role, project string) error {
	return nil
}
func (e *externalEntityProviderRBAC) RevokeRoleInProject(subject string, role core.Role, project string) error {
	return nil
}
func (e *externalEntityProviderRBAC) InheritProjectRole(roleWhichGetsPermissions, roleWhichProvidesPermissions core.Role, project string) error {
	return nil
}
func (e *externalEntityProviderRBAC) InheritProjectRolesAcrossProjects(roleWhichGetsPermissions, roleWhichProvidesPermissions core.ProjectRole) error {
	return nil
}
func (e *externalEntityProviderRBAC) LinkDomainAndProjectRole(domainRoleWhichGetsPermission, projectRoleWhichProvidesPermissions core.Role, project string) error {
	return nil
}
func (e *externalEntityProviderRBAC) AllowRole(role core.Role, object core.Object, action []core.Action) error {
	return nil
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
	// This method is not applicable for external entity provider RBAC
	return nil
}

func (e *externalEntityProviderRBAC) GetAllProjectsForUser(user string) ([]string, error) {
	// This method is not applicable for external entity provider RBAC
	return e.rootAccessControl.GetAllProjectsForUser(user)
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

func (e *externalEntityProviderRBAC) GetDomainRole(user string) (core.Role, error) {
	// This method is not applicable for external entity provider RBAC
	return "", nil
}

func (e *externalEntityProviderRBAC) GetProjectRole(user string, project string) (core.Role, error) {
	// This method is not applicable for external entity provider RBAC
	return "", nil
}
