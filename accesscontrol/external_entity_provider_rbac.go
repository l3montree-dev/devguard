package accesscontrol

import (
	"context"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/shared"
)

type externalEntityProviderRBAC struct {
	thirdPartyIntegration    shared.IntegrationAggregate
	externalEntityProviderID string
	ctx                      shared.Context

	rootAccessControl shared.AccessControl
}

var _ shared.AccessControl = (*externalEntityProviderRBAC)(nil)

func NewExternalEntityProviderRBAC(ctx shared.Context, rootAccessControl shared.AccessControl, thirdPartyIntegration shared.IntegrationAggregate, externalEntityProviderID string) *externalEntityProviderRBAC {
	return &externalEntityProviderRBAC{
		thirdPartyIntegration:    thirdPartyIntegration,
		externalEntityProviderID: externalEntityProviderID,
		ctx:                      ctx,
		rootAccessControl:        rootAccessControl,
	}
}

func (e *externalEntityProviderRBAC) GetExternalEntityProviderID() *string {
	return &e.externalEntityProviderID
}

func (e *externalEntityProviderRBAC) GetAllAssetsForUser(user string) ([]string, error) {
	return e.rootAccessControl.GetAllAssetsForUser(user)
}

func (e *externalEntityProviderRBAC) RevokeAllRolesInAssetForUser(ctx context.Context, user string, asset string) error {
	return e.rootAccessControl.RevokeAllRolesInAssetForUser(ctx, user, asset)
}

func (e *externalEntityProviderRBAC) HasAccess(ctx context.Context, userID string) (bool, error) {
	return e.thirdPartyIntegration.HasAccessToExternalEntityProvider(e.ctx, e.externalEntityProviderID)
}

func (e *externalEntityProviderRBAC) RevokeAllRolesInProjectForUser(ctx context.Context, user string, project string) error {
	return e.rootAccessControl.RevokeAllRolesInProjectForUser(ctx, user, project)
}

func (e *externalEntityProviderRBAC) InheritRole(ctx context.Context, roleWhichGetsPermissions, roleWhichProvidesPermissions shared.Role) error {
	return e.rootAccessControl.InheritRole(ctx, roleWhichGetsPermissions, roleWhichProvidesPermissions)
}

func (e *externalEntityProviderRBAC) GetAssetRole(user string, asset string) (shared.Role, error) {
	return e.rootAccessControl.GetAssetRole(user, asset)
}

func (e *externalEntityProviderRBAC) GetAllRoles(user string) []string {
	return e.rootAccessControl.GetAllRoles(user)
}

func (e *externalEntityProviderRBAC) GrantRole(ctx context.Context, subject string, role shared.Role) error {
	return e.rootAccessControl.GrantRole(ctx, subject, role)
}

func (e *externalEntityProviderRBAC) RevokeRole(ctx context.Context, subject string, role shared.Role) error {
	return e.rootAccessControl.RevokeRole(ctx, subject, role)
}

func (e *externalEntityProviderRBAC) GrantRoleInProject(ctx context.Context, subject string, role shared.Role, project string) error {
	return e.rootAccessControl.GrantRoleInProject(ctx, subject, role, project)
}

func (e *externalEntityProviderRBAC) RevokeRoleInProject(ctx context.Context, subject string, role shared.Role, project string) error {
	return e.rootAccessControl.RevokeRoleInProject(ctx, subject, role, project)
}

func (e *externalEntityProviderRBAC) InheritProjectRole(ctx context.Context, roleWhichGetsPermissions, roleWhichProvidesPermissions shared.Role, project string) error {
	return e.rootAccessControl.InheritProjectRole(ctx, roleWhichGetsPermissions, roleWhichProvidesPermissions, project)
}

func (e *externalEntityProviderRBAC) InheritAssetRole(ctx context.Context, roleWhichGetsPermissions, roleWhichProvidesPermissions shared.Role, asset string) error {
	return e.rootAccessControl.InheritAssetRole(ctx, roleWhichGetsPermissions, roleWhichProvidesPermissions, asset)
}

func (e *externalEntityProviderRBAC) InheritProjectRolesAcrossProjects(ctx context.Context, roleWhichGetsPermissions, roleWhichProvidesPermissions shared.ProjectRole) error {
	return e.rootAccessControl.InheritProjectRolesAcrossProjects(ctx, roleWhichGetsPermissions, roleWhichProvidesPermissions)
}

func (e *externalEntityProviderRBAC) LinkDomainAndProjectRole(ctx context.Context, domainRoleWhichGetsPermission, projectRoleWhichProvidesPermissions shared.Role, project string) error {
	return e.rootAccessControl.LinkDomainAndProjectRole(ctx, domainRoleWhichGetsPermission, projectRoleWhichProvidesPermissions, project)
}

func (e *externalEntityProviderRBAC) LinkProjectAndAssetRole(ctx context.Context, projectRoleWhichGetsPermission, assetRoleWhichProvidesPermissions shared.Role, project, asset string) error {
	return e.rootAccessControl.LinkProjectAndAssetRole(ctx, projectRoleWhichGetsPermission, assetRoleWhichProvidesPermissions, project, asset)
}

func (e *externalEntityProviderRBAC) AllowRole(ctx context.Context, role shared.Role, object shared.Object, action []shared.Action) error {
	return e.rootAccessControl.AllowRole(ctx, role, object, action)
}

func (e *externalEntityProviderRBAC) IsAllowed(ctx context.Context, userID string, object shared.Object, action shared.Action) (bool, error) {
	// ALLOW ORG read access for all users - this is pretty much the same as HasAccess.
	if object == shared.ObjectOrganization && action == shared.ActionRead {
		return true, nil
	}

	return e.rootAccessControl.IsAllowed(ctx, userID, object, action)
}

func (e *externalEntityProviderRBAC) IsAllowedInProject(ctx context.Context, project *models.Project, user string, object shared.Object, action shared.Action) (bool, error) {
	if project.ExternalEntityProviderID == nil || project.ExternalEntityID == nil {
		return false, nil
	}
	return e.rootAccessControl.IsAllowedInProject(ctx, project, user, object, action)
}

func (e *externalEntityProviderRBAC) AllowRoleInProject(ctx context.Context, project string, role shared.Role, object shared.Object, action []shared.Action) error {
	return e.rootAccessControl.AllowRoleInProject(ctx, project, role, object, action)
}

func (e *externalEntityProviderRBAC) GetAllProjectsForUser(user string) ([]string, error) {
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

func (e *externalEntityProviderRBAC) GetAllMembersOfAsset(assetID string) ([]string, error) {
	return e.rootAccessControl.GetAllMembersOfAsset(assetID)
}

func (e *externalEntityProviderRBAC) GetDomainRole(user string) (shared.Role, error) {
	return e.rootAccessControl.GetDomainRole(user)
}

func (e *externalEntityProviderRBAC) GetProjectRole(user string, project string) (shared.Role, error) {
	return e.rootAccessControl.GetProjectRole(user, project)
}

func (e *externalEntityProviderRBAC) GrantRoleInAsset(ctx context.Context, subject string, role shared.Role, asset string) error {
	return e.rootAccessControl.GrantRoleInAsset(ctx, subject, role, asset)
}

func (e *externalEntityProviderRBAC) RevokeRoleInAsset(ctx context.Context, subject string, role shared.Role, asset string) error {
	return e.rootAccessControl.RevokeRoleInAsset(ctx, subject, role, asset)
}

func (e *externalEntityProviderRBAC) IsAllowedInAsset(ctx context.Context, asset *models.Asset, user string, object shared.Object, action shared.Action) (bool, error) {
	if asset.ExternalEntityProviderID == nil || asset.ExternalEntityID == nil {
		return false, nil
	}
	return e.rootAccessControl.IsAllowedInAsset(ctx, asset, user, object, action)
}

func (e *externalEntityProviderRBAC) AllowRoleInAsset(ctx context.Context, asset string, role shared.Role, object shared.Object, action []shared.Action) error {
	return e.rootAccessControl.AllowRoleInAsset(ctx, asset, role, object, action)
}
