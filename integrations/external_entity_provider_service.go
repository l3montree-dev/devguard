package integrations

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"

	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/labstack/echo/v4"
	"golang.org/x/sync/singleflight"
	"gorm.io/gorm/clause"
)

type externalEntityProviderService struct {
	projectService         shared.ProjectService
	assetRepository        shared.AssetRepository
	projectRepository      shared.ProjectRepository
	rbacProvider           shared.RBACProvider
	singleFlightGroup      *singleflight.Group
	organizationRepository shared.OrganizationRepository
	assetService           shared.AssetService
}

func NewExternalEntityProviderService(
	projectService shared.ProjectService,
	assetService shared.AssetService,
	assetRepository shared.AssetRepository,
	projectRepository shared.ProjectRepository,
	rbacProvider shared.RBACProvider,
	organizationRepository shared.OrganizationRepository,

) externalEntityProviderService {
	return externalEntityProviderService{
		projectService:         projectService,
		assetRepository:        assetRepository,
		projectRepository:      projectRepository,
		rbacProvider:           rbacProvider,
		singleFlightGroup:      &singleflight.Group{},
		organizationRepository: organizationRepository,
		assetService:           assetService,
	}
}

func (s externalEntityProviderService) TriggerSync(c echo.Context) error {
	org := shared.GetOrg(c)
	if org.IsExternalEntity() {
		// Trigger the sync for the external entity provider projects
		err := s.RefreshExternalEntityProviderProjects(c, org, shared.GetSession(c).GetUserID())
		if err != nil {
			return echo.NewHTTPError(500, "could not trigger sync").WithInternal(err)
		}
		return c.NoContent(204)
	}
	return echo.NewHTTPError(400, "organization is not an external entity provider")
}

func (s externalEntityProviderService) TriggerOrgSync(c echo.Context) error {
	orgs, err := s.SyncOrgs(c)
	if err != nil {
		return echo.NewHTTPError(500, "could not sync organizations").WithInternal(err)
	}

	return c.JSON(200, utils.Map(orgs, func(o *models.Org) dtos.OrgDTO {
		return org.FromModel(*o)
	}))
}

func (s externalEntityProviderService) SyncOrgs(c echo.Context) ([]*models.Org, error) {
	// return the enabled git providers as well
	thirdPartyIntegration := shared.GetThirdPartyIntegration(c)
	userID := shared.GetSession(c).GetUserID()
	orgs, err, _ := s.singleFlightGroup.Do("syncOrgs/"+userID, func() (any, error) {
		orgs, err := thirdPartyIntegration.ListOrgs(c)
		if err != nil {
			return nil, fmt.Errorf("could not list organizations: %w", err)
		}

		orgsPtr := utils.Map(orgs, utils.Ptr)

		// make sure, that the third party organizations exists inside the database
		if err := s.organizationRepository.Upsert(&orgsPtr, []clause.Column{
			{Name: "external_entity_provider_id"},
		}, nil); err != nil {
			return nil, fmt.Errorf("could not upsert organizations: %w", err)
		}

		// make sure the user is a member of the organizations
		for _, org := range orgsPtr {
			if err := shared.BootstrapOrg(s.rbacProvider.GetDomainRBAC(org.GetID().String()), userID, shared.RoleMember); err != nil {
				slog.Warn("could not bootstrap organization", "orgID", org.GetID(), "err", err)
			}
		}

		return orgsPtr, nil
	})

	if err != nil {
		return nil, fmt.Errorf("could not sync organizations: %w", err)
	}

	return orgs.([]*models.Org), nil
}

func (s externalEntityProviderService) RefreshExternalEntityProviderProjects(ctx shared.Context, org models.Org, user string) error {

	_, err, shared := s.singleFlightGroup.Do(org.ID.String()+"/"+user, func() (any, error) {
		if org.ExternalEntityProviderID == nil {
			return nil, fmt.Errorf("organization %s does not have an external entity provider configured", org.GetID())
		}

		domainRBAC := s.rbacProvider.GetDomainRBAC(org.GetID().String())
		allowedProjects, err := domainRBAC.GetAllProjectsForUser(user)
		if err != nil {
			return nil, fmt.Errorf("could not get allowed projects for user %s: %w", user, err)
		}

		allowedAssets, err := domainRBAC.GetAllAssetsForUser(user)
		if err != nil {
			return nil, fmt.Errorf("could not get allowed assets for user %s: %w", user, err)
		}

		projects, roles, err := s.fetchExternalProjects(ctx, user, *org.ExternalEntityProviderID)
		if err != nil {
			return nil, err
		}

		created, updated, err := s.upsertProjects(org, projects, *org.ExternalEntityProviderID)
		if err != nil {
			return nil, err
		}

		if err := s.enableCommunityPoliciesForNewProjects(created); err != nil {
			return nil, err
		}

		projectsMap := s.createProjectsMap(created, updated)

		assets, err := s.syncProjectsAndAssets(ctx, domainRBAC, user, projects, roles, append(created, updated...))
		if err != nil {
			return nil, err
		}

		assetsMap := make(map[string]struct{}, len(assets))
		for _, asset := range assets {
			assetsMap[asset.ID.String()] = struct{}{}
		}

		s.revokeAccessForRemovedProjects(domainRBAC, user, allowedProjects, projectsMap)
		s.revokeAccessForRemovedAssets(domainRBAC, user, allowedAssets, assetsMap)

		return nil, nil
	})

	slog.Info("external entity provider projects sync completed", "orgID", org.GetID(), "user", user, "shared", shared)
	return err
}

func (s externalEntityProviderService) fetchExternalProjects(ctx shared.Context, user, providerID string) ([]models.Project, []shared.Role, error) {
	thirdPartyIntegration := shared.GetThirdPartyIntegration(ctx)
	projects, roles, err := thirdPartyIntegration.ListGroups(context.TODO(), user, providerID)
	if err != nil {
		return nil, nil, fmt.Errorf("could not list projects for user %s: %w", user, err)
	}
	return projects, roles, nil
}

func (s externalEntityProviderService) upsertProjects(org models.Org, projects []models.Project, providerID string) ([]models.Project, []models.Project, error) {
	// make sure the projects exist inside the database
	toUpsert := make([]*models.Project, 0, len(projects))
	for i := range projects {
		toUpsert = append(toUpsert, &projects[i])
		projects[i].OrganizationID = org.GetID() // ensure the organization ID is set
	}

	createdPtrs, updatedPtrs, err := s.projectRepository.UpsertSplit(nil, providerID, toUpsert)
	if err != nil {
		return nil, nil, fmt.Errorf("could not upsert projects: %w", err)
	}

	// Convert pointers to values
	created := make([]models.Project, len(createdPtrs))
	for i, ptr := range createdPtrs {
		created[i] = *ptr
	}

	updated := make([]models.Project, len(updatedPtrs))
	for i, ptr := range updatedPtrs {
		updated[i] = *ptr
	}

	slog.Info("upserted projects from external entity provider", "created", len(created), "updated", len(updated))
	return created, updated, nil
}

func (s externalEntityProviderService) enableCommunityPoliciesForNewProjects(created []models.Project) error {
	for _, project := range created {
		if err := s.projectRepository.EnableCommunityManagedPolicies(nil, project.ID); err != nil {
			return fmt.Errorf("could not enable community managed policies for project %s: %w", project.Slug, err)
		}
		slog.Info("enabled community managed policies for project", "projectSlug", project.Slug, "projectID", project.ID)
	}
	return nil
}

func (s externalEntityProviderService) createProjectsMap(created, updated []models.Project) map[string]struct{} {
	projectsMap := make(map[string]struct{}, len(created)+len(updated))
	for _, project := range append(created, updated...) {
		projectsMap[project.ID.String()] = struct{}{}
	}
	return projectsMap
}

func (s externalEntityProviderService) syncProjectsAndAssets(ctx shared.Context, domainRBAC shared.AccessControl, user string, originalProjects []models.Project, roles []shared.Role, projects []models.Project) ([]*models.Asset, error) {
	wg := utils.ErrGroup[[]*models.Asset](10)
	for i, project := range projects {
		wg.Go(func() ([]*models.Asset, error) {
			assets, err := s.syncSingleProject(ctx, domainRBAC, user, &originalProjects[i], roles[i], &project)
			if err != nil {
				slog.Error("could not sync project", "projectSlug", project.Slug, "projectID", project.ID, "err", err)
				// swallow the error right here
				return nil, nil
			}
			return assets, nil
		})

	}
	assets, err := wg.WaitAndCollect()
	if err != nil {
		return nil, err
	}

	// flatten the assets slice
	return utils.Flat(assets), nil
}

func (s externalEntityProviderService) syncSingleProject(ctx shared.Context, domainRBAC shared.AccessControl, user string, originalProject *models.Project, userRole shared.Role, project *models.Project) ([]*models.Asset, error) {
	if err := s.projectService.BootstrapProject(domainRBAC, originalProject); err != nil {
		return nil, fmt.Errorf("could not bootstrap project: %w", err)
	}

	if err := s.updateUserRole(domainRBAC, user, userRole, project.ID.String()); err != nil {
		return nil, err
	}

	return s.syncProjectAssets(ctx, user, project)
}

func (s externalEntityProviderService) updateUserRole(domainRBAC shared.AccessControl, user string, userRole shared.Role, projectID string) error {
	currentRole, _ := domainRBAC.GetProjectRole(user, projectID) // swallow the error here - if an error happens means the user is not part of the project

	if currentRole == userRole || userRole == "" {
		return nil // user already has the correct role
	}

	if err := domainRBAC.RevokeRoleInProject(user, currentRole, projectID); err != nil {
		slog.Warn("could not revoke role for user", "user", user, "role", currentRole, "projectID", projectID, "err", err)
		// we don't care if the user does not have the role
	}

	if err := domainRBAC.GrantRoleInProject(user, userRole, projectID); err != nil {
		slog.Warn("could not grant role for user", "user", user, "role", userRole, "projectID", projectID, "err", err)
		// we don't care if the user already has the role
	}

	return nil
}

func (s externalEntityProviderService) updateUserRoleInAsset(domainRBAC shared.AccessControl, user string, userRole shared.Role, assetID string) error {
	currentRole, _ := domainRBAC.GetAssetRole(user, assetID) // swallow the error here - if an error happens means the user is not part of the asset

	if currentRole == userRole || userRole == "" {
		return nil // user already has the correct role
	}
	if err := domainRBAC.RevokeRoleInAsset(user, currentRole, assetID); err != nil {
		slog.Warn("could not revoke role for user", "user", user, "role", currentRole, "assetID", assetID, "err", err)
		// we don't care if the user does not have the role
	}

	if err := domainRBAC.GrantRoleInAsset(user, userRole, assetID); err != nil {
		slog.Warn("could not grant role for user", "user", user, "role", userRole, "assetID", assetID, "err", err)
		// we don't care if the user already has the role
	}

	return nil
}

func (s externalEntityProviderService) syncProjectAssets(ctx shared.Context, user string, project *models.Project) ([]*models.Asset, error) {
	thirdPartyIntegration := shared.GetThirdPartyIntegration(ctx)
	domainRBAC := shared.GetRBAC(ctx)

	assets, roles, err := thirdPartyIntegration.ListProjects(context.TODO(), user, *project.ExternalEntityProviderID, *project.ExternalEntityID)
	if err != nil {
		return nil, fmt.Errorf("could not list assets for project %s: %w", project.Slug, err)
	}

	// ensure the assets exist in the database
	toUpsert := make([]*models.Asset, 0, len(assets))
	for i := range assets {
		assets[i].ProjectID = project.ID
		toUpsert = append(toUpsert, &assets[i])
	}

	if err := s.assetRepository.Upsert(&toUpsert, []clause.Column{
		{Name: "external_entity_provider_id"},
		{Name: "external_entity_id"},
	}, []string{"project_id", "slug", "description", "name", "avatar"}); err != nil {
		return nil, fmt.Errorf("could not upsert assets for project %s: %w", project.Slug, err)
	}

	for i, asset := range toUpsert {
		if err := s.assetService.BootstrapAsset(domainRBAC, asset); err != nil {
			return nil, fmt.Errorf("could not bootstrap asset %s: %w", asset.Slug, err)
		}

		// make sure to update the role for the user on the asset
		if err := s.updateUserRoleInAsset(domainRBAC, user, roles[i], asset.ID.String()); err != nil {
			return nil, fmt.Errorf("could not update user role in asset %s: %w", asset.Slug, err)
		}
	}

	return toUpsert, nil
}

func (s externalEntityProviderService) revokeAccessForRemovedProjects(domainRBAC shared.AccessControl, user string, allowedProjects []string, projectsMap map[string]struct{}) {
	// maybe we need to revoke some access for projects that no longer exist
	for _, project := range allowedProjects {
		if _, ok := projectsMap[project]; !ok {
			// project no longer exists, revoke access
			if err := domainRBAC.RevokeAllRolesInProjectForUser(user, project); err != nil {
				slog.Warn("could not revoke all roles for user", "user", user, "projectID", project, "err", err)
			}
		}
	}
}

func (s externalEntityProviderService) revokeAccessForRemovedAssets(domainRBAC shared.AccessControl, user string, allowedAssets []string, assetsMap map[string]struct{}) {
	// maybe we need to revoke some access for assets that no longer exist
	for _, asset := range allowedAssets {
		if _, ok := assetsMap[asset]; !ok {
			// asset no longer exists, revoke access
			if err := domainRBAC.RevokeAllRolesInAssetForUser(user, asset); err != nil {
				slog.Warn("could not revoke all roles for user", "user", user, "assetID", asset, "err", err)
			}
		}
	}
}
