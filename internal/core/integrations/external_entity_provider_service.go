package integrations

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/labstack/echo/v4"
	"golang.org/x/sync/singleflight"
	"gorm.io/gorm/clause"
)

type externalEntityProviderService struct {
	projectService    core.ProjectService
	assetRepository   core.AssetRepository
	projectRepository core.ProjectRepository
	rbacProvider      core.RBACProvider
	singleFlightGroup *singleflight.Group
}

func NewExternalEntityProviderService(
	projectService core.ProjectService,
	assetRepository core.AssetRepository,
	projectRepository core.ProjectRepository,
	rbacProvider core.RBACProvider,
) externalEntityProviderService {
	return externalEntityProviderService{
		projectService:    projectService,
		assetRepository:   assetRepository,
		projectRepository: projectRepository,
		rbacProvider:      rbacProvider,
		singleFlightGroup: &singleflight.Group{},
	}
}

func (s externalEntityProviderService) TriggerSync(c echo.Context) error {
	org := core.GetOrg(c)
	if org.IsExternalEntity() {
		// Trigger the sync for the external entity provider projects
		err := s.RefreshExternalEntityProviderProjects(c, org, core.GetSession(c).GetUserID())
		if err != nil {
			return echo.NewHTTPError(500, "could not trigger sync").WithInternal(err)
		}
		return c.NoContent(204)
	}
	return echo.NewHTTPError(400, "organization is not an external entity provider")
}

func (s externalEntityProviderService) RefreshExternalEntityProviderProjects(ctx core.Context, org models.Org, user string) error {
	_, err, shared := s.singleFlightGroup.Do(org.ID.String()+"/"+user, func() (any, error) {
		if org.ExternalEntityProviderID == nil {
			return nil, fmt.Errorf("organization %s does not have an external entity provider configured", org.GetID())
		}

		domainRBAC := s.rbacProvider.GetDomainRBAC(org.GetID().String())
		allowedProjects, err := s.getAllowedProjectsForUser(domainRBAC, user)
		if err != nil {
			return nil, err
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

		if err := s.syncProjectsAndAssets(ctx, domainRBAC, user, projects, roles, append(created, updated...)); err != nil {
			return nil, err
		}

		s.revokeAccessForRemovedProjects(domainRBAC, user, allowedProjects, projectsMap)

		return nil, nil
	})

	slog.Info("external entity provider projects sync completed", "orgID", org.GetID(), "user", user, "shared", shared)
	return err
}

func (s externalEntityProviderService) getAllowedProjectsForUser(domainRBAC core.AccessControl, user string) ([]string, error) {
	allowedProjects, err := domainRBAC.GetAllProjectsForUser(user)
	if err != nil {
		return nil, fmt.Errorf("could not get allowed projects for user %s: %w", user, err)
	}
	return allowedProjects, nil
}

func (s externalEntityProviderService) fetchExternalProjects(ctx core.Context, user, providerID string) ([]models.Project, []core.Role, error) {
	thirdPartyIntegration := core.GetThirdPartyIntegration(ctx)
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

func (s externalEntityProviderService) syncProjectsAndAssets(ctx core.Context, domainRBAC core.AccessControl, user string, originalProjects []models.Project, roles []core.Role, projects []models.Project) error {
	for i, project := range projects {
		if err := s.syncSingleProject(ctx, domainRBAC, user, &originalProjects[i], roles[i], &project); err != nil {
			slog.Error("could not sync project", "projectSlug", project.Slug, "projectID", project.ID, "err", err)
			continue
		}
	}
	return nil
}

func (s externalEntityProviderService) syncSingleProject(ctx core.Context, domainRBAC core.AccessControl, user string, originalProject *models.Project, userRole core.Role, project *models.Project) error {
	if err := s.projectService.BootstrapProject(domainRBAC, originalProject); err != nil {
		return fmt.Errorf("could not bootstrap project: %w", err)
	}

	if err := s.updateUserRole(domainRBAC, user, userRole, project.ID.String()); err != nil {
		return err
	}

	return s.syncProjectAssets(ctx, user, project)
}

func (s externalEntityProviderService) updateUserRole(domainRBAC core.AccessControl, user string, userRole core.Role, projectID string) error {
	currentRole, _ := domainRBAC.GetProjectRole(user, projectID) // swallow the error here - if an error happens means the user is not part of the project

	if currentRole == userRole {
		return nil // user already has the correct role
	}

	if err := domainRBAC.RevokeRoleInProject(user, currentRole, projectID); err != nil {
		slog.Warn("could not revoke role for user", "user", user, "role", currentRole, "projectID", projectID, "err", err)
		// we don't care if the user does not have the role
	} else {
		slog.Info("revoked role for user", "user", user, "role", currentRole, "projectID", projectID)
	}

	if err := domainRBAC.GrantRoleInProject(user, userRole, projectID); err != nil {
		slog.Warn("could not grant role for user", "user", user, "role", userRole, "projectID", projectID, "err", err)
		// we don't care if the user already has the role
	}

	return nil
}

func (s externalEntityProviderService) syncProjectAssets(ctx core.Context, user string, project *models.Project) error {
	thirdPartyIntegration := core.GetThirdPartyIntegration(ctx)

	assets, _, err := thirdPartyIntegration.ListProjects(context.TODO(), user, *project.ExternalEntityProviderID, *project.ExternalEntityID)
	if err != nil {
		return echo.NewHTTPError(500, "could not fetch assets for project").WithInternal(err)
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
	}, []string{"project_id", "slug", "description", "name"}); err != nil {
		return echo.NewHTTPError(500, "could not upsert assets").WithInternal(err)
	}

	return nil
}

func (s externalEntityProviderService) revokeAccessForRemovedProjects(domainRBAC core.AccessControl, user string, allowedProjects []string, projectsMap map[string]struct{}) {
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
