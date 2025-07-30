package integrations

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm/clause"
)

type externalEntityProviderService struct {
	projectService    core.ProjectService
	assetRepository   core.AssetRepository
	projectRepository core.ProjectRepository
}

func NewExternalEntityProviderService(
	projectService core.ProjectService,
	assetRepository core.AssetRepository,
	projectRepository core.ProjectRepository,
) externalEntityProviderService {
	return externalEntityProviderService{
		projectService:    projectService,
		assetRepository:   assetRepository,
		projectRepository: projectRepository,
	}
}

func (s externalEntityProviderService) RefreshExternalEntityProviderProjects(ctx core.Context, casbinProvider core.RBACProvider, org models.Org, user string) error {
	thirdPartyIntegration := core.GetThirdPartyIntegration(ctx)

	if org.ExternalEntityProviderID == nil {
		return fmt.Errorf("organization %s does not have an external entity provider configured", org.GetID())
	}

	// This method is not applicable for external entity provider RBAC
	projects, roles, err := thirdPartyIntegration.ListGroups(context.TODO(), user, *org.ExternalEntityProviderID)
	if err != nil {
		return fmt.Errorf("could not list projects for user %s: %w", user, err)
	}

	// make sure the projects exist inside the database
	toUpsert := make([]*models.Project, 0, len(projects))
	for i := range projects {
		toUpsert = append(toUpsert, &projects[i])
		projects[i].OrganizationID = org.GetID() // ensure the organization ID is set
	}
	created, updated, err := s.projectRepository.UpsertSplit(nil, *org.ExternalEntityProviderID, toUpsert)
	if err != nil {
		return fmt.Errorf("could not upsert projects: %w", err)
	}

	// enable the community managed policies for the projects
	for _, project := range created {
		if err := s.projectRepository.EnableCommunityManagedPolicies(nil, project.ID); err != nil {
			return fmt.Errorf("could not enable community managed policies for project %s: %w", project.Slug, err)
		}
		slog.Info("enabled community managed policies for project", "projectSlug", project.Slug, "projectID", project.ID)
	}

	domainRBAC := casbinProvider.GetDomainRBAC(org.GetID().String())

	// update the assets inside those projects as well
	for i, project := range append(created, updated...) {
		err := s.projectService.BootstrapProject(domainRBAC, &projects[i])
		if err != nil {
			slog.Error("could not bootstrap project", "projectSlug", project.Slug, "projectID", project.ID, "err", err)
			continue
		}

		userRole := roles[i]
		currentRole, _ := domainRBAC.GetProjectRole(user, project.ID.String()) // swallow the error here - if an error happens means the user is not part of the project

		if currentRole == userRole {
			continue // user already has the correct role
		}
		if err := domainRBAC.RevokeRoleInProject(user, currentRole, project.ID.String()); err != nil {
			slog.Warn("could not revoke role for user", "user", user, "role", currentRole, "projectID", project.ID.String(), "err", err)
			continue // we don't care if the user does not have the role
		}
		slog.Info("revoked role for user", "user", user, "role",
			currentRole, "projectID", project.ID.String())
		if err := domainRBAC.GrantRoleInProject(user, userRole, project.ID.String()); err != nil {
			slog.Warn("could not grant role for user", "user", user, "role", userRole, "projectID", project.ID.String(), "err", err)
			continue // we don't care if the user already has the role
		}

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
	}

	return nil
}
