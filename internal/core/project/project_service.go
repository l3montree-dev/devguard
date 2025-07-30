package project

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm/clause"
)

type service struct {
	projectRepository core.ProjectRepository
	assetRepository   core.AssetRepository
}

func NewService(projectRepository core.ProjectRepository, assetRepository core.AssetRepository) *service {
	return &service{
		projectRepository: projectRepository,
		assetRepository:   assetRepository,
	}
}

func (s *service) ReadBySlug(ctx core.Context, organizationID uuid.UUID, slug string) (models.Project, error) {
	project, err := s.projectRepository.ReadBySlug(organizationID, slug)
	if err != nil {
		return models.Project{}, echo.NewHTTPError(404, "project not found").WithInternal(err)
	}

	// check if it is an external entity
	return project, nil
}

func (s *service) CreateProject(ctx core.Context, project *models.Project) error {
	err := s.assetRepository.Transaction(func(tx core.DB) error {
		if err := s.projectRepository.Create(tx, project); err != nil {
			// check if duplicate key error
			if database.IsDuplicateKeyError(err) {
				// get the project by slug and project id unscoped
				project, err := s.projectRepository.ReadBySlugUnscoped(project.OrganizationID, project.Slug)
				if err != nil {
					return echo.NewHTTPError(500, "could not create project").WithInternal(err)
				}

				if err = s.projectRepository.Activate(tx, project.GetID()); err != nil {
					return echo.NewHTTPError(500, "could not activate project").WithInternal(err)
				}

				slog.Info("project activated", "projectSlug", project.Slug, "projectID", project.GetID())

			} else {
				return echo.NewHTTPError(500, "could not create project").WithInternal(err)
			}
		}

		// enable the default community policies
		return s.projectRepository.EnableCommunityManagedPolicies(tx, project.ID)
	})
	if err != nil {
		slog.Error("could not create project", "err", err, "projectSlug", project.Slug, "projectID", project.ID)
		return echo.NewHTTPError(500, "could not create project").WithInternal(err)
	}

	domainRBAC := core.GetRBAC(ctx)

	if err := s.bootstrapProject(domainRBAC, project); err != nil {
		return echo.NewHTTPError(500, "could not bootstrap project").WithInternal(err)
	}

	return nil
}

func (s *service) bootstrapProject(rbac core.AccessControl, project *models.Project) error {
	// make sure to keep the organization roles in sync
	// let the organization admin role inherit all permissions from the project admin
	if err := rbac.LinkDomainAndProjectRole("admin", "admin", project.ID.String()); err != nil {
		return err
	}

	// give the admin of a project all member permissions
	if err := rbac.InheritProjectRole("admin", "member", project.ID.String()); err != nil {
		return err
	}

	if err := rbac.AllowRoleInProject(project.ID.String(), "admin", "user", []core.Action{
		core.ActionCreate,
		core.ActionDelete,
		core.ActionUpdate,
	}); err != nil {
		return err
	}

	if err := rbac.AllowRoleInProject(project.ID.String(), "admin", "asset", []core.Action{
		core.ActionCreate,
		core.ActionDelete,
		core.ActionUpdate,
	}); err != nil {
		return err
	}

	if err := rbac.AllowRoleInProject(project.ID.String(), "admin", "project", []core.Action{
		core.ActionDelete,
		core.ActionUpdate,
	}); err != nil {
		return err
	}

	if err := rbac.AllowRoleInProject(project.ID.String(), "member", "project", []core.Action{
		core.ActionRead,
	}); err != nil {
		return err
	}

	if err := rbac.AllowRoleInProject(project.ID.String(), "member", "asset", []core.Action{
		core.ActionRead,
	}); err != nil {
		return err
	}

	// check if there is a parent project - if so, we need to further inherit the roles
	if project.ParentID != nil {
		// make a parent project admin an admin of the child project
		if err := rbac.InheritProjectRolesAcrossProjects(core.ProjectRole{
			Role:    "admin",
			Project: (*project.ParentID).String(),
		}, core.ProjectRole{
			Role:    "admin",
			Project: project.ID.String(),
		}); err != nil {
			return err
		}

		// make a parent project member a member of the child project
		if err := rbac.InheritProjectRolesAcrossProjects(core.ProjectRole{
			Role:    "member",
			Project: (*project.ParentID).String(),
		}, core.ProjectRole{
			Role:    "member",
			Project: project.ID.String(),
		}); err != nil {
			return err
		}
	}

	return nil
}

func (s *service) ListProjectsByOrganizationID(organizationID uuid.UUID) ([]models.Project, error) {
	return s.projectRepository.GetByOrgID(organizationID)
}

func (s *service) RefreshExternalEntityProviderProjects(ctx core.Context, casbinProvider core.RBACProvider, org models.Org, user string) error {
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
		err := s.bootstrapProject(domainRBAC, &projects[i])
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

func (s *service) ListAllowedProjects(c core.Context) ([]models.Project, error) {
	// get all projects the user has at least read access to
	rbac := core.GetRBAC(c)
	projectsIdsStr, err := rbac.GetAllProjectsForUser(core.GetSession(c).GetUserID())
	if err != nil {
		return nil, echo.NewHTTPError(500, "could not get projects for user").WithInternal(err)
	}

	// extract the project ids from the roles
	projectIDs := make(map[uuid.UUID]struct{})
	for _, project := range projectsIdsStr {
		projectID := uuid.MustParse(project)

		projectIDs[projectID] = struct{}{}
	}

	// check if parentID is set
	queryParentID := c.QueryParam("parentId")
	var parentID *uuid.UUID = nil
	if queryParentID != "" {
		tmp, err := uuid.Parse(queryParentID)
		if err != nil {
			return nil, err
		}

		parentID = &tmp
	}

	projectIDsSlice := make([]uuid.UUID, 0, len(projectIDs))
	for projectID := range projectIDs {
		projectIDsSlice = append(projectIDsSlice, projectID)
	}

	projects, err := s.projectRepository.List(projectIDsSlice, parentID, core.GetOrg(c).GetID())

	if err != nil {
		return nil, err
	}

	return projects, nil
}

func (s *service) RecursivelyGetChildProjects(projectID uuid.UUID) ([]models.Project, error) {
	return s.projectRepository.RecursivelyGetChildProjects(projectID)
}

func (s *service) GetDirectChildProjects(projectID uuid.UUID) ([]models.Project, error) {
	return s.projectRepository.GetDirectChildProjects(projectID)
}
