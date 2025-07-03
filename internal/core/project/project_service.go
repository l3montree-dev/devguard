package project

import (
	"fmt"
	"log/slog"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/labstack/echo/v4"
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

	if err := s.bootstrapProject(ctx, project); err != nil {
		return echo.NewHTTPError(500, "could not bootstrap project").WithInternal(err)
	}

	return nil
}

func (s *service) bootstrapProject(c core.Context, project *models.Project) error {
	// get the rbac object
	rbac := core.GetRBAC(c)
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

func (s *service) ListAllowedProjects(c core.Context) ([]models.Project, error) {
	// get all projects the user has at least read access to
	rbac := core.GetRBAC(c)
	projectSliceOrProjectIDSlice, err := rbac.GetAllProjectsForUser(core.GetSession(c).GetUserID())
	if err != nil {
		return nil, echo.NewHTTPError(500, "could not get projects for user").WithInternal(err)
	}

	if slice, ok := projectSliceOrProjectIDSlice.([]models.Project); ok {
		// if the user is looking for projects which have a parent id set, we return an empty slice
		if c.QueryParam("parentId") != "" {
			return []models.Project{}, nil
		}
		// make sure the projects exist inside the database
		toUpsert := make([]*models.Project, 0, len(slice))
		for i := range slice {
			toUpsert = append(toUpsert, &slice[i])
			slice[i].OrganizationID = core.GetOrg(c).GetID() // ensure the organization ID is set
		}
		created, _, err := s.projectRepository.UpsertSplit(nil, *rbac.GetExternalEntityProviderID(), toUpsert)
		if err != nil {
			return nil, echo.NewHTTPError(500, "could not upsert projects").WithInternal(err)
		}

		// enable the community managed policies for the projects
		for _, project := range created {
			if err := s.projectRepository.EnableCommunityManagedPolicies(nil, project.ID); err != nil {
				return nil, echo.NewHTTPError(500, "could not enable community managed policies").WithInternal(err)
			}
			slog.Info("enabled community managed policies for project", "projectSlug", project.Slug, "projectID", project.ID)
		}

		return slice, err
	}
	projectsIdsStr, ok := projectSliceOrProjectIDSlice.([]string)
	if !ok {
		return nil, echo.NewHTTPError(500, "could not get projects for user").WithInternal(fmt.Errorf("expected []string but got %T", projectSliceOrProjectIDSlice))
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
