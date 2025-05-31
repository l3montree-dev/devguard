package project

import (
	"fmt"
	"log/slog"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/accesscontrol"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/labstack/echo/v4"
)

type service struct {
	projectRepository core.ProjectRepository
}

func NewService(projectRepository core.ProjectRepository) *service {
	return &service{
		projectRepository: projectRepository,
	}
}

func (s *service) CreateProject(ctx core.Context, project models.Project) (*models.Project, error) {
	newProject := project
	if newProject.Name == "" || newProject.Slug == "" {
		return nil, echo.NewHTTPError(409, "projects with an empty name or an empty slug are not allowed").WithInternal(fmt.Errorf("projects with an empty name or an empty slug are not allowed"))
	}

	if err := s.projectRepository.Create(nil, &newProject); err != nil {
		// check if duplicate key error
		if database.IsDuplicateKeyError(err) {
			// get the project by slug and project id unscoped
			project, err := s.projectRepository.ReadBySlugUnscoped(project.OrganizationID, project.Slug)
			if err != nil {
				return nil, echo.NewHTTPError(500, "could not create asset").WithInternal(err)
			}

			if err = s.projectRepository.Activate(nil, project.GetID()); err != nil {
				return nil, echo.NewHTTPError(500, "could not activate asset").WithInternal(err)
			}

			slog.Info("project activated", "projectSlug", project.Slug, "projectID", project.GetID())
			newProject = project

		} else {
			return nil, echo.NewHTTPError(500, "could not create project").WithInternal(err)
		}
	}

	if err := s.bootstrapProject(ctx, newProject); err != nil {
		return nil, echo.NewHTTPError(500, "could not bootstrap project").WithInternal(err)
	}

	return &newProject, nil
}

func (s *service) bootstrapProject(c core.Context, project models.Project) error {
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

	if err := rbac.AllowRoleInProject(project.ID.String(), "admin", "user", []accesscontrol.Action{
		accesscontrol.ActionCreate,
		accesscontrol.ActionDelete,
		accesscontrol.ActionUpdate,
	}); err != nil {
		return err
	}

	if err := rbac.AllowRoleInProject(project.ID.String(), "admin", "asset", []accesscontrol.Action{
		accesscontrol.ActionCreate,
		accesscontrol.ActionDelete,
		accesscontrol.ActionUpdate,
	}); err != nil {
		return err
	}

	if err := rbac.AllowRoleInProject(project.ID.String(), "admin", "project", []accesscontrol.Action{
		accesscontrol.ActionDelete,
		accesscontrol.ActionUpdate,
	}); err != nil {
		return err
	}

	if err := rbac.AllowRoleInProject(project.ID.String(), "member", "project", []accesscontrol.Action{
		accesscontrol.ActionRead,
	}); err != nil {
		return err
	}

	if err := rbac.AllowRoleInProject(project.ID.String(), "member", "asset", []accesscontrol.Action{
		accesscontrol.ActionRead,
	}); err != nil {
		return err
	}

	// check if there is a parent project - if so, we need to further inherit the roles
	if project.ParentID != nil {
		// make a parent project admin an admin of the child project
		if err := rbac.InheritProjectRolesAcrossProjects(accesscontrol.ProjectRole{
			Role:    "admin",
			Project: (*project.ParentID).String(),
		}, accesscontrol.ProjectRole{
			Role:    "admin",
			Project: project.ID.String(),
		}); err != nil {
			return err
		}

		// make a parent project member a member of the child project
		if err := rbac.InheritProjectRolesAcrossProjects(accesscontrol.ProjectRole{
			Role:    "member",
			Project: (*project.ParentID).String(),
		}, accesscontrol.ProjectRole{
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
	projectsIdsStr := rbac.GetAllProjectsForUser(core.GetSession(c).GetUserID())

	// extract the project ids from the roles
	projectIDs := make(map[uuid.UUID]struct{})
	for _, project := range projectsIdsStr {
		projectID := uuid.MustParse(project)

		projectIDs[projectID] = struct{}{}
	}

	// check if parentId is set
	parentId := c.QueryParam("parentId")
	var parentID *uuid.UUID = nil
	if parentId != "" {
		tmp, err := uuid.Parse(parentId)
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
