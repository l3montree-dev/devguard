package project

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
)

type service struct {
	projectRepository projectRepository
}

func NewService(projectRepository projectRepository) *service {
	return &service{
		projectRepository: projectRepository,
	}
}

func (s *service) ListAllowedProjects(c core.Context) ([]models.Project, error) {
	// get all projects the user has at least read access to
	rbac := core.GetRBAC(c)
	projectsIdsStr := rbac.GetAllProjectsForUser(core.GetSession(c).GetUserID())

	// extract the project ids from the roles
	projectIDs := make([]uuid.UUID, 0)
	for _, project := range projectsIdsStr {
		projectID := uuid.MustParse(project)
		projectIDs = append(projectIDs, projectID)
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

	projects, err := s.projectRepository.List(projectIDs, parentID, core.GetTenant(c).GetID())

	if err != nil {
		return nil, err
	}

	return projects, nil
}
