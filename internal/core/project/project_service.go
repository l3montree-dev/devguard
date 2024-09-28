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

	projects, err := s.projectRepository.List(projectIDs, core.GetTenant(c).GetID())

	if err != nil {
		return nil, err
	}

	return projects, nil
}
