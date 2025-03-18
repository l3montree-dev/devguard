package daemon

import (
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/component"
	"github.com/l3montree-dev/devguard/internal/core/vulndb"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
)

func UpdateDepsDevInformation(db core.DB) error {
	componentProjectRepository := repositories.NewComponentProjectRepository(db)
	projectsToUpdate, err := componentProjectRepository.FindAllOutdatedProjects()
	depsDevService := vulndb.NewDepsDevService()
	componentService := component.NewComponentService(&depsDevService, componentProjectRepository, repositories.NewComponentRepository(db))

	if err != nil {
		return err
	}

	for _, project := range projectsToUpdate {
		go componentService.RefreshComponentProjectInformation(project)
	}

	return nil
}
