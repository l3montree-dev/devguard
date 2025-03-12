package daemon

import (
	"context"
	"log/slog"

	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/vulndb"
	"github.com/l3montree-dev/devguard/internal/database"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/package-url/packageurl-go"
)

func combineNamespaceAndName(namespace, name string) string {
	if namespace == "" {
		return name
	}

	return namespace + "/" + name
}

func handleComponent(depsDevService core.DepsDevService, componentProjectRepository core.ComponentProjectRepository, componentRepository core.ComponentRepository, component models.Component) {
	pURL := component.Purl

	p, err := packageurl.FromString(pURL)
	if err != nil {
		slog.Warn("could not parse package url", "purl", pURL)
		return
	}

	resp, err := depsDevService.GetVersion(context.Background(), p.Type, combineNamespaceAndName(p.Namespace, p.Name), p.Version)

	if err != nil {
		slog.Warn("could not get license information", "err", err, "purl", pURL)

		// set the license to unknown
		component.License = utils.Ptr("unknown")

		// save the component
		if err := componentRepository.Save(nil, &component); err != nil {
			slog.Warn("could not save component", "err", err)
		}
		return
	}

	// check if there is a license
	if len(resp.Licenses) > 0 {
		// update the license
		component.License = &resp.Licenses[0]
	} else {
		// set the license to unknown
		component.License = utils.Ptr("unknown")
	}

	// check if there is a related project
	if len(resp.RelatedProjects) > 0 {
		// find the project with the "SOURCE_REPO" type
		for _, project := range resp.RelatedProjects {
			if project.RelationType == "SOURCE_REPO" {
				// get the project key and fetch the project
				projectKey := project.ProjectKey.ID

				// fetch the project
				projectResp, err := depsDevService.GetProject(context.Background(), projectKey)
				if err != nil {
					slog.Warn("could not get project information", "err", err, "projectKey", projectKey)
				}

				jsonbScorecard, err := database.JsonbFromStruct(projectResp.Scorecard)
				if err != nil {
					slog.Warn("could not convert scorecard to jsonb", "err", err)
				}

				// save the project information
				project := models.ComponentProject{
					ID:          projectKey,
					StarsCount:  projectResp.StarsCount,
					ForksCount:  projectResp.ForksCount,
					License:     projectResp.License,
					Description: projectResp.Description,
					Homepage:    projectResp.Homepage,
					ScoreCard:   jsonbScorecard,
				}

				// save the project
				if err := componentProjectRepository.Save(nil, &project); err != nil {
					slog.Warn("could not save project", "err", err)
				}

				component.ComponentProjectID = &projectKey
				break
			}
		}
	} else {
		slog.Warn("no related projects found", "purl", pURL)
	}

	// save the component
	if err := componentRepository.Save(nil, &component); err != nil {
		slog.Warn("could not save component", "err", err)
	} else {
		slog.Info("updated component", "purl", pURL)
	}
}

func handleComponentProject(depsDevService core.DepsDevService, componentProjectRepository core.ComponentProjectRepository, project models.ComponentProject) {
	projectKey := project.ID
	projectResp, err := depsDevService.GetProject(context.Background(), projectKey)

	if err != nil {
		slog.Warn("could not get project information", "err", err, "projectKey", projectKey)
		return
	}

	jsonbScorecard, err := database.JsonbFromStruct(projectResp.Scorecard)
	if err != nil {
		slog.Warn("could not convert scorecard to jsonb", "err", err)
	}

	// update the project information
	project.StarsCount = projectResp.StarsCount
	project.ForksCount = projectResp.ForksCount
	project.License = projectResp.License
	project.Description = projectResp.Description
	project.Homepage = projectResp.Homepage
	project.ScoreCard = jsonbScorecard

	// save the project
	if err := componentProjectRepository.Save(nil, &project); err != nil {
		slog.Warn("could not save project", "err", err)
	} else {
		slog.Info("updated project", "projectKey", projectKey)
	}
}

func UpdateDepsDevInformation(db core.DB) error {
	componentProjectRepository := repositories.NewComponentProjectRepository(db)
	projectsToUpdate, err := componentProjectRepository.FindAllOutdatedProjects()
	depsDevService := vulndb.NewDepsDevService()

	if err != nil {
		return err
	}

	for _, project := range projectsToUpdate {
		go handleComponentProject(&depsDevService, componentProjectRepository, project)
	}

	componentRepository := repositories.NewComponentRepository(db)
	// get all components, which do not have a license yet
	components, err := componentRepository.FindAllWithoutLicense()

	if err != nil {
		return err
	}

	// update the license information for each component
	for _, component := range components {
		go handleComponent(&depsDevService, componentProjectRepository, componentRepository, component)
	}

	return nil
}
