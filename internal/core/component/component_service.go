package component

import (
	"context"
	"log/slog"

	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/monitoring"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/package-url/packageurl-go"
)

type service struct {
	componentRepository        core.ComponentRepository
	depsDevService             core.DepsDevService
	componentProjectRepository core.ComponentProjectRepository
	licenseRiskService         core.LicenseRiskService
}

func NewComponentService(depsDevService core.DepsDevService, componentProjectRepository core.ComponentProjectRepository, componentRepository core.ComponentRepository, licenseRiskService core.LicenseRiskService) service {
	return service{
		componentRepository:        componentRepository,
		componentProjectRepository: componentProjectRepository,
		depsDevService:             depsDevService,
		licenseRiskService:         licenseRiskService,
	}
}

func combineNamespaceAndName(namespace, name string) string {
	if namespace == "" {
		return name
	}

	return namespace + "/" + name
}

func (s *service) RefreshComponentProjectInformation(project models.ComponentProject) {
	projectKey := project.ProjectKey
	projectResp, err := s.depsDevService.GetProject(context.Background(), projectKey)

	if err != nil {
		slog.Warn("could not get project information", "err", err, "projectKey", projectKey)
		return
	}

	var jsonbScorecard *database.JSONB = nil
	if projectResp.Scorecard != nil {
		jsonb, err := database.JSONbFromStruct(*projectResp.Scorecard)
		if err != nil {
			slog.Warn("could not convert scorecard to jsonb", "err", err)
		} else {
			jsonbScorecard = &jsonb
		}
	}

	// update the project information
	project.StarsCount = projectResp.StarsCount
	project.ForksCount = projectResp.ForksCount
	project.License = projectResp.License
	project.Description = projectResp.Description
	project.Homepage = projectResp.Homepage
	project.ScoreCard = jsonbScorecard

	// save the project
	if err := s.componentProjectRepository.Save(nil, &project); err != nil {
		slog.Warn("could not save project", "err", err)
	} else {
		slog.Info("updated project", "projectKey", projectKey)
		monitoring.DepsDevProjectUpdatedAmount.Inc()
	}
}

func (s *service) GetLicense(component models.Component) (models.Component, error) {
	pURL := component.Purl

	p, err := packageurl.FromString(pURL)
	if err != nil {
		// swallow the error
		component.License = utils.Ptr("unknown")
		return component, nil
	}

	resp, err := s.depsDevService.GetVersion(context.Background(), p.Type, combineNamespaceAndName(p.Namespace, p.Name), p.Version)

	if err != nil {
		slog.Warn("could not get license information", "err", err, "purl", pURL)

		// set the license to unknown
		component.License = utils.Ptr("unknown")
		return component, nil
	}

	// check if there is a license
	if len(resp.Licenses) > 0 {
		// update the license
		component.License = &resp.Licenses[0]
		component.Published = &resp.PublishedAt
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
				projectResp, err := s.depsDevService.GetProject(context.Background(), projectKey)
				if err != nil {
					slog.Warn("could not get project information", "err", err, "projectKey", projectKey)
				}

				var jsonbScorecard *database.JSONB = nil
				var scoreCardScore *float64 = nil
				if projectResp.Scorecard != nil {
					jsonb, err := database.JSONbFromStruct(*projectResp.Scorecard)
					scoreCardScore = &projectResp.Scorecard.OverallScore

					if err != nil {
						slog.Warn("could not convert scorecard to jsonb", "err", err)
					} else {
						jsonbScorecard = &jsonb
					}
				}
				// save the project information
				componentProject := &models.ComponentProject{
					ProjectKey:     projectKey,
					StarsCount:     projectResp.StarsCount,
					ForksCount:     projectResp.ForksCount,
					License:        projectResp.License,
					Description:    projectResp.Description,
					Homepage:       projectResp.Homepage,
					ScoreCard:      jsonbScorecard,
					ScoreCardScore: scoreCardScore,
				}

				component.ComponentProject = componentProject
				component.ComponentProjectKey = &projectKey
				break
			}
		}
	} else {
		slog.Warn("no related projects found", "purl", pURL)
	}

	return component, nil
}

func (s *service) GetAndSaveLicenseInformation(assetVersion models.AssetVersion, scannerID string) ([]models.Component, error) {
	componentDependencies, err := s.componentRepository.LoadComponents(nil, assetVersion.Name, assetVersion.AssetID, scannerID)
	if err != nil {
		return nil, err
	}

	// only get the components - there might be duplicates
	componentsWithoutLicense := make([]models.Component, 0)
	seen := make(map[string]bool)
	for _, componentDependency := range componentDependencies {
		if _, ok := seen[componentDependency.DependencyPurl]; !ok && componentDependency.Dependency.License == nil {
			seen[componentDependency.DependencyPurl] = true
			componentsWithoutLicense = append(componentsWithoutLicense, componentDependency.Dependency)
		}
	}

	//why are we only getting new licenses and not updating existing ones? - licenses shouldn't change after once they are set
	slog.Info("getting license information for components", "amount", len(componentsWithoutLicense))
	errGroup := utils.ErrGroup[models.Component](10)
	for _, component := range componentsWithoutLicense {
		errGroup.Go(func() (models.Component, error) {
			return s.GetLicense(component)
		})
	}

	// wait for all components to be processed
	components, err := errGroup.WaitAndCollect()
	if err != nil {
		return nil, err
	}

	// save the components
	if err := s.componentRepository.SaveBatch(nil, components); err != nil {
		return nil, err
	}

	allComponents := components
	// get all the components - with licenses and without
	for _, componentDependency := range componentDependencies {
		if !seen[componentDependency.DependencyPurl] {
			// if the component is not in the seen map, it means it was not processed to get a new license
			allComponents = append(allComponents, componentDependency.Dependency)
		}
	}

	// find potential license risks
	err = s.licenseRiskService.FindLicenseRisksInComponents(assetVersion, allComponents, scannerID)
	if err != nil {
		return nil, err
	}

	return allComponents, nil
}
