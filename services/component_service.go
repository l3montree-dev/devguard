package services

import (
	"context"
	_ "embed"
	"log/slog"

	"github.com/l3montree-dev/devguard/database"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/licenses"
	"github.com/l3montree-dev/devguard/monitoring"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/package-url/packageurl-go"
)

type ComponentService struct {
	componentRepository        shared.ComponentRepository
	openSourceInsightsService  shared.OpenSourceInsightService
	componentProjectRepository shared.ComponentProjectRepository
	licenseRiskService         shared.LicenseRiskService
	artifactRepository         shared.ArtifactRepository
	synchronizer               shared.FireAndForgetSynchronizer
}

func NewComponentService(openSourceInsightsService shared.OpenSourceInsightService, componentProjectRepository shared.ComponentProjectRepository, componentRepository shared.ComponentRepository, licenseRiskService shared.LicenseRiskService, artifactRepository shared.ArtifactRepository, synchronizer shared.FireAndForgetSynchronizer) ComponentService {

	return ComponentService{
		componentRepository:        componentRepository,
		componentProjectRepository: componentProjectRepository,
		openSourceInsightsService:  openSourceInsightsService,
		licenseRiskService:         licenseRiskService,
		artifactRepository:         artifactRepository,
		synchronizer:               synchronizer,
	}
}

func combineNamespaceAndName(namespace, name string) string {
	if namespace == "" {
		return name
	}

	return namespace + "/" + name
}

func (s *ComponentService) RefreshComponentProjectInformation(project models.ComponentProject) {
	projectKey := project.ProjectKey
	projectResp, err := s.openSourceInsightsService.GetProject(context.Background(), projectKey)

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
		monitoring.OpenSourceInsightProjectUpdatedAmount.Inc()
	}
}

func (s *ComponentService) GetLicense(component models.Component) (models.Component, error) {
	pURL := component.Purl
	validatedPURL, err := packageurl.FromString(pURL)
	if err != nil {
		// swallow the error
		component.License = utils.Ptr("unknown")
		return component, nil
	}

	// check the pURL type, if its a debian or alpine package we get the license from memory
	switch validatedPURL.Type {
	case "deb":
		l := getDebianLicense(validatedPURL, component.Version)
		if l == "" {
			slog.Warn("could not get license information", "err", err, "purl", pURL)
			component.License = utils.Ptr("unknown")
			return component, nil
		}
		component.License = &l
	case "apk":
		l := licenses.GetAlpineLicense(validatedPURL, component.Version)
		if l == "" {
			slog.Warn("could not get license information", "err", err, "purl", pURL)
			component.License = utils.Ptr("unknown")
			return component, nil
		}
		component.License = &l
	default:
		resp, err := s.openSourceInsightsService.GetVersion(
			context.Background(),
			validatedPURL.Type,
			combineNamespaceAndName(validatedPURL.Namespace, validatedPURL.Name),
			validatedPURL.Version,
		)

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
		if len(resp.RelatedProjects) == 0 {
			slog.Warn("no related projects found", "purl", pURL)
			return component, nil
		}

		// find the project with the "SOURCE_REPO" type
		for _, project := range resp.RelatedProjects {
			if project.RelationType == "SOURCE_REPO" {
				// get the project key and fetch the project
				projectKey := project.ProjectKey.ID

				// fetch the project
				projectResp, err := s.openSourceInsightsService.GetProject(context.Background(), projectKey)
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
	}
	return component, nil
}

func (s *ComponentService) GetAndSaveLicenseInformation(assetVersion models.AssetVersion, artifactName *string, forceRefresh bool, upstream dtos.UpstreamState) ([]models.Component, error) {
	componentDependencies, err := s.componentRepository.LoadComponents(nil, assetVersion.Name, assetVersion.AssetID, artifactName)
	if err != nil {
		return nil, err
	}

	// only get the components - there might be duplicates
	componentsWithoutLicense := make([]models.Component, 0)
	seen := make(map[string]bool)
	for _, componentDependency := range componentDependencies {
		if _, ok := seen[componentDependency.DependencyPurl]; !ok && (forceRefresh || componentDependency.Dependency.License == nil) {
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

	s.synchronizer.FireAndForget(func() {

		allComponents = utils.Filter(allComponents, func(component models.Component) bool {
			//check if the purl is valid and has a version
			_, err = packageurl.FromString(component.Purl)
			return err == nil
		})
		// find potential license risks
		if artifactName == nil {
			// fetch all artifacts for the asset version - we need this to link the license risks to the artifacts
			artifacts, err := s.artifactRepository.GetByAssetIDAndAssetVersionName(assetVersion.AssetID, assetVersion.Name)
			if err != nil {
				slog.Error("could not fetch artifacts for asset version", "err", err, "assetVersion", assetVersion.Name, "assetID", assetVersion.AssetID)
				return
			}
			for _, artifact := range artifacts {
				err = s.licenseRiskService.FindLicenseRisksInComponents(assetVersion, allComponents, artifact.ArtifactName, upstream)
				if err != nil {
					slog.Error("could not find license risks in components", "err", err, "artifactName", artifact.ArtifactName)
				}
			}
		} else {
			err = s.licenseRiskService.FindLicenseRisksInComponents(assetVersion, allComponents, *artifactName, upstream)
			if err != nil {
				slog.Error("could not find license risks in components", "err", err, "artifactName", *artifactName)
			}
		}
	})

	return allComponents, nil
}

func (s *ComponentService) FetchInformationSources(artifact *models.Artifact) ([]models.ComponentDependency, error) {
	return s.componentRepository.FetchInformationSources(artifact)
}

func (s *ComponentService) RemoveInformationSources(artifact *models.Artifact, rootNodePurls []string) error {
	return s.componentRepository.RemoveInformationSources(artifact, rootNodePurls)
}
