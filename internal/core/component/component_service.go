package component

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"

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
	artifactRepository         core.ArtifactRepository
}

func NewComponentService(depsDevService core.DepsDevService, componentProjectRepository core.ComponentProjectRepository, componentRepository core.ComponentRepository, licenseRiskService core.LicenseRiskService, artifactRepository core.ArtifactRepository) service {
	err := loadLicensesIntoMemory()
	if err != nil {
		panic(fmt.Sprintf("error when trying to load licenses into memory, error: %s", err.Error()))
	}
	return service{
		componentRepository:        componentRepository,
		componentProjectRepository: componentProjectRepository,
		depsDevService:             depsDevService,
		licenseRiskService:         licenseRiskService,
		artifactRepository:         artifactRepository,
	}
}

func loadLicensesIntoMemory() error {
	err := json.Unmarshal(alpineLicenses, &alpineLicenseMap)
	if err != nil {
		return err
	}
	return json.Unmarshal(debianLicenses, &debianLicenseMap)
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
	validatedPURL, err := packageurl.FromString(pURL)
	if err != nil {
		// swallow the error
		component.License = utils.Ptr("unknown")
		return component, nil
	}

	// check the pURL type, if its a debian or alpine package we get the license from memory
	switch validatedPURL.Type {
	case "deb":
		license := getDebianLicense(validatedPURL, component.Version)
		if license == "" {
			slog.Warn("could not get license information", "err", err, "purl", pURL)
			component.License = utils.Ptr("unknown")
			return component, nil
		}
		component.License = &license
	case "apk":
		license := getAlpineLicense(validatedPURL, component.Version)
		if license == "" {
			slog.Warn("could not get license information", "err", err, "purl", pURL)
			component.License = utils.Ptr("unknown")
			return component, nil
		}
		component.License = &license
	default:
		resp, err := s.depsDevService.GetVersion(context.Background(), validatedPURL.Type, combineNamespaceAndName(validatedPURL.Namespace, validatedPURL.Name), validatedPURL.Version)

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
	}
	return component, nil
}

func (s *service) GetAndSaveLicenseInformation(assetVersion models.AssetVersion, artifactName *string, forceRefresh bool) ([]models.Component, error) {
	var componentDependencies []models.ComponentDependency
	var err error
	if artifactName == nil {
		// get all components for all artifacts
		componentDependencies, err = s.componentRepository.LoadComponentsForAllArtifacts(nil, assetVersion.Name, assetVersion.AssetID)
		if err != nil {
			return nil, err
		}

	} else {
		componentDependencies, err = s.componentRepository.LoadComponents(nil, assetVersion.Name, assetVersion.AssetID, *artifactName)
		if err != nil {
			return nil, err
		}

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

	go func() {
		// find potential license risks
		if artifactName == nil {
			// fetch all artifacts for the asset version - we need this to link the license risks to the artifacts
			artifacts, err := s.artifactRepository.GetByAssetIDAndAssetVersionName(assetVersion.AssetID, assetVersion.Name)
			if err != nil {
				slog.Error("could not fetch artifacts for asset version", "err", err, "assetVersion", assetVersion.Name, "assetID", assetVersion.AssetID)
				return
			}
			for _, artifact := range artifacts {
				err = s.licenseRiskService.FindLicenseRisksInComponents(assetVersion, allComponents, artifact.ArtifactName)
				if err != nil {
					slog.Error("could not find license risks in components", "err", err, "artifactName", artifact.ArtifactName)
				}
			}
		} else {
			err = s.licenseRiskService.FindLicenseRisksInComponents(assetVersion, allComponents, *artifactName)
			if err != nil {
				slog.Error("could not find license risks in components", "err", err, "artifactName", *artifactName)
			}
		}
	}()

	return allComponents, nil
}

//go:embed debian-licenses.json
var debianLicenses []byte
var debianLicenseMap map[string]string = make(map[string]string, 100*1000)
var debianMutex sync.Mutex

// some components have a already modified purl to improve cve -> purl matching (see cdx bom normalization)
// we basically need to revert that for license matching - thus the second parameter
// see pkg:deb/debian/gdbm@1.23 as an example. Fallback version is 1.23-3
func getDebianLicense(pURL packageurl.PackageURL, fallbackVersion string) string {
	var err error
	var license string
	debianMutex.Lock()
	if len(debianLicenseMap) == 0 {
		err = json.Unmarshal(debianLicenses, &debianLicenseMap)
		if err != nil {
			debianMutex.Unlock()
			return license
		}
	}
	debianMutex.Unlock()
	license, exists := debianLicenseMap[pURL.Name+pURL.Version]
	if exists {
		return license
	}
	license, exists = debianLicenseMap[pURL.Name+fallbackVersion]
	if exists {
		return license
	}
	return ""
}

//go:embed alpine-licenses.json
var alpineLicenses []byte
var alpineLicenseMap map[string]string = make(map[string]string, 100*1000)
var alpineMutex sync.Mutex

// some components have a already modified purl to improve cve -> purl matching (see cdx bom normalization)
// we basically need to revert that for license matching - thus the second parameter
// see pkg:deb/debian/gdbm@1.23 as an example. Fallback version is 1.23-3
func getAlpineLicense(pURL packageurl.PackageURL, fallbackVersion string) string {
	var err error
	var license string
	alpineMutex.Lock()
	if len(alpineLicenseMap) == 0 {
		err = json.Unmarshal(alpineLicenses, &alpineLicenseMap)
		if err != nil {
			alpineMutex.Unlock()
			return license
		}
	}
	alpineMutex.Unlock()
	license, exists := alpineLicenseMap[pURL.Name+pURL.Version]
	if exists {
		return license
	}
	license, exists = alpineLicenseMap[pURL.Name+fallbackVersion]
	if exists {
		return license
	}
	return ""
}
