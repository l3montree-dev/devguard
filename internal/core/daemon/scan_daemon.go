package daemon

import (
	"log/slog"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/assetversion"
	"github.com/l3montree-dev/devguard/internal/core/component"
	"github.com/l3montree-dev/devguard/internal/core/integrations"
	"github.com/l3montree-dev/devguard/internal/core/normalize"
	"github.com/l3montree-dev/devguard/internal/core/statistics"
	"github.com/l3montree-dev/devguard/internal/core/vuln"
	"github.com/l3montree-dev/devguard/internal/core/vulndb"
	"github.com/l3montree-dev/devguard/internal/core/vulndb/scan"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
)

func ScanAssetVersions(db core.DB) error {

	assetVersionRepository := repositories.NewAssetVersionRepository(db)
	componentRepository := repositories.NewComponentRepository(db)
	dependencyVulnRepository := repositories.NewDependencyVulnRepository(db)
	firstPartyVulnerabilityRepository := repositories.NewFirstPartyVulnerabilityRepository(db)
	cveRepository := repositories.NewCVERepository(db)
	orgRepository := repositories.NewOrgRepository(db)
	projectRepository := repositories.NewProjectRepository(db)
	assetRepository := repositories.NewAssetRepository(db)
	vulnEventRepository := repositories.NewVulnEventRepository(db)
	componentProjectRepository := repositories.NewComponentProjectRepository(db)
	statisticsRepository := repositories.NewStatisticsRepository(db)
	assetRiskHistoryRepository := repositories.NewAssetRiskHistoryRepository(db)
	projectRiskHistoryRepository := repositories.NewProjectRiskHistoryRepository(db)

	gitlabIntegration := integrations.NewGitLabIntegration(db)
	githubIntegration := integrations.NewGithubIntegration(db)
	thirdPartyIntegration := integrations.NewThirdPartyIntegrations(githubIntegration, gitlabIntegration)

	dependencyVulnService := vuln.NewService(dependencyVulnRepository, vulnEventRepository, assetRepository, cveRepository, orgRepository, projectRepository, thirdPartyIntegration, assetVersionRepository)
	firstPartyVulnService := vuln.NewFirstPartyVulnService(firstPartyVulnerabilityRepository, vulnEventRepository, assetRepository)
	depsDevService := vulndb.NewDepsDevService()
	componentService := component.NewComponentService(&depsDevService, componentProjectRepository, componentRepository)

	assetVersionService := assetversion.NewService(assetVersionRepository, componentRepository, dependencyVulnRepository, firstPartyVulnerabilityRepository, dependencyVulnService, firstPartyVulnService, assetRepository, &componentService)

	statisticsService := statistics.NewService(statisticsRepository, componentRepository, assetRiskHistoryRepository, dependencyVulnRepository, assetVersionRepository, projectRepository, projectRiskHistoryRepository)

	s := scan.NewHttpController(db, cveRepository, componentRepository, assetRepository, assetVersionRepository, assetVersionService, statisticsService, dependencyVulnService)
	assetVersions, err := assetVersionRepository.All()
	if err != nil {
		return err
	}
	var org models.Org
	orgCache := make(map[uuid.UUID]*models.Org) //stash every org we already found so we avoid querying for the same org of an asset/project repeatedly
	for i := range assetVersions {
		if orgCache[assetVersions[i].AssetID] == nil { //check if we already have found the org for this asset
			if orgCache[assetVersions[i].Asset.ProjectID] == nil { //if not we check if we already have found the org for the project
				org, err = getOrgFromAsset(db, assetVersions[i].AssetID)
				if err != nil {
					slog.Error("Error in the loop 1")
					continue
				}
				orgCache[assetVersions[i].AssetID] = &org //put both the keys of the assetID and the projectID into the stash
				orgCache[assetVersions[i].Asset.ProjectID] = &org
			} else {
				org = *orgCache[assetVersions[i].Asset.ProjectID] //if we already queried this org we just retrieve it from the map
			}
		} else {
			org = *orgCache[assetVersions[i].AssetID]
		}
		components, err := componentRepository.LoadComponents(db, assetVersions[i].Name, assetVersions[i].AssetID, "")
		if err != nil {
			continue
		}

		// group the components by scannerID
		scannerIDMap := make(map[string][]models.ComponentDependency)
		for _, component := range components {
			scannerIDMap[component.ScannerIDs] = append(scannerIDMap[component.ScannerIDs], component)
		}

		for scannerID, components := range scannerIDMap {
			bom := assetVersionService.BuildSBOM(assetVersions[i], "0.0.0", org.Name, components)
			normalizedBOM := normalize.FromCdxBom(bom, false)
			if len(components) <= 0 {
				continue
			} else {
				_, err = scan.ScanNormalizedSBOM(s, assetVersions[i].Asset, assetVersions[i], normalizedBOM, scannerID, "system")
			}

			if err != nil {
				continue
			}
		}
	}
	return nil
}

func getOrgFromAsset(db core.DB, assetID uuid.UUID) (models.Org, error) {
	var org models.Org

	err := db.Raw("SELECT o.* FROM organizations o JOIN projects p ON p.organization_id = o.id JOIN assets a ON p.id = a.project_id WHERE a.id = ?", assetID).First(&org).Error
	if err != nil {
		return org, err
	}
	return org, nil
}
