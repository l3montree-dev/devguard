package daemon

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/assetversion"
	"github.com/l3montree-dev/devguard/internal/core/component"
	"github.com/l3montree-dev/devguard/internal/core/dependency_vuln"
	"github.com/l3montree-dev/devguard/internal/core/integrations"
	"github.com/l3montree-dev/devguard/internal/core/normalize"
	"github.com/l3montree-dev/devguard/internal/core/statistics"
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

	dependencyVulnService := dependency_vuln.NewService(dependencyVulnRepository, vulnEventRepository, assetRepository, cveRepository, orgRepository, projectRepository, thirdPartyIntegration, assetVersionRepository)
	firstPartyVulnService := dependency_vuln.NewFirstPartyVulnService(firstPartyVulnerabilityRepository, vulnEventRepository, assetRepository)
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
	for i := range assetVersions {
		org, err = getOrgFromAsset(db, assetVersions[i].AssetID)
		if err != nil {
			continue
		}
		bom := assetVersionService.BuildSBOM(assetVersions[i], "0.0.0", org.Name, assetVersions[i].Components)
		normalizedBOM := normalize.FromCdxBom(bom, true)
		scan.ScanNormalizedSBOM(s, nil, assetVersions[i], normalizedBOM, assetVersions[i].Components[0].ScannerIDs)

	}
	return nil
}

func getOrgFromAsset(db core.DB, assetID uuid.UUID) (models.Org, error) {
	var org models.Org

	err := db.Raw("SELECT o.* FROM organizations o JOIN projects p ON p.organization_id = o.id JOIN assets a ON p.id = a.project_idWHERE a.id = ?", assetID).First(&org).Error
	if err != nil {
		return org, err
	}
	return org, nil
}
