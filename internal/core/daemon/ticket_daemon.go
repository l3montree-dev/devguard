package daemon

import (
	"log/slog"
	"time"

	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/vuln"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
	"github.com/l3montree-dev/devguard/internal/monitoring"
)

func SyncTickets(db core.DB, thirdPartyIntegrationAggregate core.ThirdPartyIntegration) error {
	start := time.Now()
	defer func() {
		monitoring.SyncTicketDuration.Observe(time.Since(start).Minutes())
	}()

	dependencyVulnService := vuln.NewService(
		repositories.NewDependencyVulnRepository(db),
		repositories.NewVulnEventRepository(db),
		repositories.NewAssetRepository(db),
		repositories.NewCVERepository(db),
		repositories.NewOrgRepository(db),
		repositories.NewProjectRepository(db),
		thirdPartyIntegrationAggregate,
		repositories.NewAssetVersionRepository(db),
	)
	assetVersionRepository := repositories.NewAssetVersionRepository(db)
	assetRepository := repositories.NewAssetRepository(db)
	projectRepository := repositories.NewProjectRepository(db)
	orgRepository := repositories.NewOrgRepository(db)

	orgs, err := orgRepository.All()
	if err != nil {
		slog.Error("failed to load organizations", "error", err)
		return err
	}

	for _, org := range orgs {
		// get all projects for the org
		projects, err := projectRepository.GetByOrgID(org.ID)
		if err != nil {
			slog.Error("failed to load projects for org", "orgID", org.ID, "error", err)
			continue
		}
		for _, project := range projects {
			// get all assets for the project
			assets, err := assetRepository.GetByProjectID(project.ID)
			if err != nil {
				slog.Error("failed to load assets for project", "projectID", project.ID, "error", err)
				continue
			}
			for _, asset := range assets {
				if !vuln.IsConnectedToThirdPartyIntegration(asset) {
					continue
				}
				// get all asset versions for the asset
				assetVersions, err := assetVersionRepository.GetAllAssetsVersionFromDBByAssetID(db, asset.ID)
				if err != nil {
					slog.Error("failed to load asset versions for asset", "assetID", asset.ID, "error", err)
					continue
				}
				for _, assetVersion := range assetVersions {
					err := dependencyVulnService.SyncAllIssues(org, project, asset, assetVersion)
					if err != nil {
						slog.Error("failed to sync issues for asset version", "assetVersionName", assetVersion.Name, "assetID", asset.ID, "error", err)
						continue
					}

				}
			}
		}
	}

	monitoring.SyncTicketDaemonAmount.Inc()

	return nil
}
