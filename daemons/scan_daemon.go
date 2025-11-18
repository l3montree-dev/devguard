package daemons

import (
	"log/slog"
	"time"

	"github.com/l3montree-dev/devguard/controllers"
	"github.com/l3montree-dev/devguard/monitoring"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
)

func ScanArtifacts(
	db shared.DB,
	scanController *controllers.ScanController,
	assetVersionService shared.AssetVersionService,
	assetVersionRepository shared.AssetVersionRepository,
	assetRepository shared.AssetRepository,
	projectRepository shared.ProjectRepository,
	orgRepository shared.OrganizationRepository,
	artifactService shared.ArtifactService,
	componentRepository shared.ComponentRepository,
) error {
	start := time.Now()
	defer func() {
		monitoring.ScanDaemonDuration.Observe(time.Since(start).Minutes())
	}()

	// THIS IS MANDATORY - WE RESET THE SYNCHRONIZER.
	// if we wont do that, the daemon would sync the issues in a goroutine without waiting for them to finish
	// this might infer with the ticket daemon which runs next
	/*
		ScanArtifacts --> Create Ticket ----------------> Completed
		              Ticket Daemon starts ----> Create Ticket ----> Completed

		If the ticket daemon starts creating tickets before the scan artifacts daemon has finished creating tickets, there might be duplicate tickets created for the same vulnerability.

		Ref: https://github.com/l3montree-dev/devguard/issues/1284
		Ref: https://github.com/l3montree-dev/devguard/issues/1285
	*/

	scanController.FireAndForgetSynchronizer = utils.NewSyncFireAndForgetSynchronizer()

	orgs, err := orgRepository.All()
	if err != nil {
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
				// get all asset versions for the asset
				assetVersions, err := assetVersionRepository.GetAssetVersionsByAssetID(db, asset.ID)
				if err != nil {
					slog.Error("failed to load asset versions for asset", "assetID", asset.ID, "error", err)
					continue
				}

				monitoring.AssetVersionScanAmount.Inc()

				for i := range assetVersions {

					artifacts, err := artifactService.GetArtifactNamesByAssetIDAndAssetVersionName(assetVersions[i].AssetID, assetVersions[i].Name)
					if err != nil {
						slog.Error("failed to get artifacts for asset version", "assetVersionName", assetVersions[i].Name, "assetID", assetVersions[i].AssetID, "error", err)
						continue
					}

					for _, artifact := range artifacts {

						components, err := componentRepository.LoadComponents(db, assetVersions[i].Name, assetVersions[i].AssetID, &artifact.ArtifactName)
						if err != nil {
							slog.Error("failed to load components", "error", err)
							continue
						}

						bom, err := assetVersionService.BuildSBOM(asset, assetVersions[i], artifact.ArtifactName, "", components)
						if err != nil {
							slog.Error("error when building SBOM")
							continue
						}
						if len(components) <= 0 {
							continue
						} else {
							_, _, _, err = scanController.ScanNormalizedSBOM(org, project, asset, assetVersions[i], artifact, bom, "system")
						}

						if err != nil {
							slog.Error("failed to scan normalized sbom", "error", err, "artifactName", artifact, "assetVersionName", assetVersions[i].Name, "assetID", assetVersions[i].AssetID)
							continue
						}

						monitoring.AssetVersionScanSuccess.Inc()
						slog.Info("scanned asset version", "assetVersionName", assetVersions[i].Name, "assetID", assetVersions[i].AssetID)
					}
				}
			}
		}
	}
	monitoring.ScanDaemonAmount.Inc()
	return nil
}
