package commands

import (
	"log/slog"
	"time"

	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/assetversion"
	"github.com/l3montree-dev/devguard/internal/core/dependencyVuln"
	"github.com/l3montree-dev/devguard/internal/core/normalize"
	"github.com/l3montree-dev/devguard/internal/core/vulndb/scan"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
	"github.com/spf13/cobra"
)

func NewScanCommand() *cobra.Command {
	scanCmd := cobra.Command{
		Use:   "scan",
		Short: "Perform a vulnerability scan",
	}
	scanCmd.AddCommand(newSbomCommand())
	return &scanCmd
}

func newSbomCommand() *cobra.Command {
	sbom := cobra.Command{
		Use:   "sbom",
		Short: "Will rescan all sboms using the current available affected package and cpe information",
		Args:  cobra.ExactArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			core.LoadConfig() // nolint
			database, err := core.DatabaseFactory()

			if err != nil {
				slog.Error("could not connect to database", "err", err)
				return
			}
			assetRepository := repositories.NewAssetRepository(database)
			assetVersionRepository := repositories.NewAssetVersionRepository(database)
			dependencyVulnRepository := repositories.NewDependencyVulnRepository(database)
			firstPartyVulnRepository := repositories.NewFirstPartyVulnerabilityRepository(database)
			vulnEventRepository := repositories.NewVulnEventRepository(database)
			firstPartyVulnService := dependencyVuln.NewFirstPartyVulnService(firstPartyVulnRepository, vulnEventRepository, assetRepository)
			dependencyVulnService := dependencyVuln.NewService(dependencyVulnRepository, repositories.NewVulnEventRepository(database), assetRepository, repositories.NewCVERepository(database))
			componentRepository := repositories.NewComponentRepository(database)

			assetVersionService := assetversion.NewService(assetVersionRepository, componentRepository, dependencyVulnRepository, firstPartyVulnRepository, dependencyVulnService, firstPartyVulnService, assetRepository)

			sbomScanner := scan.NewSBOMScanner(scan.NewCPEComparer(database), scan.NewPurlComparer(database), repositories.NewCVERepository(database))

			assetVersions, err := assetVersionRepository.GetAllAssetsVersionFromDB(database)
			if err != nil {
				slog.Error("could not get assets", "err", err)
				return
			}
			for _, assetVersion := range assetVersions {
				components, err := componentRepository.LoadAllLatestComponentFromAssetVersion(nil, assetVersion, "")

				// group the components by scanner
				scannerComponents := make(map[string][]models.ComponentDependency)
				for _, component := range components {
					if _, ok := scannerComponents[component.ScannerID]; !ok {
						scannerComponents[component.ScannerID] = make([]models.ComponentDependency, 0)
					}
					scannerComponents[component.ScannerID] = append(scannerComponents[component.ScannerID], component)
				}

				for scanner, scannerComponents := range scannerComponents {
					now := time.Now()
					// build the sbom of the asset

					if err != nil {
						slog.Error("could not load asset components", "err", err)
						continue
					}

					sbom := assetVersionService.BuildSBOM(assetVersion, "latest", "", scannerComponents)

					normalizedSBOM := normalize.FromCdxBom(sbom, false)

					vulns, err := sbomScanner.Scan(normalizedSBOM)
					if err != nil {
						slog.Error("could not scan sbom", "err", err)
						continue
					}

					amountOpened, amountClosed, dependencyVulns, err := assetVersionService.HandleScanResult(
						// TODO: add the correct asset
						models.Asset{},
						&assetVersion,
						vulns,
						scanner,
						"latest",
						scanner,
						"system",
						true,
					)

					if err != nil {
						slog.Error("could not handle scan result", "err", err)
						continue
					}

					slog.Info("scan result", "asset", assetVersion.Name, "totalAmount", len(dependencyVulns), "amountOpened", amountOpened, "amountClosed", amountClosed, "duration", time.Since(now))

				}
			}
		},
	}
	return &sbom
}
