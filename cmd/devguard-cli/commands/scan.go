package commands

import (
	"log/slog"
	"time"

	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/asset"
	"github.com/l3montree-dev/devguard/internal/core/flaw"
	"github.com/l3montree-dev/devguard/internal/core/normalize"
	"github.com/l3montree-dev/devguard/internal/core/vulndb/scan"
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
			flawRepository := repositories.NewFlawRepository(database)
			componentRepository := repositories.NewComponentRepository(database)
			assetService := asset.NewService(assetRepository, componentRepository, flawRepository, flaw.NewService(
				flawRepository,
				repositories.NewFlawEventRepository(database),
				assetRepository,
				repositories.NewCVERepository(database),
			))

			sbomScanner := scan.NewSBOMScanner(scan.NewCPEComparer(database), scan.NewPurlComparer(database), repositories.NewCVERepository(database))

			assets, err := assetRepository.GetAllAssetsFromDB()
			if err != nil {
				slog.Error("could not get assets", "err", err)
				return
			}
			for _, asset := range assets {
				versions, err := componentRepository.GetVersions(nil, asset)
				if err != nil {
					slog.Error("could not get versions", "err", err)
					continue
				}

				for _, scanType := range []string{"container-scanning"} {
					for _, version := range versions {
						now := time.Now()
						// build the sbom of the asset
						components, err := componentRepository.LoadAssetComponents(nil, asset, scanType, version)
						if err != nil {
							slog.Error("could not load asset components", "err", err)
							continue
						}

						sbom := assetService.BuildSBOM(asset, version, "", components)

						normalizedSBOM := normalize.FromCdxBom(sbom, false)

						vulns, err := sbomScanner.Scan(normalizedSBOM)
						if err != nil {
							slog.Error("could not scan sbom", "err", err)
							continue
						}

						amountOpened, amountClosed, flaws, err := assetService.HandleScanResult(
							asset,
							vulns,
							scanType,
							version,
							"github.com/l3montree-dev/devguard/cmd/devguard-scanner/"+scanType,
							"system",
						)

						if err != nil {
							slog.Error("could not handle scan result", "err", err)
							continue
						}

						slog.Info("scan result", "asset", asset.Name, "scanType", scanType, "version", version, "totalAmount", len(flaws), "amountOpened", amountOpened, "amountClosed", amountClosed, "duration", time.Since(now))
					}

				}
			}
		},
	}
	return &sbom
}
