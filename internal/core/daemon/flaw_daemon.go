package daemon

import (
	"log/slog"

	"github.com/l3montree-dev/devguard/internal/core/asset"
	"github.com/l3montree-dev/devguard/internal/core/vulndb/scan"
	"github.com/l3montree-dev/devguard/internal/database"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
	"github.com/l3montree-dev/devguard/internal/utils"
)

func UpdateComponentProperties(db database.DB) error {
	// we need to update component depth and fixedVersion for each flaw.
	// to make this as efficient as possible, we start by getting all the assets
	// and then we get all the components for each asset.

	assetRepository := repositories.NewAssetRepository(db)
	purlComparer := scan.NewPurlComparer(db)
	componentRepository := repositories.NewComponentRepository(db)
	flawRepository := repositories.NewFlawRepository(db)

	allAssets, err := assetRepository.GetAllAssetsFromDB()
	if err != nil {
		return err
	}

	for _, a := range allAssets {
		// get all flaws of that asset
		flaws, err := flawRepository.GetByAssetId(nil, a.ID)
		if err != nil {
			return err
		}

		// group by scanner id
		groups := make(map[string][]models.Flaw)
		for _, f := range flaws {
			if _, ok := groups[f.ScannerID]; !ok {
				groups[f.ScannerID] = []models.Flaw{}
			}

			groups[f.ScannerID] = append(groups[f.ScannerID], f)
		}

		// group the flaws by scanner id
		// build up the dependency tree for the asset
		for scannerID, flaws := range groups {
			components, err := componentRepository.LoadComponents(nil, a, scannerID, "")
			if err != nil {
				return err
			}

			depthMap := asset.GetComponentDepth(components)

			updateFlaws := make([]models.Flaw, 0, len(flaws))
			// update the component depth
			for _, flaw := range flaws {
				flaw.ComponentDepth = utils.Ptr(depthMap[*flaw.ComponentPurl])

				// update the fixed version
				affected, err := purlComparer.GetAffectedComponents(*flaw.ComponentPurl, "")
				if err != nil {
					continue
				}

				var fixedVersion *string

				// check if there is a fix for the flaw
				for _, c := range affected {
					// check if this affected component comes from the same cve
					if utils.Contains(utils.Map(c.CVE, func(c models.CVE) string {
						return c.CVE
					}), *flaw.CVEID) {
						continue
					}

					if c.SemverFixed != nil {
						slog.Info("found fixed version", "purl", *flaw.ComponentPurl, "fixedVersion", *flaw.ComponentFixedVersion)
						fixedVersion = c.SemverFixed
						break
					} else if c.VersionFixed != nil {
						slog.Info("found fixed version", "purl", *flaw.ComponentPurl, "fixedVersion", *flaw.ComponentFixedVersion)
						fixedVersion = c.VersionFixed
						break
					}
				}
				flaw.ComponentFixedVersion = fixedVersion

				updateFlaws = append(updateFlaws, flaw)
			}
			if err := flawRepository.SaveBatch(nil, updateFlaws); err != nil {
				return err
			}
		}
	}

	return nil
}
