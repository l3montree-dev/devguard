package daemon

import (
	"log/slog"
	"time"

	"github.com/l3montree-dev/devguard/internal/core/asset"
	"github.com/l3montree-dev/devguard/internal/core/vulndb/scan"
	"github.com/l3montree-dev/devguard/internal/database"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
	"github.com/l3montree-dev/devguard/internal/utils"
)

func getFixedVersion(purlComparer *scan.PurlComparer, flaw models.Flaw) (*string, error) {
	// we only need to update the fixed version
	// update the fixed version
	affected, err := purlComparer.GetAffectedComponents(*flaw.ComponentPurl, "")
	if err != nil {
		return nil, err
	}
	// check if there is a fix for the flaw
	for _, c := range affected {
		// check if this affected component comes from the same cve
		if !utils.Contains(utils.Map(c.CVE, func(c models.CVE) string {
			return c.CVE
		}), *flaw.CVEID) {
			continue
		}

		if c.SemverFixed != nil {
			slog.Info("found fixed version", "purl", *flaw.ComponentPurl, "fixedVersion", *c.SemverFixed, "flawId", flaw.ID)
			return c.SemverFixed, nil
		} else if c.VersionFixed != nil && *c.VersionFixed != "" {
			slog.Info("found fixed version", "purl", *flaw.ComponentPurl, "fixedVersion", *c.VersionFixed, "flawId", flaw.ID)
			return c.VersionFixed, nil
		}
	}

	return nil, nil
}

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

	wg := utils.ErrGroup[any](5)

	for _, a := range allAssets {
		wg.Go(func() (any, error) {
			slog.Info("updating asset", "asset", a.ID)
			now := time.Now()
			defer func() {
				slog.Info("updated asset", "asset", a.ID, "duration", time.Since(now))
			}()
			// get all flaws of that asset
			flaws, err := flawRepository.GetByAssetId(nil, a.ID)
			if err != nil {
				slog.Warn("could not get flaws", "asset", a.ID, "err", err)
				return nil, err
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
					slog.Warn("could not load components", "asset", a.ID, "scanner", scannerID, "err", err)
					continue
				}

				depthMap := asset.GetComponentDepth(components)

				for _, flaw := range flaws {
					depth := depthMap[*flaw.ComponentPurl]
					if flaw.ComponentFixedVersion != nil && flaw.ComponentDepth != nil && depth == *flaw.ComponentDepth {
						continue // nothing todo here - the component has a depth which is the same and it already has a fix version
					}

					doUpdate := false

					if flaw.ComponentFixedVersion == nil {
						fixedVersion, err := getFixedVersion(purlComparer, flaw)
						slog.Info("got fixed version", "fixedVersion", fixedVersion)
						if err != nil {
							slog.Warn("could not get fixed version", "err", err)
						}
						if fixedVersion != nil {
							flaw.ComponentFixedVersion = fixedVersion
							doUpdate = true
						}
					}

					if flaw.ComponentDepth == nil || depth != *flaw.ComponentDepth {
						flaw.ComponentDepth = utils.Ptr(depth)
						doUpdate = true
					}

					if !doUpdate {
						continue
					}

					// save the flaw
					if err := flawRepository.Save(nil, &flaw); err != nil {
						slog.Warn("could not save flaw", "flaw", flaw.ID, "err", err)
					}
				}

			}
			return nil, nil
		})
	}

	_, err = wg.WaitAndCollect()
	if err != nil {
		slog.Error("could not update component properties", "err", err)
		return err
	}

	return nil
}
