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

func getFixedVersion(purlComparer *scan.PurlComparer, vuln models.DependencyVulnerability) (*string, error) {
	// we only need to update the fixed version
	// update the fixed version
	affected, err := purlComparer.GetAffectedComponents(*vuln.ComponentPurl, "")
	if err != nil {
		return nil, err
	}
	// check if there is a fix for the vuln
	for _, c := range affected {
		// check if this affected component comes from the same cve
		if !utils.Contains(utils.Map(c.CVE, func(c models.CVE) string {
			return c.CVE
		}), *vuln.CVEID) {
			continue
		}

		if c.SemverFixed != nil {
			slog.Info("found fixed version", "purl", *vuln.ComponentPurl, "fixedVersion", *c.SemverFixed, "vulnId", vuln.ID)
			return c.SemverFixed, nil
		} else if c.VersionFixed != nil && *c.VersionFixed != "" {
			slog.Info("found fixed version", "purl", *vuln.ComponentPurl, "fixedVersion", *c.VersionFixed, "vulnId", vuln.ID)
			return c.VersionFixed, nil
		}
	}

	return nil, nil
}

func UpdateComponentProperties(db database.DB) error {
	// we need to update component depth and fixedVersion for each vuln.
	// to make this as efficient as possible, we start by getting all the assets
	// and then we get all the components for each asset.

	assetRepository := repositories.NewAssetRepository(db)
	purlComparer := scan.NewPurlComparer(db)
	componentRepository := repositories.NewComponentRepository(db)
	vulnRepository := repositories.NewDependencyVulnerability(db)

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
			// get all vulns of that asset
			vulns, err := vulnRepository.GetByAssetId(nil, a.ID)
			if err != nil {
				slog.Warn("could not get vulns", "asset", a.ID, "err", err)
				return nil, err
			}

			// group by scanner id
			groups := make(map[string][]models.DependencyVulnerability)
			for _, f := range vulns {
				if _, ok := groups[f.ScannerID]; !ok {
					groups[f.ScannerID] = []models.DependencyVulnerability{}
				}

				groups[f.ScannerID] = append(groups[f.ScannerID], f)
			}

			// group the vulns by scanner id
			// build up the dependency tree for the asset
			for scannerID, vulns := range groups {
				components, err := componentRepository.LoadComponents(nil, a, scannerID, "")
				if err != nil {
					slog.Warn("could not load components", "asset", a.ID, "scanner", scannerID, "err", err)
					continue
				}

				depthMap := asset.GetComponentDepth(components)

				for _, vuln := range vulns {
					depth := depthMap[*vuln.ComponentPurl]
					if vuln.ComponentFixedVersion != nil && vuln.ComponentDepth != nil && depth == *vuln.ComponentDepth {
						continue // nothing todo here - the component has a depth which is the same and it already has a fix version
					}

					doUpdate := false

					if vuln.ComponentFixedVersion == nil {
						fixedVersion, err := getFixedVersion(purlComparer, vuln)
						slog.Info("got fixed version", "fixedVersion", fixedVersion)
						if err != nil {
							slog.Warn("could not get fixed version", "err", err)
						}
						if fixedVersion != nil {
							vuln.ComponentFixedVersion = fixedVersion
							doUpdate = true
						}
					}

					if vuln.ComponentDepth == nil || depth != *vuln.ComponentDepth {
						vuln.ComponentDepth = utils.Ptr(depth)
						doUpdate = true
					}

					if !doUpdate {
						continue
					}

					// save the vuln
					if err := vulnRepository.Save(nil, &vuln); err != nil {
						slog.Warn("could not save vuln", "vuln", vuln.ID, "err", err)
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
