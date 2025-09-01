package daemon

import (
	"log/slog"
	"time"

	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/normalize"
	"github.com/l3montree-dev/devguard/internal/core/vulndb/scan"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
	"github.com/l3montree-dev/devguard/internal/monitoring"
	"github.com/l3montree-dev/devguard/internal/utils"
)

func getFixedVersion(purlComparer *scan.PurlComparer, dependencyVuln models.DependencyVuln) (*string, error) {
	// we only need to update the fixed version
	// update the fixed version
	affected, err := purlComparer.GetAffectedComponents(*dependencyVuln.ComponentPurl, "")
	if err != nil {
		return nil, err
	}
	// check if there is a fix for the dependencyVuln
	for _, c := range affected {
		// check if this affected component comes from the same cve
		if !utils.Contains(utils.Map(c.CVE, func(c models.CVE) string {
			return c.CVE
		}), *dependencyVuln.CVEID) {
			continue
		}

		if c.SemverFixed != nil {
			return normalize.FixFixedVersion(utils.SafeDereference(dependencyVuln.ComponentPurl), c.SemverFixed), nil
		} else if c.VersionFixed != nil && *c.VersionFixed != "" {
			return normalize.FixFixedVersion(utils.SafeDereference(dependencyVuln.ComponentPurl), c.VersionFixed), nil
		}
	}

	return nil, nil
}

func UpdateFixedVersions(db core.DB) error {
	// we need to update component depth and fixedVersion for each dependencyVuln.
	// to make this as efficient as possible, we start by getting all the assets
	// and then we get all the components for each asset.

	start := time.Now()
	defer func() {
		monitoring.UpdateComponentPropertiesDuration.Observe(time.Since(start).Minutes())
	}()

	purlComparer := scan.NewPurlComparer(db)
	dependencyVulnRepository := repositories.NewDependencyVulnRepository(db)

	var dependencyVulns []models.DependencyVuln
	// get all dependency vulns without a fixed version
	err := dependencyVulnRepository.GetDB(nil).Where("component_fixed_version IS NULL OR component_fixed_version = ''").Find(&dependencyVulns).Error
	if err != nil {
		slog.Error("could not get dependency vulns without fixed version", "err", err)
		return err
	}

	slog.Info("updating fixed versions for dependency vulns", "count", len(dependencyVulns))

	wg := utils.ErrGroup[any](5)

	for _, dependencyVuln := range dependencyVulns {
		wg.Go(func() (any, error) {
			doUpdate := false
			fixedVersion, err := getFixedVersion(purlComparer, dependencyVuln)

			if err == nil {
				if fixedVersion != nil && fixedVersion != dependencyVuln.ComponentFixedVersion {
					dependencyVuln.ComponentFixedVersion = fixedVersion
					doUpdate = true
				}
			}

			if !doUpdate {
				return nil, nil
			}

			// save the dependencyVuln
			if err := dependencyVulnRepository.Save(nil, &dependencyVuln); err != nil {
				slog.Warn("could not save dependencyVuln", "dependencyVuln", dependencyVuln.ID, "err", err)
			}

			monitoring.DependencyVulnsUpdatedAmount.Inc()

			return nil, nil
		})

		_, err = wg.WaitAndCollect()
		if err != nil {
			slog.Error("could not update fixed versions", "err", err)
			return err
		}
	}

	return nil
}
