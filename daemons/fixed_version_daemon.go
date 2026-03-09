package daemons

import (
	"context"
	"log/slog"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/l3montree-dev/devguard/vulndb/scan"
	"github.com/package-url/packageurl-go"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
)

func getFixedVersion(ctx context.Context, purlComparer *scan.PurlComparer, dependencyVuln models.DependencyVuln) (*string, error) {
	// we only need to update the fixed version
	// update the fixed version
	parsed, err := packageurl.FromString(dependencyVuln.ComponentPurl)
	if err != nil {
		slog.Warn("could not parse purl", "purl", dependencyVuln.ComponentPurl, "err", err)
		return nil, err
	}

	affected, err := purlComparer.GetAffectedComponents(ctx, parsed)
	if err != nil {
		return nil, err
	}
	// check if there is a fix for the dependencyVuln
	for _, c := range affected {
		// check if this affected component comes from the same cve
		if !utils.Contains(utils.Map(c.CVE, func(c models.CVE) string {
			return c.CVE
		}), dependencyVuln.CVEID) {
			continue
		}

		if c.SemverFixed != nil {
			return normalize.FixFixedVersion(dependencyVuln.ComponentPurl, c.SemverFixed), nil
		} else if c.VersionFixed != nil && *c.VersionFixed != "" {
			return normalize.FixFixedVersion(dependencyVuln.ComponentPurl, c.VersionFixed), nil
		}
	}

	return nil, nil
}

func (runner *DaemonRunner) UpdateFixedVersions(ctx context.Context) error {
	// we need to update component depth and fixedVersion for each dependencyVuln.
	// to make this as efficient as possible, we start by getting all the assets
	// and then we get all the components for each asset.
	ctx, span := daemonTracer.Start(ctx, "daemon.fixed-versions")
	defer span.End()

	purlComparer := scan.NewPurlComparer(runner.db)

	var dependencyVulns []models.DependencyVuln
	// get all dependency vulns without a fixed version
	err := runner.dependencyVulnRepository.GetDB(ctx, nil).Where("component_fixed_version IS NULL OR component_fixed_version = ''").Find(&dependencyVulns).Error
	if err != nil {
		slog.Error("could not get dependency vulns without fixed version", "err", err)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	span.SetAttributes(attribute.Int("dependency_vulns.count", len(dependencyVulns)))

	slog.Info("updating fixed versions for dependency vulns", "count", len(dependencyVulns))

	wg := utils.ErrGroup[any](5)

	for _, dependencyVuln := range dependencyVulns {
		wg.Go(func() (any, error) {
			doUpdate := false
			fixedVersion, err := getFixedVersion(ctx, purlComparer, dependencyVuln)

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
			if err := runner.dependencyVulnRepository.Save(ctx, nil, &dependencyVuln); err != nil {
				slog.Warn("could not save dependencyVuln", "dependencyVuln", dependencyVuln.ID, "err", err)
			}

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
