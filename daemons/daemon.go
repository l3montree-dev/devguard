package daemons

import (
	"context"
	"log/slog"
	"time"

	"github.com/l3montree-dev/devguard/shared"
	"github.com/pkg/errors"
	"gorm.io/gorm"
)

func getLastMirrorTime(configService shared.ConfigService, key string) (time.Time, error) {
	var lastMirror struct {
		Time time.Time `json:"time"`
	}

	err := configService.GetJSONConfig(context.Background(), key, &lastMirror)

	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		slog.Error("could not get last mirror time", "err", err, "key", key)
		return time.Time{}, err
	} else if errors.Is(err, gorm.ErrRecordNotFound) {
		slog.Info("no last mirror time found. Setting to 0", "key", key)
		return time.Time{}, nil
	}

	return lastMirror.Time, nil
}

func shouldMirror(configService shared.ConfigService, key string) bool {
	lastTime, err := getLastMirrorTime(configService, key)
	if err != nil {
		return false
	}

	return time.Since(lastTime) > 12*time.Hour
}

func markMirrored(configService shared.ConfigService, key string) error {
	return configService.SetJSONConfig(context.Background(), key, struct {
		Time time.Time `json:"time"`
	}{
		Time: time.Now(),
	})
}

func (runner *DaemonRunner) maybeRunAndMark(key string, fn func() error) error {
	if shouldMirror(runner.configService, key) {
		// always mark as mirrored - even in case of error to avoid endless loops
		err1 := markMirrored(runner.configService, key)
		err := fn()
		if err != nil {
			return err
		}
		if err1 != nil {
			return err1
		}
	}
	return nil
}

func (runner *DaemonRunner) CleanupOrphanedRecords(ctx context.Context) error {
	if err := runner.artifactRepository.GetDB(ctx, nil).Exec(CleanupOrphanedRecordsSQL).Error; err != nil {
		slog.Error("Failed to clean up orphaned records after deleting artifact", "err", err)
		return err
	}
	return nil
}

func (runner *DaemonRunner) runDaemons() {
	ctx := context.Background()
	if err := runner.maybeRunAndMark("maintain.cleanup", func() error {
		runner.CleanupOrphanedRecords(ctx)
		return nil
	}); err != nil {
		slog.Error("could not run cleanup daemons", "err", err)
	}

	if err := runner.maybeRunAndMark("vulndb.opensourceinsights", func() error {
		return runner.UpdateOpenSourceInsightInformation(ctx)
	}); err != nil {
		slog.Error("could not update deps dev information", "err", err)
	}

	if err := runner.maybeRunAndMark("vulndb.vulndb", func() error {
		return runner.UpdateVulnDB(ctx)
	}); err != nil {
		slog.Error("could not update vuln db", "err", err)
	}

	if err := runner.maybeRunAndMark("vulndb.fixedVersions", func() error {
		return runner.UpdateFixedVersions(ctx)
	}); err != nil {
		slog.Error("could not update fixed versions", "err", err)
	}

	if err := runner.maybeRunAndMark("vulndb.directDependencyFixedVersion", func() error {
		return runner.RunResolveFixedVersionsPipeline(context.Background(), false)
	}); err != nil {
		slog.Error("could not resolve direct depend	ency fixed versions", "err", err)
	}
}

var CleanupOrphanedRecordsSQL = `
DELETE FROM dependency_vulns dv
WHERE NOT EXISTS (SELECT artifact_dependency_vulns.dependency_vuln_id FROM artifact_dependency_vulns WHERE artifact_dependency_vulns.dependency_vuln_id = dv.id);

DELETE FROM license_risks lr
WHERE NOT EXISTS (SELECT artifact_license_risks.license_risk_id FROM artifact_license_risks WHERE artifact_license_risks.license_risk_id = lr.id);

-- Clean up artifact root nodes (component_id IS NULL, dependency_id LIKE 'artifact:%')
-- where the artifact no longer exists
DELETE FROM component_dependencies cd
WHERE cd.component_id IS NULL
AND cd.dependency_id LIKE 'artifact:%'
AND NOT EXISTS (
    SELECT 1 FROM artifacts a
    WHERE 'artifact:' || a.artifact_name = cd.dependency_id
    AND a.asset_version_name = cd.asset_version_name
    AND a.asset_id = cd.asset_id
);

-- Clean up component_dependencies that point to non-existent artifacts
DELETE FROM component_dependencies cd
WHERE cd.component_id LIKE 'artifact:%'
AND NOT EXISTS (
    SELECT 1 FROM artifacts a
    WHERE 'artifact:' || a.artifact_name = cd.component_id
    AND a.asset_version_name = cd.asset_version_name
    AND a.asset_id = cd.asset_id
);

DELETE FROM vuln_events ve WHERE ve.vuln_type = 'dependencyVuln' AND NOT EXISTS (
    SELECT dependency_vulns.id FROM dependency_vulns WHERE dependency_vulns.id = ve.vuln_id
);

DELETE FROM vuln_events ve WHERE ve.vuln_type = 'firstPartyVuln' AND NOT EXISTS(
	SELECT first_party_vulnerabilities.id FROM first_party_vulnerabilities WHERE first_party_vulnerabilities.id = ve.vuln_id
);

DELETE FROM vuln_events ve WHERE ve.vuln_type = 'licenseRisk' AND NOT EXISTS(
	SELECT license_risks.id FROM license_risks WHERE license_risks.id = ve.vuln_id
);
`
