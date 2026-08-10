package daemons

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/l3montree-dev/devguard/vulndb/scan"
	"github.com/package-url/packageurl-go"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
)

func getFixedVersion(ctx context.Context, purlComparer *scan.PurlComparer, job fixedVersionJob) (*string, error) {
	// we only need to update the fixed version
	parsed, err := packageurl.FromString(job.Purl)
	if err != nil {
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
		}), job.CVEID) {
			continue
		}

		if c.SemverFixed != nil {
			return normalize.FixFixedVersion(job.Purl, c.SemverFixed), nil
		} else if c.VersionFixed != nil && *c.VersionFixed != "" {
			return normalize.FixFixedVersion(job.Purl, c.VersionFixed), nil
		}
	}

	return nil, nil
}

type fixedVersionJob struct {
	Purl         string `gorm:"column:component_purl"`
	CVEID        string `gorm:"column:cve_id"`
	FixedVersion string `gorm:"column:component_fixed_version"`
}

func (runner *DaemonRunner) UpdateFixedVersions(ctx context.Context) error {
	// we need to update component depth and fixedVersion for each dependencyVuln.
	// to make this as efficient as possible, we start by getting all the assets
	// and then we get all the components for each asset.
	ctx, span := daemonTracer.Start(ctx, "daemon.fixed-versions")
	defer span.End()

	// purlComparer := scan.NewPurlComparer(runner.db)

	var fixedVersionJobs []fixedVersionJob
	// get all dependency vulns without a fixed version
	err := runner.dependencyVulnRepository.GetDB(ctx, nil).Raw(`  
	SELECT component_purl, cve_id 
	FROM dependency_vulns dv 
	WHERE dv.component_fixed_version IS NULL OR dv.component_fixed_version = ''
  	GROUP BY dv.component_purl,dv.cve_id;`).Find(&fixedVersionJobs).Error
	if err != nil {
		slog.Error("could not get dependency vulns without fixed version", "err", err)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("could not fetch vulns to update: %w", err)
	}

	span.SetAttributes(attribute.Int("amount of jobs", len(fixedVersionJobs)))

	slog.Info("updating fixed versions for dependency vulns", "count", len(fixedVersionJobs))

	wg := utils.ErrGroup[any](20)
	updatingJobs := make([]fixedVersionJob, 0, len(fixedVersionJobs))
	updatingJobsChannel := make(chan fixedVersionJob, 50)
	collectorWaitGroup := &sync.WaitGroup{}

	collectorWaitGroup.Go(
		func() {
			for job := range updatingJobsChannel {
				updatingJobs = append(updatingJobs, job)
			}
		})

	start := time.Now()
	errorCount := 0
	for i, job := range fixedVersionJobs {
		if i%1000 == 0 {
			slog.Info("status", "count", i, "time", time.Since(start))
		}
		wg.Go(func() (any, error) {
			fixedVersion, err := getFixedVersion(ctx, purlComparer, job)
			if err != nil {
				slog.Error(err.Error())
				errorCount++
				// return nil, fmt.Errorf("could not get fixed version for purl %s, error: %w", job.Purl, err)
				return nil, nil
			}
			// check if a fixed version could be determined and that its a new value
			if fixedVersion != nil && *fixedVersion != "" {
				job.FixedVersion = *fixedVersion
				updatingJobsChannel <- job
			}

			return nil, nil
		})
	}

	_, err = wg.WaitAndCollect() // all jobs are processed
	if err != nil {
		slog.Error("could not update fixed versions", "err", err)
		return err
	}
	if errorCount > 0 {
		slog.Warn("ran into errors", "amount", errorCount)
	}

	close(updatingJobsChannel) // no more results will come in

	collectorWaitGroup.Wait() // then wait until all results are collected
	// updatingJobs, err := runner.GetFixedVersionInformationForVulns(ctx, fixedVersionJobs)
	// if err != nil {
	// 	return fmt.Errorf("could not get fixed version information for vulns: %w", err)
	// }
	// slog.Info("finished fetching fixed information", "time", time.Since(start))
	return nil

	if err := runner.UpdateAllFixedVersions(ctx, updatingJobs); err != nil {
		return err
	}
	slog.Info("successfully updated all component fixed versions", "time", time.Since(start))
	return nil
}

const updateTmpTableName = "fixed_version_update_stage"

// updates the dependency vulns with the new fixed version data
func (runner *DaemonRunner) UpdateAllFixedVersions(ctx context.Context, fixedVersions []fixedVersionJob) error {
	tx, err := runner.pgxpool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("could not start pgx transaction: %w", err)
	}

	defer func() {
		if err := tx.Rollback(ctx); err != nil && err != pgx.ErrTxClosed {
			slog.Error("fatal could not rollback updating transaction, database state possibly inconsistent", "error", err)
		}
		if err == nil {
			slog.Info("successfully rolled back transaction")
		}
	}() // rollback if we fail

	// first create temporary staging table
	_, err = tx.Exec(ctx, fmt.Sprintf(`CREATE TEMP TABLE IF NOT EXISTS %s (
		component_purl text,
		cve_id text,
		component_fixed_version text
	) ON COMMIT DROP;`, updateTmpTableName))
	if err != nil {
		return fmt.Errorf("could not create tmp table for updating: %w", err)
	}

	// then insert all entries to update into it using copy
	_, err = tx.CopyFrom(ctx, pgx.Identifier{updateTmpTableName}, []string{"component_purl", "cve_id", "component_fixed_version"},
		pgx.CopyFromSlice(len(fixedVersions), func(i int) ([]any, error) {
			return []any{fixedVersions[i].Purl, fixedVersions[i].CVEID, fixedVersions[i].FixedVersion}, nil
		}))
	if err != nil {
		return fmt.Errorf("could not copy into temp table for updating: %w", err)
	}

	// now we update the main table using the temp table values
	// match on purl + cveID and overwrite only the component_fixed_version
	_, err = tx.Exec(ctx, fmt.Sprintf(`UPDATE public.dependency_vulns AS liveTable 
	SET component_fixed_version = updated.component_fixed_version
	FROM %s as updated
	WHERE liveTable.component_purl = updated.component_purl
	AND liveTable.cve_id = updated.cve_id;`, updateTmpTableName))
	if err != nil {
		return fmt.Errorf("could not update live table from tmp table: %w", err)
	}

	// if err := tx.Commit(ctx); err != nil {
	// 	return fmt.Errorf("could not commit update transaction: %w", err)
	// }
	return nil
}

func (runner *DaemonRunner) GetFixedVersionInformationForVulns(ctx context.Context, jobs []fixedVersionJob) ([]fixedVersionJob, error) {
	type resultRow struct {
		CVE          string
		Purl         string
		VersionFixed *string
		SemverFixed  *string
	}

	cveIDs := make([]string, len(jobs))
	purls := make([]string, len(jobs))
	for i := range jobs {
		cveIDs[i] = jobs[i].CVEID
		purls[i] = jobs[i].Purl
	}

	resultSet, err := runner.pgxpool.Query(ctx, `
	SELECT pairs.cve, pairs.purl, ac.version_fixed, ac.semver_fixed
	FROM unnest($1::text[], $2::text[]) AS pairs(cve, purl)
	JOIN cves ON cves.cve = pairs.cve
	JOIN cve_affected_component cac ON cac.cve_id = cves.id
	JOIN affected_components ac ON cac.affected_component_id = ac.id
    AND ac.purl = pairs.purl
	WHERE ac.version_fixed IS NOT NULL OR ac.semver_fixed IS NOT NULL;`, cveIDs, purls)
	if err != nil {
		return nil, fmt.Errorf("could not query fixed versions: %w", err)
	}
	defer resultSet.Close()

	fixedVersions := make([]fixedVersionJob, 0, len(jobs))
	for resultSet.Next() {
		result := resultRow{}
		if err := resultSet.Scan(&result); err != nil {
			return nil, fmt.Errorf("could not scan row: %w", err)
		}

		var fixedVersion *string
		if result.SemverFixed != nil {
			fixedVersion = normalize.FixFixedVersion(result.Purl, result.SemverFixed)
		} else if result.VersionFixed != nil && *result.VersionFixed != "" {
			fixedVersion = normalize.FixFixedVersion(result.Purl, result.VersionFixed)
		}
		if fixedVersion != nil { //should always be the case
			fixedVersions = append(fixedVersions, fixedVersionJob{
				Purl:         result.Purl,
				CVEID:        result.CVE,
				FixedVersion: *fixedVersion,
			})
		}
	}
	if resultSet.Err() != nil {
		return nil, fmt.Errorf("could not read from results: %w", err)
	}
	return fixedVersions, nil
}
