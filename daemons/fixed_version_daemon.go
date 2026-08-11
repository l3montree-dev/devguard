package daemons

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/l3montree-dev/devguard/vulndb/scan"
	"github.com/package-url/packageurl-go"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"gorm.io/gorm"
)

type fixedVersionJob struct {
	Purl         string `gorm:"column:component_purl"`
	CVEID        string `gorm:"column:cve_id"`
	FixedVersion string `gorm:"column:component_fixed_version"`
}

func (runner *DaemonRunner) UpdateFixedVersions(ctx context.Context) error {
	ctx, span := daemonTracer.Start(ctx, "daemon.fixed-versions")
	defer span.End()

	// we only compare the cve id, therefore we only need to preload those
	purlComparer := scan.NewPurlComparer(runner.db, scan.WithPreloads(
		func(db *gorm.DB) *gorm.DB {
			return db.Preload("CVE", func(db *gorm.DB) *gorm.DB {
				return db.Select("id", "cve")
			})
		},
	))

	var fixedVersionJobs []fixedVersionJob

	// get all dependency vulns without a fixed version (distinct on purl + cveID)
	err := runner.dependencyVulnRepository.GetDB(ctx, nil).Raw(`  
	SELECT component_purl, cve_id 
	FROM dependency_vulns dv 
	WHERE dv.component_fixed_version IS NULL 
	OR dv.component_fixed_version = ''
  	GROUP BY dv.component_purl,dv.cve_id;`).Find(&fixedVersionJobs).Error
	if err != nil {
		slog.Error("could not get dependency vulns without fixed version", "err", err)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("could not fetch vulns to update: %w", err)
	}

	span.SetAttributes(attribute.Int("amount of jobs", len(fixedVersionJobs)))
	slog.Info("start updating fixed versions for dependency vulns", "count", len(fixedVersionJobs))

	start := time.Now()
	updatingJobs, err := determineFixedVersionsForPurls(ctx, purlComparer, fixedVersionJobs)
	if err != nil {
		return err
	}
	slog.Info("finished calculating updating jobs", "time", time.Since(start))

	start = time.Now()
	if err := runner.UpdateAllFixedVersions(ctx, updatingJobs); err != nil {
		return err
	}
	slog.Info("successfully updated dependency vulns", "time", time.Since(start))
	slog.Info("successfully updated all component fixed versions", "time", time.Since(start))
	return nil
}

const updateTmpTableName = "fixed_version_update_stage"

// updates the dependency vulns with the new fixed version data
func (runner *DaemonRunner) UpdateAllFixedVersions(ctx context.Context, updatingJobs []fixedVersionJob) error {
	slog.Info("start updating dependency vulns", "amount", len(updatingJobs))
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
		pgx.CopyFromSlice(len(updatingJobs), func(i int) ([]any, error) {
			return []any{updatingJobs[i].Purl, updatingJobs[i].CVEID, updatingJobs[i].FixedVersion}, nil
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

func determineFixedVersionsForPurls(ctx context.Context, comparer *scan.PurlComparer, fixedVersionJobs []fixedVersionJob) ([]fixedVersionJob, error) {
	const purlBatchSize = 1000
	purlsFromJobs := make([]packageurl.PackageURL, 0, len(fixedVersionJobs))
	for _, job := range fixedVersionJobs {
		parsedPurl, err := packageurl.FromString(job.Purl)
		if err == nil {
			purlsFromJobs = append(purlsFromJobs, parsedPurl)
		}
	}

	// split them up into batches to avoid parameter limit
	purlToAffectedComponents := make(map[string][]models.AffectedComponent, len(purlsFromJobs))
	for start := 0; start < len(purlsFromJobs); start += purlBatchSize {
		batchStart := time.Now()
		end := min(start+purlBatchSize, len(purlsFromJobs))
		candidates, err := comparer.GetAffectedComponentsBatch(ctx, purlsFromJobs[start:end])
		if err != nil {
			return nil, fmt.Errorf("could not get affected components for purls: %w", err)
		}

		// map purls to affected components for fast lookups later
		for _, candidate := range candidates {
			if candidate.Components != nil { // filter out unnecessary map entries
				purlToAffectedComponents[candidate.Purl.String()] = candidate.Components
			}
		}
		slog.Info("finished fetching batch", "amount", end, "time", time.Since(batchStart))
	}

	updatingJobs := make([]fixedVersionJob, 0, len(fixedVersionJobs))
	for i, job := range fixedVersionJobs {
		// look up using the same normalization the map keys were built with
		parsedPurl, err := packageurl.FromString(job.Purl)
		if err != nil {
			continue
		}
		affectedComponents := purlToAffectedComponents[parsedPurl.String()]
		for _, ac := range affectedComponents {
			if !slices.Contains(utils.Map(ac.CVE, func(cve models.CVE) string {
				return cve.CVE
			}), job.CVEID) {
				continue
			}

			var fixedVersion *string
			if ac.SemverFixed != nil {
				fixedVersion = normalize.FixFixedVersion(job.Purl, ac.SemverFixed)
			} else if ac.VersionFixed != nil {
				fixedVersion = normalize.FixFixedVersion(job.Purl, ac.VersionFixed)
			}
			if fixedVersion != nil {
				slog.Info("i", "i", i)
				job.FixedVersion = *fixedVersion
				updatingJobs = append(updatingJobs, job)
				break
			}
		}
	}

	return updatingJobs, nil
}
