package services

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/utils"
	"golang.org/x/sync/errgroup"
)

type scopeLevel int

const (
	orgLevel scopeLevel = iota // fully exported, including everything below them
	projectLevel
	assetLevel
	parentOrgLevel // only the row itself, referenced upwards by a scoped project or asset
	parentProjectLevel
)

// resolved ids for every scope level
type exportScope struct {
	orgIDs           []string
	projectIDs       []string
	assetIDs         []string
	parentOrgIDs     []string
	parentProjectIDs []string
}

func (scope exportScope) idsFor(level scopeLevel) []string {
	switch level {
	case orgLevel:
		return scope.orgIDs
	case projectLevel:
		return scope.projectIDs
	case assetLevel:
		return scope.assetIDs
	case parentOrgLevel:
		return scope.parentOrgIDs
	case parentProjectLevel:
		return scope.parentProjectIDs
	default:
		panic(fmt.Sprintf("unknown scope level %d", level))
	}
}

type scopeFilter struct {
	column string
	level  scopeLevel // which resolved ID set the column is matched against
}

type tableProperties struct {
	tableID   string
	filters   []scopeFilter
	model     utils.Tabler
	customSQL *string
}

const transferFileLocation = "/transfer-files/"

// SQL foreign key column constants
const (
	orgTableID      = "organizations"
	projectsTableID = "projects"
	assetsTableID   = "assets"

	orgFKColumn     = "org_id"
	projectFKColumn = "project_id"
	assetFKColumn   = "asset_id"
)

const concurrentDBWorkers = 6

var (
	orgScope     = scopeFilter{column: orgFKColumn, level: orgLevel}
	projectScope = scopeFilter{column: projectFKColumn, level: projectLevel}
	assetScope   = scopeFilter{column: assetFKColumn, level: assetLevel}
)

// all tables with a simple syntax
var tablesToSync []tableProperties = []tableProperties{
	// org level
	{tableID: orgTableID, filters: []scopeFilter{{column: "id", level: orgLevel}, {column: "id", level: parentOrgLevel}}},
	{tableID: projectsTableID, filters: []scopeFilter{{column: "id", level: projectLevel}, {column: "id", level: parentProjectLevel}}},
	{tableID: "compliance_postures", filters: []scopeFilter{orgScope, projectScope, assetScope}},
	// external user org pivot table

	// project level
	//project enabled policies (pivot table)
	{tableID: assetsTableID, filters: []scopeFilter{{column: "id", level: assetLevel}}},

	// asset level
	{tableID: "external_references", filters: []scopeFilter{assetScope}},
	{tableID: "vex_rules", filters: []scopeFilter{assetScope}},
	{tableID: "asset_versions", filters: []scopeFilter{assetScope}},

	// asset version level
	{tableID: "license_risks", filters: []scopeFilter{assetScope}},
	{tableID: "first_party_vulnerabilities", filters: []scopeFilter{assetScope}},
	{tableID: "dependency_vulns", filters: []scopeFilter{assetScope}},
	{tableID: "advisories", filters: []scopeFilter{assetScope}},
	{tableID: "artifacts", filters: []scopeFilter{assetScope}},

	// artifact level
	{tableID: "release_items", filters: []scopeFilter{assetScope}},
	{tableID: "attestations", filters: []scopeFilter{assetScope}},
	{tableID: "sboms", filters: []scopeFilter{assetScope}},
	// artifact dep vulns pivot table
	// artifact license risks pivot table

	// reminder load SBOM merkle data + vuln_events
}

type DataTransferService struct {
	pool *pgxpool.Pool
	// Event Broker?
}

func NewDataTransferService(pool *pgxpool.Pool) *DataTransferService {
	return &DataTransferService{
		pool: pool,
	}
}

func (service *DataTransferService) StartExport(ctx context.Context, options dtos.DataTransferExportOptions) error {
	slog.Info("starting data transfer export process...")
	start := time.Now()

	// GUARD AGAINST SQL INJECTION (validate user input as uuids)

	// initiate read only and read uncommitted transaction to use as snapshot for the export
	snapshotTx, err := service.pool.BeginTx(ctx, pgx.TxOptions{
		IsoLevel:   pgx.RepeatableRead,
		AccessMode: pgx.ReadOnly,
	})
	if err != nil {
		return fmt.Errorf("could not start export transaction: %w", err)
	}

	var snapshotID string // used as reference for other transactions
	err = snapshotTx.QueryRow(ctx, `SELECT pg_export_snapshot();`).Scan(&snapshotID)
	if err != nil {
		return fmt.Errorf("could not retrieve snapshot id: %w", err)
	}

	scope, err := resolveScope(ctx, snapshotTx, options.AffectedEntities)
	if err != nil {
		return err
	}

	jobs := make(chan queryJob, 50) // small number of jobs can all be queued at once
	output := make(chan output, 5)

	group, errCtx := errgroup.WithContext(ctx)
	outputDrainWG := &sync.WaitGroup{}
	group.SetLimit(concurrentDBWorkers) // cap the number of concurrent db reads
	for group.TryGo(func() error { return service.DatabaseQueryWorker(errCtx, snapshotID, jobs, output) }) {
	}
	go func() {
		sql, args, err := sqlFromTableProperties(tablesToSync[0], scope)
		if err != nil {
			slog.Error("could not build export query", "err", err)
			close(jobs)
			return
		}

		jobs <- queryJob{tableID: tablesToSync[0].tableID, sql: sql, args: args}
		close(jobs)
	}()

	outputDrainWG.Go(func() {
		for result := range output {
			slog.Info("received query data", "table", result.tableID, "count", len(result.rows))
		}
	})

	err = group.Wait()
	if err != nil {
		return fmt.Errorf("encountered error during export, aborting: %w", err)
	}
	close(output)

	// wait for output to drain
	outputDrainWG.Wait()

	slog.Info("finished export", "time", time.Since(start))
	return nil
}

type output struct {
	tableID string
	rows    [][]byte // one json object per row
}

type queryJob struct {
	tableID string
	sql     string
	args    []any
}

func (service *DataTransferService) DatabaseQueryWorker(ctx context.Context, snapshotID string, jobs chan queryJob, outputChan chan output) error {
	workerTx, err := service.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return fmt.Errorf("could not start worker tx: %w", err)
	}

	_, err = workerTx.Exec(ctx, fmt.Sprintf("SET TRANSACTION SNAPSHOT '%s';", snapshotID))
	if err != nil {
		return fmt.Errorf("could not set worker transaction snapshot: %w", err)
	}

	for job := range jobs {
		job.sql = job.sql + ";"
		slog.Info("starting new job", "sql", job.sql)
		rows, err := workerTx.Query(ctx, job.sql, job.args...)
		if err != nil {
			return fmt.Errorf("could not query table: %w\n\nSQL: %s", err, job.sql)
		}
		defer rows.Close()

		var tableRows [][]byte
		for rows.Next() {
			var row []byte
			if err := rows.Scan(&row); err != nil {
				return fmt.Errorf("could not scan row of %s: %w", job.tableID, err)
			}
			tableRows = append(tableRows, row)
		}

		if err := rows.Err(); err != nil {
			return fmt.Errorf("error when reading rows: %w", err)
		}
		rows.Close()
		slog.Info("successfully queried table data", "table", job.tableID, "rows count", len(tableRows))
		outputChan <- output{tableID: job.tableID, rows: tableRows}
	}

	slog.Info("worker finished")
	return nil
}

// build the scoped row_to_json query for an exported table, args are ordered like the placeholders
func sqlFromTableProperties(properties tableProperties, scope exportScope) (string, []any, error) {
	// fail closed, an unfiltered query would export data of other tenants
	if len(properties.filters) == 0 {
		return "", nil, fmt.Errorf("table %s has no scope filter", properties.tableID)
	}

	conditions := make([]string, 0, len(properties.filters))
	args := make([]any, 0, len(properties.filters))
	for _, filter := range properties.filters {
		args = append(args, scope.idsFor(filter.level))
		conditions = append(conditions, fmt.Sprintf("t.%s = ANY($%d::uuid[])", pgx.Identifier{filter.column}.Sanitize(), len(args)))
	}
	return fmt.Sprintf("SELECT row_to_json(t) FROM %s t WHERE %s", pgx.Identifier{properties.tableID}.Sanitize(), strings.Join(conditions, " OR ")), args, nil
}

// resolve subprojects to recursively find all projects in scope
const resolveProjectIDsSQL = `WITH RECURSIVE scoped_projects AS (
	SELECT id FROM projects WHERE organization_id = ANY($1::uuid[]) OR id = ANY($2::uuid[])
	UNION
	SELECT p.id FROM projects p JOIN scoped_projects sp ON p.parent_id = sp.id
) SELECT id FROM scoped_projects`

// resolve all implicit asset ids (via projects) and the explicit ones set by the request
const resolveAssetIDsSQL = `SELECT id FROM assets WHERE project_id = ANY($1::uuid[]) OR id = ANY($2::uuid[])`

// then we also need to get all the projects referenced by those assets to ensure FK-relations
const resolveParentProjectIDsSQL = `SELECT project_id FROM assets WHERE id = ANY($1::uuid[])
UNION
SELECT parent_id FROM projects WHERE id = ANY($2::uuid[]) AND parent_id IS NOT NULL`

// lastly we get all referenced orgs to ensure FK-relations
const resolveParentOrgIDsSQL = `SELECT DISTINCT organization_id FROM projects WHERE id = ANY($1::uuid[]) OR id = ANY($2::uuid[])`

// resolve the requested scopes into lists of ids for all levels
func resolveScope(ctx context.Context, tx pgx.Tx, requested dtos.AffectedEntities) (exportScope, error) {
	scope := exportScope{orgIDs: requested.Orgs}

	rows, _ := tx.Query(ctx, resolveProjectIDsSQL, requested.Orgs, requested.Projects)
	projectIDs, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return scope, fmt.Errorf("could not resolve project ids: %w", err)
	}
	scope.projectIDs = projectIDs

	rows, _ = tx.Query(ctx, resolveAssetIDsSQL, scope.projectIDs, requested.Assets)
	assetIDs, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return scope, fmt.Errorf("could not resolve asset ids: %w", err)
	}
	scope.assetIDs = assetIDs

	rows, _ = tx.Query(ctx, resolveParentProjectIDsSQL, requested.Assets, requested.Projects)
	parentProjectIDs, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return scope, fmt.Errorf("could not resolve parent project ids: %w", err)
	}
	scope.parentProjectIDs = parentProjectIDs

	rows, _ = tx.Query(ctx, resolveParentOrgIDsSQL, scope.projectIDs, scope.parentProjectIDs)
	parentOrgIDs, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return scope, fmt.Errorf("could not resolve parent org ids: %w", err)
	}
	scope.parentOrgIDs = parentOrgIDs

	return scope, nil
}
