package services

import (
	"archive/tar"
	"cmp"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/l3montree-dev/devguard/dtos"
	"golang.org/x/sync/errgroup"
)

type scopeLevel int

const dataTransferVersion = 1

const (
	metadataFileName   = "metadata.json"
	tableFileExtension = ".jsonl.gz"
)

const (
	// entities
	orgLevel scopeLevel = iota // fully exported, including everything below them
	projectLevel
	assetLevel
	parentOrgLevel // only the row itself, referenced upwards by a scoped project or asset
	parentProjectLevel

	// derived entities
	artifactLevel // derived from the scoped assets, for tables without a direct scope column (e.g. pivot tables)

	// sets for table data
	externalUserLevel
	dependencyVulnLevel
	firstPartyVulnLevel
	licenseRiskLevel
	compliancePostureLevel
	securityAdvisoryLevel
	assetSignatureLevel
	sbomMerkleNodeLevel

	// shared reference data, only the rows referenced by the scoped entities
	componentLevel
	componentProjectLevel
	frameworkControlLevel
)

// resolved ids for every scope level
type exportScope struct {
	orgIDs               []string
	projectIDs           []string
	assetIDs             []string
	parentOrgIDs         []string
	parentProjectIDs     []string
	artifactIDs          []string
	externalUserIDs      []string
	dependencyVulnIDs    []string
	firstPartyVulnIDs    []string
	licenseRiskIDs       []string
	compliancePostureIDs []string
	securityAdvisoryIDs  []string
	assetSignatures      []string
	sbomMerkleNodeHashes []string
	componentIDs         []string
	componentProjectKeys []string
	frameworkControlIDs  []string
}

// ids of one scope level together with the postgres array type they are cast to
type scopeIDs struct {
	ids       []string
	arrayType string
}

func (scope exportScope) idsFor(level scopeLevel) scopeIDs {
	switch level {
	case orgLevel:
		return scopeIDs{ids: scope.orgIDs, arrayType: "uuid[]"}
	case projectLevel:
		return scopeIDs{ids: scope.projectIDs, arrayType: "uuid[]"}
	case assetLevel:
		return scopeIDs{ids: scope.assetIDs, arrayType: "uuid[]"}
	case parentOrgLevel:
		return scopeIDs{ids: scope.parentOrgIDs, arrayType: "uuid[]"}
	case parentProjectLevel:
		return scopeIDs{ids: scope.parentProjectIDs, arrayType: "uuid[]"}
	case artifactLevel:
		return scopeIDs{ids: scope.artifactIDs, arrayType: "uuid[]"}
	case externalUserLevel:
		return scopeIDs{ids: scope.externalUserIDs, arrayType: "text[]"} // external user ids are provider ids, not uuids
	case dependencyVulnLevel:
		return scopeIDs{ids: scope.dependencyVulnIDs, arrayType: "uuid[]"}
	case firstPartyVulnLevel:
		return scopeIDs{ids: scope.firstPartyVulnIDs, arrayType: "uuid[]"}
	case licenseRiskLevel:
		return scopeIDs{ids: scope.licenseRiskIDs, arrayType: "uuid[]"}
	case compliancePostureLevel:
		return scopeIDs{ids: scope.compliancePostureIDs, arrayType: "uuid[]"}
	case securityAdvisoryLevel:
		return scopeIDs{ids: scope.securityAdvisoryIDs, arrayType: "uuid[]"}
	case assetSignatureLevel:
		return scopeIDs{ids: scope.assetSignatures, arrayType: "bigint[]"}
	case sbomMerkleNodeLevel:
		return scopeIDs{ids: scope.sbomMerkleNodeHashes, arrayType: "uuid[]"}
	case componentLevel:
		return scopeIDs{ids: scope.componentIDs, arrayType: "text[]"} // component ids are purls
	case componentProjectLevel:
		return scopeIDs{ids: scope.componentProjectKeys, arrayType: "text[]"}
	case frameworkControlLevel:
		return scopeIDs{ids: scope.frameworkControlIDs, arrayType: "text[]"}
	default:
		panic(fmt.Sprintf("unknown scope level %d", level))
	}
}

type scopeFilter struct {
	column string
	level  scopeLevel // which resolved ID set the column is matched against
}

// SQL foreign key column constants
const (
	orgTableID      = "organizations"
	projectsTableID = "projects"
	assetsTableID   = "assets"

	orgFKColumn      = "org_id"
	projectFKColumn  = "project_id"
	assetFKColumn    = "asset_id"
	artifactFKColumn = "artifact_id"
)

const concurrentDBWorkers = 6

var (
	orgScope      = scopeFilter{column: orgFKColumn, level: orgLevel}
	projectScope  = scopeFilter{column: projectFKColumn, level: projectLevel}
	assetScope    = scopeFilter{column: assetFKColumn, level: assetLevel}
	artifactScope = scopeFilter{column: artifactFKColumn, level: artifactLevel}
)

type tableProperties struct {
	filters      []scopeFilter
	importOrder  int  // tables only reference tables with a lower import order, equal ones are independent of each other
	skipExisting bool // shared reference data, rows already present on the target are kept
}

// all tables with a simple syntax, keyed by table name
var tablesToSync = map[string]tableProperties{
	// org level
	orgTableID:            {importOrder: 0, filters: []scopeFilter{{column: "id", level: orgLevel}, {column: "id", level: parentOrgLevel}}},
	projectsTableID:       {importOrder: 1, filters: []scopeFilter{{column: "id", level: projectLevel}, {column: "id", level: parentProjectLevel}}},
	"compliance_postures": {importOrder: 4, filters: []scopeFilter{orgScope, projectScope, assetScope}},
	"external_users":      {importOrder: 0, filters: []scopeFilter{{column: "id", level: externalUserLevel}}},
	"external_user_orgs":  {importOrder: 1, filters: []scopeFilter{orgScope}},

	// project level
	assetsTableID: {importOrder: 2, filters: []scopeFilter{{column: "id", level: assetLevel}}},

	// asset level
	"external_references": {importOrder: 3, filters: []scopeFilter{assetScope}},
	"vex_rules":           {importOrder: 3, filters: []scopeFilter{assetScope}},
	"asset_versions":      {importOrder: 3, filters: []scopeFilter{assetScope}},

	// asset version level
	"license_risks":               {importOrder: 4, filters: []scopeFilter{assetScope}},
	"first_party_vulnerabilities": {importOrder: 4, filters: []scopeFilter{assetScope}},
	"dependency_vulns":            {importOrder: 4, filters: []scopeFilter{assetScope}},
	"advisories":                  {importOrder: 4, filters: []scopeFilter{assetScope}},
	"artifacts":                   {importOrder: 4, filters: []scopeFilter{assetScope}},

	// artifact level
	"attestations":              {importOrder: 5, filters: []scopeFilter{assetScope}},
	"sboms":                     {importOrder: 5, filters: []scopeFilter{assetScope}},
	"artifact_dependency_vulns": {importOrder: 5, filters: []scopeFilter{artifactScope}},
	"artifact_license_risks":    {importOrder: 5, filters: []scopeFilter{artifactScope}},

	// package level
	"sbom_merkle_nodes": {importOrder: 0, filters: []scopeFilter{{column: "node_hash", level: sbomMerkleNodeLevel}}},
	"sbom_merkle_edges": {importOrder: 1, filters: []scopeFilter{{column: "subtree_hash", level: sbomMerkleNodeLevel}}}, // a node hash fixes its children, so all edges of a reachable parent are in scope

	// shared reference data
	"component_projects":  {importOrder: 0, skipExisting: true, filters: []scopeFilter{{column: "project_key", level: componentProjectLevel}}},
	"components":          {importOrder: 1, skipExisting: true, filters: []scopeFilter{{column: "id", level: componentLevel}}},
	"frameworks_controls": {importOrder: 0, skipExisting: true, filters: []scopeFilter{{column: "framework_control_id", level: frameworkControlLevel}}},

	// vuln level
	"vuln_events": {importOrder: 5, filters: []scopeFilter{
		{column: "dependency_vuln_id", level: dependencyVulnLevel},
		{column: "first_party_vuln_id", level: firstPartyVulnLevel},
		{column: "license_risk_id", level: licenseRiskLevel},
		{column: "compliance_posture_id", level: compliancePostureLevel},
		{column: "security_advisory_id", level: securityAdvisoryLevel},
		{column: "asset_signature", level: assetSignatureLevel}, // group events of all dependency vulns sharing the signature
	}},
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

func checkExportOptions(options dtos.DataTransferExportOptions) error {
	for _, id := range append(options.AffectedEntities.Orgs, append(options.AffectedEntities.Projects, options.AffectedEntities.Assets...)...) {
		if _, err := uuid.Parse(id); err != nil {
			return fmt.Errorf("export options contain invalid uuid (%s): %w", id, err)
		}
	}
	return nil
}

func (service *DataTransferService) StartExport(ctx context.Context, options dtos.DataTransferExportOptions, out io.Writer) error {
	start := time.Now()

	// validate export options
	if err := checkExportOptions(options); err != nil {
		return fmt.Errorf("invalid export options provided: %w", err)
	}

	jobDirectoryPath, err := os.MkdirTemp("", "devguard-export-*")
	if err != nil {
		return fmt.Errorf("could not create export directory: %w", err)
	}

	// the files are only needed until they are written to out
	defer func() {
		if err := os.RemoveAll(jobDirectoryPath); err != nil {
			slog.Error("could not clean up export directory", "path", jobDirectoryPath, "err", err)
		}
	}()

	slog.Info("starting data transfer export process...", "directory", jobDirectoryPath)

	// initiate read only and read uncommitted transaction to use as snapshot for the export
	snapshotTx, err := service.pool.BeginTx(ctx, pgx.TxOptions{
		IsoLevel:   pgx.RepeatableRead,
		AccessMode: pgx.ReadOnly,
	})

	if err != nil {
		return fmt.Errorf("could not start export transaction: %w", err)
	}
	defer snapshotTx.Commit(ctx) // ends the transaction before returning

	var snapshotID string // used as reference for other transactions
	err = snapshotTx.QueryRow(ctx, `SELECT pg_export_snapshot();`).Scan(&snapshotID)
	if err != nil {
		return fmt.Errorf("could not retrieve snapshot id: %w", err)
	}

	// ensure correct export scope
	if _, err := snapshotTx.Exec(ctx, "SET search_path TO public"); err != nil {
		return fmt.Errorf("could not set search path for export: %w", err)
	}

	// check the schema migration version and dirtiness of the database
	var schemaMigration struct {
		version string
		dirty   bool
	}

	schemaRow := snapshotTx.QueryRow(ctx, "SELECT version, dirty FROM schema_migrations LIMIT 1;")
	if err := schemaRow.Scan(&schemaMigration.version, &schemaMigration.dirty); err != nil {
		return fmt.Errorf("could not determine schema migration state: %w", err)
	}

	if schemaMigration.dirty {
		return fmt.Errorf("dirty database schema detected, cannot export.")
	}

	scope, err := resolveScope(ctx, snapshotTx, options.AffectedEntities)
	if err != nil {
		return err
	}

	// concurrent data structure setup
	jobs := make(chan queryJob, len(tablesToSync)) // small number of jobs, all can be queued at once
	group, errCtx := errgroup.WithContext(ctx)

	// start the db query worker pool
	group.SetLimit(concurrentDBWorkers + 1) // cap the number of concurrent db reads (1 for the producer routine)

	// start the producer function first
	group.Go(func() error {
		defer close(jobs)
		for tableID, table := range tablesToSync {
			sql, args, err := sqlFromTableProperties(tableID, table, scope)
			if err != nil {
				return fmt.Errorf("could not build export query: %w", err)
			}

			jobs <- queryJob{tableID: tableID, sql: sql, args: args}
		}
		return nil
	})

	// then spin up the worker pool
	for group.TryGo(func() error {
		return service.DatabaseQueryWorker(errCtx, jobDirectoryPath, snapshotID, jobs)
	}) {
	}

	err = group.Wait()
	if err != nil {
		return fmt.Errorf("encountered error during export, aborting: %w", err)
	}

	slog.Info("finished writing file data", "time", time.Since(start))

	var exportTimestamp time.Time
	if err := snapshotTx.QueryRow(ctx, "SELECT current_timestamp;").Scan(&exportTimestamp); err != nil {
		return fmt.Errorf("could not extract transaction timestamp: %w", err)
	}

	err = buildMetadataFile(jobDirectoryPath, options, schemaMigration.version, exportTimestamp)
	if err != nil {
		return fmt.Errorf("could not build metadata file: %w", err)
	}

	// release the snapshot before sending, a slow client should not keep the transaction open
	if err := snapshotTx.Commit(ctx); err != nil {
		return fmt.Errorf("could not end export transaction: %w", err)
	}

	slog.Info("finished export, sending archive", "time", time.Since(start))

	// the table files are already gzipped, so the archive itself stays uncompressed
	tarWriter := tar.NewWriter(out)
	if err := tarWriter.AddFS(os.DirFS(jobDirectoryPath)); err != nil {
		return fmt.Errorf("could not write export archive: %w", err)
	}
	if err := tarWriter.Close(); err != nil {
		return fmt.Errorf("could not finish export archive: %w", err)
	}

	slog.Info("finished sending archive", "time", time.Since(start))
	return nil
}

type queryJob struct {
	tableID string
	sql     string
	args    []any
}

type metadata struct {
	ExportVersion         int                   `json:"export_version"`
	DatabaseSchemaVersion string                `json:"database_schema_version"`
	ExportTimestamp       time.Time             `json:"export_timestamp"`
	ExportScope           dtos.AffectedEntities `json:"export_scope"`
}

func buildMetadataFile(jobDirectoryPath string, exportOptions dtos.DataTransferExportOptions, databaseSchemaVersion string, exportTimestamp time.Time) error {
	metadataFD, err := os.Create(filepath.Join(jobDirectoryPath, metadataFileName))
	if err != nil {
		return fmt.Errorf("could not create metadata file: %w", err)
	}
	defer metadataFD.Close()

	exportMetadata := metadata{
		ExportVersion:         dataTransferVersion,
		DatabaseSchemaVersion: databaseSchemaVersion,
		ExportTimestamp:       exportTimestamp,
		ExportScope:           exportOptions.AffectedEntities,
	}

	err = json.NewEncoder(metadataFD).Encode(exportMetadata)
	if err != nil {
		return fmt.Errorf("could not write metadata file: %w", err)
	}
	return metadataFD.Close()
}

func (service *DataTransferService) DatabaseQueryWorker(ctx context.Context, baseFolder string, snapshotID string, jobs chan queryJob) error {
	workerTx, err := service.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return fmt.Errorf("could not start worker tx: %w", err)
	}
	defer workerTx.Rollback(ctx)

	_, err = workerTx.Exec(ctx, fmt.Sprintf("SET TRANSACTION SNAPSHOT '%s';", snapshotID))
	if err != nil {
		return fmt.Errorf("could not set worker transaction snapshot: %w", err)
	}

	for job := range jobs {
		if err := exportTable(ctx, workerTx, baseFolder, job); err != nil {
			return err
		}
	}

	slog.Info("db worker finished")
	return nil
}

// separate function so the defers run per table instead of piling up until the worker returns
func exportTable(ctx context.Context, tx pgx.Tx, baseFolder string, job queryJob) error {
	job.sql = job.sql + ";"
	slog.Info("starting new job", "sql", job.sql)
	rows, err := tx.Query(ctx, job.sql, job.args...)
	if err != nil {
		return fmt.Errorf("could not query table: %w\n\nSQL: %s", err, job.sql)
	}
	defer rows.Close()

	tableFd, err := os.Create(filepath.Join(baseFolder, job.tableID+tableFileExtension))
	if err != nil {
		return fmt.Errorf("could not create file for table data, table (%s): %w", job.tableID, err)
	}
	defer tableFd.Close()
	gzipWriter := gzip.NewWriter(tableFd)
	defer gzipWriter.Close()

	for rows.Next() {
		var row []byte
		if err := rows.Scan(&row); err != nil {
			return fmt.Errorf("could not scan row of %s: %w", job.tableID, err)
		}

		// row is already json from row_to_json, we can just write that with a newline
		if _, err := gzipWriter.Write(append(row, '\n')); err != nil {
			return fmt.Errorf("could not write row of %s: %w", job.tableID, err)
		}
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("error when reading rows: %w", err)
	}
	slog.Info("successfully queried table data", "table", job.tableID, "rows count", rows.CommandTag().RowsAffected())
	rows.Close()
	// finish up the gzip file
	if err := gzipWriter.Close(); err != nil {
		return fmt.Errorf("could not finish compressed file of %s: %w", job.tableID, err)
	}
	if err := tableFd.Close(); err != nil {
		return fmt.Errorf("could not close file of %s: %w", job.tableID, err)
	}
	return nil
}

// build the scoped row_to_json query for an exported table, args are ordered like the placeholders
func sqlFromTableProperties(tableID string, properties tableProperties, scope exportScope) (string, []any, error) {
	// fail closed, an unfiltered query would export data of other tenants
	if len(properties.filters) == 0 {
		return "", nil, fmt.Errorf("table %s has no scope filter", tableID)
	}

	conditions := make([]string, 0, len(properties.filters))
	args := make([]any, 0, len(properties.filters))
	for _, filter := range properties.filters {
		scopeIDs := scope.idsFor(filter.level)
		args = append(args, scopeIDs.ids)
		conditions = append(conditions, fmt.Sprintf("t.%s = ANY($%d::%s)", pgx.Identifier{filter.column}.Sanitize(), len(args), scopeIDs.arrayType))
	}
	return fmt.Sprintf("SELECT row_to_json(t) FROM %s t WHERE %s", pgx.Identifier{tableID}.Sanitize(), strings.Join(conditions, " OR ")), args, nil
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

// artifacts of the scoped assets, used by the artifact pivot tables
const resolveArtifactIDsSQL = `SELECT id FROM artifacts WHERE asset_id = ANY($1::uuid[])`

// external users which are members of a fully scoped org
const resolveExternalUserIDsSQL = `SELECT DISTINCT external_user_id FROM external_user_orgs WHERE org_id = ANY($1::uuid[])`

// vulns of the scoped assets, used by the vuln events
const resolveDependencyVulnIDsSQL = `SELECT id FROM dependency_vulns WHERE asset_id = ANY($1::uuid[])`
const resolveFirstPartyVulnIDsSQL = `SELECT id FROM first_party_vulnerabilities WHERE asset_id = ANY($1::uuid[])`
const resolveLicenseRiskIDsSQL = `SELECT id FROM license_risks WHERE asset_id = ANY($1::uuid[])`
const resolveSecurityAdvisoryIDsSQL = `SELECT id FROM advisories WHERE asset_id = ANY($1::uuid[])`

// same filters as the compliance_postures table export
const resolveCompliancePostureIDsSQL = `SELECT id FROM compliance_postures WHERE org_id = ANY($1::uuid[]) OR project_id = ANY($2::uuid[]) OR asset_id = ANY($3::uuid[])`

// the asset id is part of the signature hash, so signatures never span multiple assets
const resolveAssetSignaturesSQL = `SELECT DISTINCT asset_signature::text FROM dependency_vulns WHERE asset_id = ANY($1::uuid[])`

// recursively walk the merkle graph down from the roots of the scoped sboms
const resolveSBOMMerkleNodeHashesSQL = `WITH RECURSIVE reachable AS (
	SELECT root_subtree_hash AS node_hash FROM sboms WHERE asset_id = ANY($1::uuid[])
	UNION
	SELECT e.direct_dependency_subtree_hash FROM sbom_merkle_edges e JOIN reachable r ON e.subtree_hash = r.node_hash
) SELECT node_hash FROM reachable`

// components referenced by the scoped license risks
const resolveComponentIDsSQL = `SELECT DISTINCT component_purl FROM license_risks WHERE id = ANY($1::uuid[])`

// projects of those components, project_key is optional
const resolveComponentProjectKeysSQL = `SELECT DISTINCT project_key FROM components WHERE id = ANY($1::text[]) AND project_key IS NOT NULL`

// framework controls referenced by the scoped compliance postures
const resolveFrameworkControlIDsSQL = `SELECT DISTINCT framework_control_id FROM compliance_postures WHERE id = ANY($1::uuid[]) AND framework_control_id IS NOT NULL`

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

	rows, _ = tx.Query(ctx, resolveArtifactIDsSQL, scope.assetIDs)
	artifactIDs, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return scope, fmt.Errorf("could not resolve artifact ids: %w", err)
	}
	scope.artifactIDs = artifactIDs

	rows, _ = tx.Query(ctx, resolveExternalUserIDsSQL, scope.orgIDs)
	externalUserIDs, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return scope, fmt.Errorf("could not resolve external user ids: %w", err)
	}
	scope.externalUserIDs = externalUserIDs

	rows, _ = tx.Query(ctx, resolveDependencyVulnIDsSQL, scope.assetIDs)
	dependencyVulnIDs, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return scope, fmt.Errorf("could not resolve dependency vuln ids: %w", err)
	}
	scope.dependencyVulnIDs = dependencyVulnIDs

	rows, _ = tx.Query(ctx, resolveFirstPartyVulnIDsSQL, scope.assetIDs)
	firstPartyVulnIDs, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return scope, fmt.Errorf("could not resolve first party vuln ids: %w", err)
	}
	scope.firstPartyVulnIDs = firstPartyVulnIDs

	rows, _ = tx.Query(ctx, resolveLicenseRiskIDsSQL, scope.assetIDs)
	licenseRiskIDs, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return scope, fmt.Errorf("could not resolve license risk ids: %w", err)
	}
	scope.licenseRiskIDs = licenseRiskIDs

	rows, _ = tx.Query(ctx, resolveCompliancePostureIDsSQL, scope.orgIDs, scope.projectIDs, scope.assetIDs)
	compliancePostureIDs, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return scope, fmt.Errorf("could not resolve compliance posture ids: %w", err)
	}
	scope.compliancePostureIDs = compliancePostureIDs

	rows, _ = tx.Query(ctx, resolveSecurityAdvisoryIDsSQL, scope.assetIDs)
	securityAdvisoryIDs, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return scope, fmt.Errorf("could not resolve security advisory ids: %w", err)
	}
	scope.securityAdvisoryIDs = securityAdvisoryIDs

	rows, _ = tx.Query(ctx, resolveAssetSignaturesSQL, scope.assetIDs)
	assetSignatures, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return scope, fmt.Errorf("could not resolve asset signatures: %w", err)
	}
	scope.assetSignatures = assetSignatures

	rows, _ = tx.Query(ctx, resolveSBOMMerkleNodeHashesSQL, scope.assetIDs)
	sbomMerkleNodeHashes, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return scope, fmt.Errorf("could not resolve sbom merkle node hashes: %w", err)
	}
	scope.sbomMerkleNodeHashes = sbomMerkleNodeHashes

	rows, _ = tx.Query(ctx, resolveComponentIDsSQL, scope.licenseRiskIDs)
	componentIDs, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return scope, fmt.Errorf("could not resolve component ids: %w", err)
	}
	scope.componentIDs = componentIDs

	rows, _ = tx.Query(ctx, resolveComponentProjectKeysSQL, scope.componentIDs)
	componentProjectKeys, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return scope, fmt.Errorf("could not resolve component project keys: %w", err)
	}
	scope.componentProjectKeys = componentProjectKeys

	rows, _ = tx.Query(ctx, resolveFrameworkControlIDsSQL, scope.compliancePostureIDs)
	frameworkControlIDs, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return scope, fmt.Errorf("could not resolve framework control ids: %w", err)
	}
	scope.frameworkControlIDs = frameworkControlIDs

	return scope, nil
}

type errorHandling struct {
	method       string // nothing, update (columns)
	updateColumn []string
}

type importJob struct {
	tableName        string
	tableImportOrder int
	pathToFile       string
}

func (service *DataTransferService) ImportFile(ctx context.Context, importFile io.Reader) error {
	slog.Info("start importing data...")
	start := time.Now()

	importDirectoryPath, err := os.MkdirTemp("", "devguard-import-*")
	if err != nil {
		return fmt.Errorf("could not create import directory: %w", err)
	}
	defer func() {
		if err := os.RemoveAll(importDirectoryPath); err != nil {
			slog.Error("could not clean up import directory", "path", importDirectoryPath, "err", err)
		}
	}()

	if err := extractImportArchive(importFile, importDirectoryPath); err != nil {
		return fmt.Errorf("could not extract import archive: %w", err)
	}

	importTx, err := service.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("could not start import transaction: %w", err)
	}
	defer importTx.Rollback(ctx) // no-op after a successful commit

	if _, err := importTx.Exec(ctx, "SET LOCAL search_path TO public"); err != nil {
		return fmt.Errorf("could not set search path for import: %w", err)
	}

	if err := checkImportMetadata(ctx, importTx, importDirectoryPath); err != nil {
		return err // error explained in the called function
	}

	importFiles, err := os.ReadDir(importDirectoryPath)
	if err != nil {
		return fmt.Errorf("could not read import directory: %w", err)
	}

	jobs := make([]importJob, 0, len(importFiles))
	// validate files and parse them into jobs
	for _, file := range importFiles {
		if file.Name() == metadataFileName {
			continue
		}

		fileID, found := strings.CutSuffix(file.Name(), tableFileExtension)
		if !found {
			return fmt.Errorf("invalid file encoding for file: %s", file.Name())
		}

		tableData, ok := tablesToSync[fileID]
		if !ok {
			return fmt.Errorf("invalid fileName detected: %s", file.Name())
		}

		jobs = append(jobs, importJob{
			tableName:        fileID,
			tableImportOrder: tableData.importOrder,
			pathToFile:       filepath.Join(importDirectoryPath, file.Name()),
		})
	}

	// sort the jobs to ensure no FK violations
	slices.SortFunc(jobs, func(job1, job2 importJob) int {
		return cmp.Compare(job1.tableImportOrder, job2.tableImportOrder)
	})

	// every table is copied into this staging table first, so postgres can convert the json rows itself
	if _, err := importTx.Exec(ctx, "CREATE TEMP TABLE import_staging (data jsonb) ON COMMIT DROP"); err != nil {
		return fmt.Errorf("could not create staging table: %w", err)
	}

	for _, job := range jobs {
		if err := importTable(ctx, importTx, job); err != nil {
			return err
		}
	}

	if err := importTx.Commit(ctx); err != nil {
		return fmt.Errorf("could not commit import transaction: %w", err)
	}

	slog.Info("successfully finished import", "time", time.Since(start))
	return nil
}

func importTable(ctx context.Context, tx pgx.Tx, job importJob) error {
	file, err := os.Open(job.pathToFile)
	if err != nil {
		return fmt.Errorf("could not open file of %s: %w", job.tableName, err)
	}
	defer file.Close()

	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		return fmt.Errorf("could not decompress file of %s: %w", job.tableName, err)
	}
	defer gzipReader.Close()

	if _, err := tx.Exec(ctx, "TRUNCATE import_staging"); err != nil {
		return fmt.Errorf("could not reset staging table: %w", err)
	}

	// csv with control characters as quote and delimiter, so COPY leaves the json backslash escapes untouched
	copyTag, err := tx.Conn().PgConn().CopyFrom(ctx, gzipReader, `COPY import_staging (data) FROM STDIN WITH (FORMAT csv, QUOTE E'\x01', DELIMITER E'\x02')`)
	if err != nil {
		return fmt.Errorf("could not copy rows of %s: %w", job.tableName, err)
	}

	table := pgx.Identifier{job.tableName}.Sanitize()
	insertSQL := fmt.Sprintf("INSERT INTO %s SELECT r.* FROM import_staging, jsonb_populate_record(NULL::%s, data) r", table, table)
	if tablesToSync[job.tableName].skipExisting {
		insertSQL += " ON CONFLICT DO NOTHING"
	}
	insertTag, err := tx.Exec(ctx, insertSQL)
	if err != nil {
		return fmt.Errorf("could not insert rows of %s: %w", job.tableName, err)
	}

	slog.Info("imported table", "table", job.tableName, "copied rows", copyTag.RowsAffected(), "inserted rows", insertTag.RowsAffected())
	return nil
}

// TODO handle file inclusion attacks vectors
func extractImportArchive(importFile io.Reader, importDirectoryPath string) error {
	allowedFiles := map[string]bool{metadataFileName: true}
	for tableID := range tablesToSync {
		allowedFiles[tableID+tableFileExtension] = true
	}

	tarReader := tar.NewReader(importFile)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("could not read archive entry: %w", err)
		}

		if header.Typeflag != tar.TypeReg || !allowedFiles[header.Name] {
			return fmt.Errorf("unexpected archive entry: %s", header.Name)
		}

		if err := extractArchiveFile(tarReader, filepath.Join(importDirectoryPath, header.Name)); err != nil {
			return err
		}
	}
	return nil
}

func extractArchiveFile(tarReader *tar.Reader, filePath string) error {
	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("could not create file %s: %w", filepath.Base(filePath), err)
	}
	defer file.Close()

	if _, err := io.Copy(file, tarReader); err != nil {
		return fmt.Errorf("could not extract file %s: %w", filepath.Base(filePath), err)
	}
	return nil
}

// the rows are only valid for the exact schema they were exported from
func checkImportMetadata(ctx context.Context, tx pgx.Tx, importDirectoryPath string) error {
	metadataFile, err := os.Open(filepath.Join(importDirectoryPath, metadataFileName))
	if err != nil {
		return fmt.Errorf("could not open metadata file: %w", err)
	}
	defer metadataFile.Close()

	var importMetadata metadata
	if err := json.NewDecoder(metadataFile).Decode(&importMetadata); err != nil {
		return fmt.Errorf("could not read metadata file: %w", err)
	}

	if importMetadata.ExportVersion != dataTransferVersion {
		return fmt.Errorf("export version does not match DevGuard version (export: %d, current: %d)", importMetadata.ExportVersion, dataTransferVersion)
	}

	var schemaMigration struct {
		version string
		dirty   bool
	}
	schemaRow := tx.QueryRow(ctx, "SELECT version, dirty FROM schema_migrations LIMIT 1;")
	if err := schemaRow.Scan(&schemaMigration.version, &schemaMigration.dirty); err != nil {
		return fmt.Errorf("could not determine schema migration state: %w", err)
	}

	if schemaMigration.dirty {
		return fmt.Errorf("dirty database schema detected, cannot import")
	}

	if importMetadata.DatabaseSchemaVersion != schemaMigration.version {
		return fmt.Errorf("export schema version %s does not match database schema version %s", importMetadata.DatabaseSchemaVersion, schemaMigration.version)
	}
	return nil
}
