package services

import (
	"archive/tar"
	"cmp"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"golang.org/x/sync/errgroup"
)

//-------------------------------------------------------------------
//						Module Definitions
//-------------------------------------------------------------------

const dataTransferVersion = 1 // current data transfer version to check compatibility
// if breaking changes are introduced increase by 1

const (
	metadataFileName   = "metadata.json"
	tableFileExtension = ".jsonl.gz"
)

type DataTransferService struct {
	pool           *pgxpool.Pool
	rbacProvider   shared.RBACProvider
	projectService shared.ProjectService
	assetService   shared.AssetService
}

func NewDataTransferService(pool *pgxpool.Pool, rbacProvider shared.RBACProvider, projectService shared.ProjectService, assetService shared.AssetService) *DataTransferService {
	return &DataTransferService{
		pool:           pool,
		rbacProvider:   rbacProvider,
		projectService: projectService,
		assetService:   assetService,
	}
}

//-------------------------------------------------------------------
//						Structs and Types
//-------------------------------------------------------------------

// resolved ids keyed by id set name, resolveScope sets every key so a misspelled key fails the export
type exportScope map[string][]string

type scopeFilter struct {
	column    string
	ids       string // which resolved id set the column is matched against
	arrayType string // postgres array type the ids are cast to, since different ids have different datatypes
}

type tableProperties struct {
	filters          []scopeFilter
	importOrder      int  // tables only reference tables on lower import order values
	conflictsAllowed bool // true = on conflict do nothing, else fail on conflict
}

// shortcut for common scope filters
var (
	assetScope    = scopeFilter{column: "asset_id", ids: "assetIDs", arrayType: "uuid[]"}
	artifactScope = scopeFilter{column: "artifact_id", ids: "artifactIDs", arrayType: "uuid[]"}
)

// all tables with a simple syntax, keyed by table name
var tablesToSync = map[string]tableProperties{
	// org level
	"organizations":       {importOrder: 0, filters: []scopeFilter{{column: "id", ids: "orgIDs", arrayType: "uuid[]"}}},
	"projects":            {importOrder: 1, filters: []scopeFilter{{column: "id", ids: "projectIDs", arrayType: "uuid[]"}}},
	"compliance_postures": {importOrder: 4, filters: []scopeFilter{{column: "org_id", ids: "orgIDs", arrayType: "uuid[]"}}}, // only org exports, the posture id is a hash over the org so it does not make sense to export on project or asset level
	"external_users":      {importOrder: 0, conflictsAllowed: true, filters: []scopeFilter{{column: "id", ids: "externalUserIDs", arrayType: "text[]"}}},
	"external_user_orgs":  {importOrder: 1, filters: []scopeFilter{{column: "org_id", ids: "orgIDs", arrayType: "uuid[]"}}},

	// project level
	"assets": {importOrder: 2, filters: []scopeFilter{{column: "id", ids: "assetIDs", arrayType: "uuid[]"}}},

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

	// sbom data
	"sbom_merkle_nodes": {importOrder: 0, conflictsAllowed: true, filters: []scopeFilter{{column: "node_hash", ids: "sbomMerkleNodeHashes", arrayType: "uuid[]"}}},
	"sbom_merkle_edges": {importOrder: 1, conflictsAllowed: true, filters: []scopeFilter{{column: "subtree_hash", ids: "sbomMerkleNodeHashes", arrayType: "uuid[]"}}}, // a node hash fixes its children, so all edges of a reachable parent are in scope

	// shared reference data
	"component_projects":  {importOrder: 0, conflictsAllowed: true, filters: []scopeFilter{{column: "project_key", ids: "componentProjectKeys", arrayType: "text[]"}}},
	"components":          {importOrder: 1, conflictsAllowed: true, filters: []scopeFilter{{column: "id", ids: "componentIDs", arrayType: "text[]"}}},
	"frameworks_controls": {importOrder: 0, conflictsAllowed: true, filters: []scopeFilter{{column: "framework_control_id", ids: "frameworkControlIDs", arrayType: "text[]"}}},

	// vuln events
	"vuln_events": {importOrder: 5, filters: []scopeFilter{
		{column: "dependency_vuln_id", ids: "dependencyVulnIDs", arrayType: "uuid[]"},
		{column: "first_party_vuln_id", ids: "firstPartyVulnIDs", arrayType: "uuid[]"},
		{column: "license_risk_id", ids: "licenseRiskIDs", arrayType: "uuid[]"},
		{column: "compliance_posture_id", ids: "compliancePostureIDs", arrayType: "uuid[]"},
		{column: "security_advisory_id", ids: "securityAdvisoryIDs", arrayType: "uuid[]"},
		{column: "asset_signature", ids: "assetSignatures", arrayType: "bigint[]"}, // group events of all dependency vulns sharing the signature
	}},
}

//-------------------------------------------------------------------
//		SQL constants for resolving table data from id sets
//-------------------------------------------------------------------

// all projects of an org, sub projects belong to the same org
const resolveOrgProjectIDsSQL = `SELECT id FROM projects WHERE organization_id = $1`

// the exported project and all its sub projects
const resolveSubProjectIDsSQL = `WITH RECURSIVE sub_projects AS (
	SELECT id FROM projects WHERE id = $1
	UNION
	SELECT p.id FROM projects p JOIN sub_projects sp ON p.parent_id = sp.id
) SELECT id FROM sub_projects`

const resolveAssetIDsSQL = `SELECT id FROM assets WHERE project_id = ANY($1::uuid[])`

// artifacts of the scoped assets, used by the artifact pivot tables
const resolveArtifactIDsSQL = `SELECT id FROM artifacts WHERE asset_id = ANY($1::uuid[])`

// external users which are members of a fully scoped org
const resolveExternalUserIDsSQL = `SELECT DISTINCT external_user_id FROM external_user_orgs WHERE org_id = ANY($1::uuid[])`

// vulns of the scoped assets, used by the vuln events
const resolveDependencyVulnIDsSQL = `SELECT id FROM dependency_vulns WHERE asset_id = ANY($1::uuid[])`
const resolveFirstPartyVulnIDsSQL = `SELECT id FROM first_party_vulnerabilities WHERE asset_id = ANY($1::uuid[])`
const resolveLicenseRiskIDsSQL = `SELECT id FROM license_risks WHERE asset_id = ANY($1::uuid[])`
const resolveSecurityAdvisoryIDsSQL = `SELECT id FROM advisories WHERE asset_id = ANY($1::uuid[])`

// same filter as the compliance_postures table export
const resolveCompliancePostureIDsSQL = `SELECT id FROM compliance_postures WHERE org_id = ANY($1::uuid[])`

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

//-------------------------------------------------------------------
//							Export Logic
//-------------------------------------------------------------------

func (service *DataTransferService) StartExport(ctx context.Context, options dtos.DataTransferExportOptions, out io.Writer) error {
	start := time.Now()

	// export will be built here and then discarded after successful transmission
	jobDirectoryPath, err := os.MkdirTemp("", "devguard-export-*")
	if err != nil {
		return fmt.Errorf("could not create export directory: %w", err)
	}

	// clean up temp directory
	defer func() {
		if err := os.RemoveAll(jobDirectoryPath); err != nil {
			slog.Error("could not clean up export directory", "path", jobDirectoryPath, "err", err)
		}
	}()

	slog.Info("starting data transfer export process...", "directory", jobDirectoryPath)

	// initiate read only and repeatable read transaction to use as snapshot for the export
	// read only enforces no writes and makes queries more efficient
	// repeatable read enforces a snapshot on the current state of the database eliminating race conditions
	snapshotTx, err := service.pool.BeginTx(ctx, pgx.TxOptions{
		IsoLevel:   pgx.RepeatableRead,
		AccessMode: pgx.ReadOnly,
	})
	if err != nil {
		return fmt.Errorf("could not start export transaction: %w", err)
	}
	defer snapshotTx.Commit(ctx) // nolint
	// ends the transaction (releases snapshot) before returning

	var snapshotID string // used as reference for the other transactions -> use the same snapshot
	err = snapshotTx.QueryRow(ctx, `SELECT pg_export_snapshot();`).Scan(&snapshotID)
	if err != nil {
		return fmt.Errorf("could not retrieve snapshot id: %w", err)
	}

	// ensure correct export scope
	if _, err := snapshotTx.Exec(ctx, "SET search_path TO public"); err != nil {
		return fmt.Errorf("could not set search path for export: %w", err)
	}

	databaseSchemaVersion, err := currentSchemaVersion(ctx, snapshotTx)
	if err != nil {
		return err
	}

	// first step is to resolve the export scope into set of ids to query the actual tables with
	// each id set gets filled with the ids found in scope
	scope, err := resolveScope(ctx, snapshotTx, options)
	if err != nil {
		return err
	}

	// now we resolved the export scope into a set of ids for each affected table
	// this makes each table lookup an independent job, thus allowing for concurrent reads
	jobs := make(chan string, len(tablesToSync)) // small number of jobs, all can be queued at once
	for tableID := range tablesToSync {
		jobs <- tableID
	}
	close(jobs)

	const concurrentDBWorkers = 6

	// each worker receives a table, queries it and writes the result to the temporary directory
	group, errCtx := errgroup.WithContext(ctx)
	for range concurrentDBWorkers {
		group.Go(func() error {
			return service.databaseQueryWorker(errCtx, jobDirectoryPath, snapshotID, scope, jobs)
		})
	}

	err = group.Wait()
	if err != nil {
		return fmt.Errorf("encountered error during export, aborting: %w", err)
	}

	slog.Info("finished writing file data", "time", time.Since(start))

	// at this point all the table data has been exported in the temp directory each in a separate compressed json file
	// now we just need to wrap it up with a metadata file
	var exportTimestamp time.Time
	// current_timestamp is constant across the whole transaction
	if err := snapshotTx.QueryRow(ctx, "SELECT current_timestamp;").Scan(&exportTimestamp); err != nil {
		return fmt.Errorf("could not extract transaction timestamp: %w", err)
	}

	err = buildMetadataFile(jobDirectoryPath, options, databaseSchemaVersion, exportTimestamp)
	if err != nil {
		return fmt.Errorf("could not build metadata file: %w", err)
	}

	// release the snapshot when the export part is finished
	if err := snapshotTx.Commit(ctx); err != nil {
		return fmt.Errorf("could not end export transaction: %w", err)
	}

	slog.Info("finished export, sending archive", "time", time.Since(start))

	// the table files are already gzipped, so the archive itself stays uncompressed
	// response is written inside the export on the provided out path
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

// builds the metadata file from the aggregated information
func buildMetadataFile(jobDirectoryPath string, exportOptions dtos.DataTransferExportOptions, databaseSchemaVersion string, exportTimestamp time.Time) error {
	metadataFD, err := os.Create(filepath.Join(jobDirectoryPath, metadataFileName))
	if err != nil {
		return fmt.Errorf("could not create metadata file: %w", err)
	}
	defer metadataFD.Close()

	exportMetadata := dtos.DataTransferMetadata{
		ExportVersion:         dataTransferVersion,
		DatabaseSchemaVersion: databaseSchemaVersion,
		ExportTimestamp:       exportTimestamp,
		EntityType:            exportOptions.EntityType,
		EntityID:              exportOptions.EntityID,
	}

	err = json.NewEncoder(metadataFD).Encode(exportMetadata)
	if err != nil {
		return fmt.Errorf("could not write metadata file: %w", err)
	}
	return nil
}

// receives a table, queries its scoped rows and writes the output to the respective file
func (service *DataTransferService) databaseQueryWorker(ctx context.Context, baseFolder string, snapshotID string, scope exportScope, jobs chan string) error {
	workerTx, err := service.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return fmt.Errorf("could not start worker tx: %w", err)
	}
	defer workerTx.Rollback(ctx) // nolint

	// own transaction but uses the same underlying snapshot of the database
	_, err = workerTx.Exec(ctx, fmt.Sprintf("SET TRANSACTION SNAPSHOT '%s';", snapshotID))
	if err != nil {
		return fmt.Errorf("could not set worker transaction snapshot: %w", err)
	}

	for tableID := range jobs {
		// run in a function so defers work
		if err := exportTable(ctx, workerTx, baseFolder, tableID, scope); err != nil {
			return err
		}
	}

	slog.Info("db worker finished")
	return nil
}

func exportTable(ctx context.Context, tx pgx.Tx, baseFolder string, tableID string, scope exportScope) error {
	sql, args, err := sqlFromTableProperties(tableID, tablesToSync[tableID], scope)
	if err != nil {
		return fmt.Errorf("could not build export query: %w", err)
	}

	slog.Info("starting new job", "sql", sql)
	rows, err := tx.Query(ctx, sql, args...)
	if err != nil {
		return fmt.Errorf("could not query table: %w\n\nSQL: %s", err, sql)
	}
	defer rows.Close()

	// create the table file regardless of output size
	tableFd, err := os.Create(filepath.Join(baseFolder, tableID+tableFileExtension))
	if err != nil {
		return fmt.Errorf("could not create file for table data, table (%s): %w", tableID, err)
	}
	defer tableFd.Close()

	gzipWriter := gzip.NewWriter(tableFd)
	defer gzipWriter.Close()

	for rows.Next() {
		// scan each row into a buffer and stream that into the file through the gzip compression
		var row []byte
		if err := rows.Scan(&row); err != nil {
			return fmt.Errorf("could not scan row of %s: %w", tableID, err)
		}

		// row is already json from row_to_json, we can just write that with a newline
		if _, err := gzipWriter.Write(append(row, '\n')); err != nil {
			return fmt.Errorf("could not write row of %s: %w", tableID, err)
		}
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("error when reading rows: %w", err)
	}
	slog.Info("successfully queried table data", "table", tableID, "rows count", rows.CommandTag().RowsAffected())
	rows.Close()

	// finish up the gzip file
	if err := gzipWriter.Close(); err != nil {
		return fmt.Errorf("could not finish compressed file of %s: %w", tableID, err)
	}
	if err := tableFd.Close(); err != nil {
		return fmt.Errorf("could not close file of %s: %w", tableID, err)
	}
	return nil
}

// build the scoped row_to_json query for an exported table, args are ordered like the placeholders
func sqlFromTableProperties(tableID string, properties tableProperties, scope exportScope) (string, []any, error) {
	// no filter would leak data of the whole table
	if len(properties.filters) == 0 {
		return "", nil, fmt.Errorf("table %s has no scope filter", tableID)
	}

	// for each filter build the SQL condition and the respective argument (sanitized)
	conditions := make([]string, 0, len(properties.filters))
	args := make([]any, 0, len(properties.filters))
	for _, filter := range properties.filters {
		ids, ok := scope[filter.ids]
		if !ok {
			return "", nil, fmt.Errorf("id set %s of table %s was not resolved", filter.ids, tableID)
		}
		args = append(args, ids)
		conditions = append(conditions, fmt.Sprintf("t.%s = ANY($%d::%s)", pgx.Identifier{filter.column}.Sanitize(), len(args), filter.arrayType))
	}
	return fmt.Sprintf("SELECT row_to_json(t) FROM %s t WHERE %s", pgx.Identifier{tableID}.Sanitize(), strings.Join(conditions, " OR ")), args, nil
}

// recursively collect all id sets in order: first entities, then direct referenced tables and lastly indirect referenced tables
func resolveScope(ctx context.Context, tx pgx.Tx, options dtos.DataTransferExportOptions) (exportScope, error) {
	entityID := options.EntityID.String()
	// project and asset exports leave the entity sets above them empty
	scope := exportScope{"orgIDs": nil, "projectIDs": nil, "assetIDs": nil}
	var err error

	// resolve all set of entity ids based on export scope
	switch options.EntityType {
	case dtos.DataTransferEntityOrg:
		// for an org recursively find all projects in this org
		scope["orgIDs"] = []string{entityID}
		if scope["projectIDs"], err = collectIDs(ctx, tx, resolveOrgProjectIDsSQL, entityID); err != nil {
			return scope, fmt.Errorf("could not resolve project ids: %w", err)
		}

		// then resolve all affected assets
		if scope["assetIDs"], err = collectIDs(ctx, tx, resolveAssetIDsSQL, scope["projectIDs"]); err != nil {
			return scope, fmt.Errorf("could not resolve asset ids: %w", err)
		}
	case dtos.DataTransferEntityProject:
		// for a project only find sub projects of this project downwards
		if scope["projectIDs"], err = collectIDs(ctx, tx, resolveSubProjectIDsSQL, entityID); err != nil {
			return scope, fmt.Errorf("could not resolve project ids: %w", err)
		}

		// then resolve all affected assets
		if scope["assetIDs"], err = collectIDs(ctx, tx, resolveAssetIDsSQL, scope["projectIDs"]); err != nil {
			return scope, fmt.Errorf("could not resolve asset ids: %w", err)
		}
	case dtos.DataTransferEntityAsset:
		// for assets just set the assetID
		scope["assetIDs"] = []string{entityID}
	default:
		return scope, fmt.Errorf("unknown export entity type: %s", options.EntityType)
	}

	// now with the entities resolved we can first get all the entity related ids
	if scope["artifactIDs"], err = collectIDs(ctx, tx, resolveArtifactIDsSQL, scope["assetIDs"]); err != nil {
		return scope, fmt.Errorf("could not resolve artifact ids: %w", err)
	}

	if scope["externalUserIDs"], err = collectIDs(ctx, tx, resolveExternalUserIDsSQL, scope["orgIDs"]); err != nil {
		return scope, fmt.Errorf("could not resolve external user ids: %w", err)
	}

	if scope["dependencyVulnIDs"], err = collectIDs(ctx, tx, resolveDependencyVulnIDsSQL, scope["assetIDs"]); err != nil {
		return scope, fmt.Errorf("could not resolve dependency vuln ids: %w", err)
	}

	if scope["firstPartyVulnIDs"], err = collectIDs(ctx, tx, resolveFirstPartyVulnIDsSQL, scope["assetIDs"]); err != nil {
		return scope, fmt.Errorf("could not resolve first party vuln ids: %w", err)
	}

	if scope["licenseRiskIDs"], err = collectIDs(ctx, tx, resolveLicenseRiskIDsSQL, scope["assetIDs"]); err != nil {
		return scope, fmt.Errorf("could not resolve license risk ids: %w", err)
	}

	if scope["compliancePostureIDs"], err = collectIDs(ctx, tx, resolveCompliancePostureIDsSQL, scope["orgIDs"]); err != nil {
		return scope, fmt.Errorf("could not resolve compliance posture ids: %w", err)
	}

	if scope["securityAdvisoryIDs"], err = collectIDs(ctx, tx, resolveSecurityAdvisoryIDsSQL, scope["assetIDs"]); err != nil {
		return scope, fmt.Errorf("could not resolve security advisory ids: %w", err)
	}

	if scope["assetSignatures"], err = collectIDs(ctx, tx, resolveAssetSignaturesSQL, scope["assetIDs"]); err != nil {
		return scope, fmt.Errorf("could not resolve asset signatures: %w", err)
	}

	if scope["sbomMerkleNodeHashes"], err = collectIDs(ctx, tx, resolveSBOMMerkleNodeHashesSQL, scope["assetIDs"]); err != nil {
		return scope, fmt.Errorf("could not resolve sbom merkle node hashes: %w", err)
	}

	// and after that we can get all the ids one level deeper (e.g. resolving pivot tables)
	if scope["componentIDs"], err = collectIDs(ctx, tx, resolveComponentIDsSQL, scope["licenseRiskIDs"]); err != nil {
		return scope, fmt.Errorf("could not resolve component ids: %w", err)
	}

	if scope["componentProjectKeys"], err = collectIDs(ctx, tx, resolveComponentProjectKeysSQL, scope["componentIDs"]); err != nil {
		return scope, fmt.Errorf("could not resolve component project keys: %w", err)
	}

	if scope["frameworkControlIDs"], err = collectIDs(ctx, tx, resolveFrameworkControlIDsSQL, scope["compliancePostureIDs"]); err != nil {
		return scope, fmt.Errorf("could not resolve framework control ids: %w", err)
	}

	return scope, nil
}

// helper function to query one id column
func collectIDs(ctx context.Context, tx pgx.Tx, sql string, args ...any) ([]string, error) {
	rows, _ := tx.Query(ctx, sql, args...)
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

//-------------------------------------------------------------------
//						Import Logic
//-------------------------------------------------------------------

func (service *DataTransferService) ImportFile(ctx context.Context, importFile io.Reader, options dtos.DataTransferImportOptions) error {
	slog.Info("start importing data...")
	start := time.Now()

	// unpack the files locally into a temp folder so we are able to handle them in the appropriate order
	importDirectoryPath, err := os.MkdirTemp("", "devguard-import-*")
	if err != nil {
		return fmt.Errorf("could not create import directory: %w", err)
	}
	// clean up after the import finishes
	defer func() {
		if err := os.RemoveAll(importDirectoryPath); err != nil {
			slog.Error("could not clean up import directory", "path", importDirectoryPath, "err", err)
		}
	}()

	// write the imported file to the temp directory, it now lives there
	if err := extractImportArchive(importFile, importDirectoryPath); err != nil {
		return fmt.Errorf("could not extract import archive: %w", err)
	}

	// transaction ensures atomicity for the import but also disallows concurrent writes
	importTx, err := service.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("could not start import transaction: %w", err)
	}
	defer importTx.Rollback(ctx) // nolint
	//no-op after a successful commit

	if _, err := importTx.Exec(ctx, "SET LOCAL search_path TO public"); err != nil {
		return fmt.Errorf("could not set search path for import: %w", err)
	}

	// check if the transfer version (program logic) and the schema migrations (database version) match the one of the export
	importMetadata, err := checkImportMetadata(ctx, importTx, importDirectoryPath)
	if err != nil {
		return err // errors are detailed in the called function
	}

	// sort the tables to ensure no FK violations
	tableNames := slices.SortedFunc(maps.Keys(tablesToSync), func(table1, table2 string) int {
		return cmp.Compare(tablesToSync[table1].importOrder, tablesToSync[table2].importOrder)
	})

	// every table is copied into this staging table first, so postgres can convert the json rows itself
	if _, err := importTx.Exec(ctx, "CREATE TEMP TABLE import_staging (data jsonb) ON COMMIT DROP"); err != nil {
		return fmt.Errorf("could not create staging table: %w", err)
	}

	for _, tableName := range tableNames {
		if err := importTable(ctx, importTx, importDirectoryPath, tableName, importMetadata, options); err != nil {
			return err
		}
	}

	// now we also need to setup RBAC rules so the user can access the imported contents
	// this cannot be done inside one shared transaction
	if err := service.bootstrapImportedRBAC(ctx, importTx, importMetadata, options); err != nil {
		return fmt.Errorf("could not set up permissions for imported data: %w", err)
	}

	if err := importTx.Commit(ctx); err != nil {
		// a failed commit leaves the RBAC rules hanging -> no-op for non existing users
		return fmt.Errorf("could not commit import transaction: %w", err)
	}

	slog.Info("successfully finished import", "time", time.Since(start))
	return nil
}

// the importer gets the highest role on the imported entity, the rules of the import target stay untouched
func (service *DataTransferService) bootstrapImportedRBAC(ctx context.Context, tx pgx.Tx, importMetadata dtos.DataTransferMetadata, options dtos.DataTransferImportOptions) error {
	owner := shared.NewSession(options.OwnerID, shared.SessionActorUser, nil, false)

	switch importMetadata.EntityType {
	case dtos.DataTransferEntityOrg:
		rbac := service.rbacProvider.GetDomainRBAC(importMetadata.EntityID.String())

		err := shared.BootstrapOrg(ctx, rbac, options.OwnerID, shared.RoleOwner)
		if err != nil {
			return fmt.Errorf("could not bootstrap organization: %w", err)
		}

		projects, assets, err := loadImportedProjectsAndAssets(ctx, tx, importedOrgProjectsSQL, importMetadata.EntityID)
		if err != nil {
			return err
		}
		return service.bootstrapProjectsAndAssets(ctx, rbac, projects, assets)

	case dtos.DataTransferEntityProject:
		rbac := service.rbacProvider.GetDomainRBAC(options.TargetOrgID.String())

		projects, assets, err := loadImportedProjectsAndAssets(ctx, tx, importedSubProjectsSQL, importMetadata.EntityID)
		if err != nil {
			return err
		}
		if err := service.bootstrapProjectsAndAssets(ctx, rbac, projects, assets); err != nil {
			return err
		}

		// sub projects and assets inherit the admin role of the imported project
		if err := rbac.GrantRoleInProject(ctx, owner, shared.RoleAdmin, importMetadata.EntityID.String()); err != nil {
			return fmt.Errorf("could not grant admin role on imported project: %w", err)
		}
		return nil

	case dtos.DataTransferEntityAsset:
		rbac := service.rbacProvider.GetDomainRBAC(options.TargetOrgID.String())
		rows, _ := tx.Query(ctx, importedAssetSQL, importMetadata.EntityID)
		asset, err := pgx.CollectExactlyOneRow(rows, scanImportedAsset)
		if err != nil {
			return fmt.Errorf("could not load imported asset: %w", err)
		}
		if err := service.bootstrapProjectsAndAssets(ctx, rbac, nil, []models.Asset{asset}); err != nil {
			return err
		}
		if err := rbac.GrantRoleInAsset(ctx, owner, shared.RoleAdmin, asset.ID.String()); err != nil {
			return fmt.Errorf("could not grant admin role on imported asset: %w", err)
		}
		return nil

	default:
		return fmt.Errorf("unknown imported entity type: %s", importMetadata.EntityType)
	}
}

// the imported rows are not committed yet, so they are loaded through the import transaction and not the repositories
const importedOrgProjectsSQL = `SELECT id, parent_id FROM projects WHERE organization_id = $1`

const importedSubProjectsSQL = `WITH RECURSIVE sub_projects AS (
	SELECT id, parent_id FROM projects WHERE id = $1
	UNION
	SELECT p.id, p.parent_id FROM projects p JOIN sub_projects sp ON p.parent_id = sp.id
) SELECT id, parent_id FROM sub_projects`

const importedProjectAssetsSQL = `SELECT id, project_id FROM assets WHERE project_id = ANY($1::uuid[])`
const importedAssetSQL = `SELECT id, project_id FROM assets WHERE id = $1`

// only scans the fields the rbac bootstrap needs
func scanImportedProject(row pgx.CollectableRow) (models.Project, error) {
	var project models.Project
	err := row.Scan(&project.ID, &project.ParentID)
	return project, err
}

func scanImportedAsset(row pgx.CollectableRow) (models.Asset, error) {
	var asset models.Asset
	err := row.Scan(&asset.ID, &asset.ProjectID)
	return asset, err
}

// recalculates what projects and assets have been inserted by the import entity
func loadImportedProjectsAndAssets(ctx context.Context, tx pgx.Tx, projectsSQL string, entityID uuid.UUID) ([]models.Project, []models.Asset, error) {
	// first select all the affected projects
	rows, _ := tx.Query(ctx, projectsSQL, entityID)
	projects, err := pgx.CollectRows(rows, scanImportedProject)
	if err != nil {
		return nil, nil, fmt.Errorf("could not load imported projects: %w", err)
	}

	importedProjectIDs := utils.Map(projects, func(project models.Project) uuid.UUID { return project.ID })

	// then all the assets included in those projects
	rows, _ = tx.Query(ctx, importedProjectAssetsSQL, importedProjectIDs)
	assets, err := pgx.CollectRows(rows, scanImportedAsset)
	if err != nil {
		return nil, nil, fmt.Errorf("could not load imported assets: %w", err)
	}
	return projects, assets, nil
}

func (service *DataTransferService) bootstrapProjectsAndAssets(ctx context.Context, rbac shared.AccessControl, projects []models.Project, assets []models.Asset) error {
	for i := range projects {
		if err := service.projectService.BootstrapProject(ctx, rbac, &projects[i]); err != nil {
			return fmt.Errorf("could not bootstrap project %s: %w", projects[i].ID, err)
		}
	}
	for i := range assets {
		if err := service.assetService.BootstrapAsset(ctx, rbac, &assets[i]); err != nil {
			return fmt.Errorf("could not bootstrap asset %s: %w", assets[i].ID, err)
		}
	}
	slog.Info("set up permissions for imported data", "projects", len(projects), "assets", len(assets))
	return nil
}

// the top level rows of a project or asset archive get attached to the entity they are imported into
func attachToImportTarget(ctx context.Context, tx pgx.Tx, tableName string, importMetadata dtos.DataTransferMetadata, options dtos.DataTransferImportOptions) error {
	switch {
	// projects get attached to an org
	case importMetadata.EntityType == dtos.DataTransferEntityProject && tableName == "projects":
		if _, err := tx.Exec(ctx, `UPDATE import_staging SET data = jsonb_set(data, '{organization_id}', to_jsonb($1::uuid))`, options.TargetOrgID); err != nil {
			return fmt.Errorf("could not attach imported projects to organization: %w", err)
		}
		// sub projects keep their parent, a missing target project makes the imported project a root project
		if _, err := tx.Exec(ctx, `UPDATE import_staging SET data = jsonb_set(data, '{parent_id}', COALESCE(to_jsonb($1::uuid), 'null'::jsonb)) WHERE data->>'id' = $2`, options.TargetProjectID, importMetadata.EntityID.String()); err != nil {
			return fmt.Errorf("could not attach imported project to parent project: %w", err)
		}
	case importMetadata.EntityType == dtos.DataTransferEntityAsset && tableName == "assets":
		// assets get attached to a project
		if _, err := tx.Exec(ctx, `UPDATE import_staging SET data = jsonb_set(data, '{project_id}', to_jsonb($1::uuid))`, options.TargetProjectID); err != nil {
			return fmt.Errorf("could not attach imported asset to project: %w", err)
		}
	}
	return nil
}

// every export contains a file for each table, so a missing file means a broken archive
func importTable(ctx context.Context, tx pgx.Tx, importDirectoryPath string, tableName string, importMetadata dtos.DataTransferMetadata, options dtos.DataTransferImportOptions) error {
	file, err := os.Open(filepath.Join(importDirectoryPath, tableName+tableFileExtension))
	if err != nil {
		return fmt.Errorf("could not open file of %s: %w", tableName, err)
	}
	defer file.Close()

	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		return fmt.Errorf("could not decompress file of %s: %w", tableName, err)
	}
	defer gzipReader.Close()

	// clear the staging table first
	if _, err := tx.Exec(ctx, "TRUNCATE import_staging"); err != nil {
		return fmt.Errorf("could not reset staging table: %w", err)
	}

	// stream the new data into the staging table
	// use CSV with control characters as quote and delimiter, so COPY leaves the json backslash escapes untouched
	copyTag, err := tx.Conn().PgConn().CopyFrom(ctx, gzipReader, `COPY import_staging (data) FROM STDIN WITH (FORMAT csv, QUOTE E'\x01', DELIMITER E'\x02')`)
	if err != nil {
		return fmt.Errorf("could not copy rows of %s: %w", tableName, err)
	}

	// attach the top level table (projects or assets) to the passed parent entity
	if err := attachToImportTarget(ctx, tx, tableName, importMetadata, options); err != nil {
		return err
	}

	table := pgx.Identifier{tableName}.Sanitize()
	// we can just insert from the staging table (json_populate_records ensures column matching)
	insertSQL := fmt.Sprintf("INSERT INTO %s SELECT r.* FROM import_staging, jsonb_populate_record(NULL::%s, data) r", table, table)

	// determine conflict handling: content hashes mean no conflict handling needed since its the same entry
	if tablesToSync[tableName].conflictsAllowed {
		insertSQL += " ON CONFLICT DO NOTHING"
	}
	insertTag, err := tx.Exec(ctx, insertSQL)
	if err != nil {
		// mostly a slug or name which is already taken on this instance, the detail names the conflicting value
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" { // unique_violation
			return fmt.Errorf("could not insert rows of %s, %s rename or remove the existing entry and retry the import: %w", tableName, pgErr.Detail, err)
		}
		return fmt.Errorf("could not insert rows of %s: %w", tableName, err)
	}

	slog.Info("imported table", "table", tableName, "inserted rows", insertTag.RowsAffected(), "skipped existing rows", copyTag.RowsAffected()-insertTag.RowsAffected())
	return nil
}

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
func checkImportMetadata(ctx context.Context, tx pgx.Tx, importDirectoryPath string) (dtos.DataTransferMetadata, error) {
	metadataFile, err := os.Open(filepath.Join(importDirectoryPath, metadataFileName))
	if err != nil {
		return dtos.DataTransferMetadata{}, fmt.Errorf("could not open metadata file: %w", err)
	}
	defer metadataFile.Close()

	var importMetadata dtos.DataTransferMetadata
	if err := json.NewDecoder(metadataFile).Decode(&importMetadata); err != nil {
		return dtos.DataTransferMetadata{}, fmt.Errorf("could not read metadata file: %w", err)
	}

	if importMetadata.ExportVersion != dataTransferVersion {
		return dtos.DataTransferMetadata{}, fmt.Errorf("export version does not match DevGuard version (export: %d, current: %d)", importMetadata.ExportVersion, dataTransferVersion)
	}

	databaseSchemaVersion, err := currentSchemaVersion(ctx, tx)
	if err != nil {
		return dtos.DataTransferMetadata{}, err
	}

	if importMetadata.DatabaseSchemaVersion != databaseSchemaVersion {
		return dtos.DataTransferMetadata{}, fmt.Errorf("export schema version %s does not match database schema version %s", importMetadata.DatabaseSchemaVersion, databaseSchemaVersion)
	}
	return importMetadata, nil
}

// export and import both require a clean migration state
func currentSchemaVersion(ctx context.Context, tx pgx.Tx) (string, error) {
	var version string
	var dirty bool
	if err := tx.QueryRow(ctx, "SELECT version, dirty FROM schema_migrations LIMIT 1;").Scan(&version, &dirty); err != nil {
		return "", fmt.Errorf("could not determine schema migration state: %w", err)
	}

	if dirty {
		return "", fmt.Errorf("dirty database schema detected")
	}
	return version, nil
}
