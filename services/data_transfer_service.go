package services

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/utils"
	"golang.org/x/sync/errgroup"
)

type tableProperties struct {
	tableID            string
	referencedTableIDs []string
	model              utils.Tabler
	customSQL          *string
}

// SQL foreign key column constants
const (
	orgTableID      = "organizations"
	projectsTableID = "projects"
	assetsTableID   = "assets"

	orgFKColumn     = "org_id"
	projectFKColumn = "project_id"
	assetFKColumn   = "asset_id"
)

// all tables with a simple syntax
var tablesToSync []tableProperties = []tableProperties{
	// org level
	{tableID: orgTableID, referencedTableIDs: []string{}},
	{tableID: projectsTableID, referencedTableIDs: []string{orgTableID, projectsTableID}},
	{tableID: "compliance_postures", referencedTableIDs: []string{orgTableID, projectsTableID, assetsTableID}},
	{tableID: "invitations", referencedTableIDs: []string{orgTableID}},
	// external user org pivot table
	{tableID: "access_tokens", referencedTableIDs: []string{orgTableID, projectsTableID, assetsTableID}},
	{tableID: "trusted_entities", referencedTableIDs: []string{orgTableID, projectsTableID}},
	{tableID: "gitlab_integrations", referencedTableIDs: []string{orgTableID}},
	{tableID: "github_app_installations", referencedTableIDs: []string{orgTableID}},
	{tableID: "jira_integrations", referencedTableIDs: []string{orgTableID}},
	{tableID: "webhook_integrations", referencedTableIDs: []string{orgTableID, projectsTableID}},
	{tableID: "webhook_integrations", referencedTableIDs: []string{orgTableID, projectsTableID}},
	{tableID: "policies", referencedTableIDs: []string{orgTableID}},

	// project level
	//project enabled policies (pivot table)
	{tableID: "releases", referencedTableIDs: []string{projectsTableID}},
	{tableID: assetsTableID, referencedTableIDs: []string{projectsTableID}},

	// asset level
	{tableID: "external_references", referencedTableIDs: []string{assetsTableID}},
	{tableID: "vex_rules", referencedTableIDs: []string{assetsTableID}},
	{tableID: "asset_versions", referencedTableIDs: []string{assetsTableID}},

	// asset version level
	{tableID: "license_risks", referencedTableIDs: []string{assetsTableID}},
	{tableID: "first_party_vulnerabilities", referencedTableIDs: []string{assetsTableID}},
	{tableID: "dependency_vulnerabilities", referencedTableIDs: []string{assetsTableID}},
	{tableID: "in_toto_links", referencedTableIDs: []string{assetsTableID}},
	{tableID: "supply_chain", referencedTableIDs: []string{assetsTableID}},
	{tableID: "advisories", referencedTableIDs: []string{assetsTableID}},
	{tableID: "asset_risk_history", referencedTableIDs: []string{assetsTableID}},
	{tableID: "artifacts", referencedTableIDs: []string{assetsTableID}},

	// artifact level
	{tableID: "artifact_risk_history", referencedTableIDs: []string{assetsTableID}},
	{tableID: "release_items", referencedTableIDs: []string{assetsTableID}},
	{tableID: "attestations", referencedTableIDs: []string{assetsTableID}},
	{tableID: "sboms", referencedTableIDs: []string{assetsTableID}},
	// artifact dep vulns pivot table
	// artifact license risks pivot table

	// reminder load SBOM merkle data
}

const transferFileLocation = "/transfer-files/"

type DataTransferService struct {
	pool *pgxpool.Pool
	// Broker?
}

func NewDataTransferService(pool *pgxpool.Pool) *DataTransferService {
	return &DataTransferService{
		pool: pool,
	}
}

func (service *DataTransferService) StartExport(ctx context.Context, options dtos.DataTransferExportOptions) error {
	slog.Info("starting data transfer export process...")
	start := time.Now()

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

	group, errCtx := errgroup.WithContext(ctx)
	group.SetLimit(6) // allow max 6 concurrent DB reads

	return nil
}

type output struct {
	tableID string
	data    [][]any
	count   int
}

type queryJob struct {
	sql string
}

func (service *DataTransferService) DatabaseQueryWorker(ctx context.Context, snapshotID string, jobs <-chan queryJob, output chan<- any) error {
	workerTx, err := service.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return fmt.Errorf("could not start worker tx: %w", err)
	}

	_, err = workerTx.Exec(ctx, fmt.Sprintf("SET TRANSACTION SNAPSHOT '%s';", snapshotID))
	if err != nil {
		return fmt.Errorf("could not set worker transaction snapshot: %w", err)
	}

	for job := range jobs {
		slog.Info("starting new job", "sql", job.sql)
		rows, err := workerTx.Query(ctx, job.sql)
		if err != nil {
			return fmt.Errorf("could not query table: %w\n\nSQL: %s", err, job.sql)
		}
		defer rows.Close()

		results := make([][]any, rows.CommandTag().RowsAffected())
		i := 0
		for rows.Next() {
			if err := rows.Scan(results[i]); err != nil {
				return fmt.Errorf("could not scan values: %w", err)
			}
		}

		if err := rows.Err(); err != nil {
			return fmt.Errorf("error when reading rows: %w", err)
		}
		rows.Close()
		slog.Info("successfully queried table data", "rows count", rows.CommandTag().RowsAffected(), "sql", job.sql)
	}

	slog.Info("worker finished")
	return nil
}

// build the joined table for a exported table
func sqlFromTableProperties(properties tableProperties) string {
	sql := fmt.Sprintf("SELECT * FROM %s", properties.tableID)
	if len(properties.referencedTableIDs) > 0 {
		for _, tableID := range properties.referencedTableIDs {
			sql += fmt.Sprintf(" JOIN %s ON %s = %s.id", tableID, tableIDToFKColumnName(tableID), tableID)
		}
	}
	return sql
}

// apply the necessary WHERE filters according to the scopes provided in the export options
func scopeSQLQuery(baseQuery string, queryAppendix string, options dtos.DataTransferExportOptions) string {
	scope := options.AffectedEntities
	whereClauses := []string{}

	if len(scope.Orgs) > 0 {
		whereClauses = append(whereClauses, fmt.Sprintf("%s = ANY(%s)", orgFKColumn, strings.Join(scope.Orgs, ", ")))
	}
	if len(scope.Projects) > 0 {
		whereClauses = append(whereClauses, fmt.Sprintf("%s = ANY(%s)", projectFKColumn, strings.Join(scope.Projects, ", ")))
	}
	if len(scope.Assets) > 0 {
		whereClauses = append(whereClauses, fmt.Sprintf("%s = ANY(%s)", assetFKColumn, strings.Join(scope.Assets, ", ")))
	}

	if len(whereClauses) == 0 { // unscoped, this can be desired by the caller of this function
		return ""
	}

	whereClause := strings.Join(whereClauses, " AND ")

	return fmt.Sprintf("%s WHERE %s %s;", baseQuery, whereClause, queryAppendix)
}

func tableIDToFKColumnName(tableID string) string {
	switch tableID {
	case orgTableID:
		return orgFKColumn
	case projectsTableID:
		return projectFKColumn
	case assetsTableID:
		return assetFKColumn
	default:
		return tableID
	}
}
