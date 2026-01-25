package vulndb

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/csv"
	"encoding/pem"
	"fmt"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/l3montree-dev/devguard/monitoring"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/pkg/errors"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"

	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/file"
	"oras.land/oras-go/v2/registry/remote"
)

type importService struct {
	cveRepository                shared.CveRepository
	cweRepository                shared.CweRepository
	exploitRepository            shared.ExploitRepository
	affectedComponentsRepository shared.AffectedComponentRepository
	configService                shared.ConfigService
	pool                         *pgxpool.Pool
}

func NewImportService(cvesRepository shared.CveRepository, cweRepository shared.CweRepository, exploitRepository shared.ExploitRepository, affectedComponentsRepository shared.AffectedComponentRepository, configService shared.ConfigService, pool *pgxpool.Pool) *importService {
	return &importService{
		cveRepository:                cvesRepository,
		cweRepository:                cweRepository,
		exploitRepository:            exploitRepository,
		affectedComponentsRepository: affectedComponentsRepository,
		configService:                configService,
		pool:                         pool,
	}
}

// maps every table associated with the vulndb to their respective primary key(s) used in the diff queries
var primaryKeysFromTables = map[string][]string{"cves": {"cve"}, "cwes": {"cwe"}, "affected_components": {"id"}, "cve_affected_component": {"affected_component_id", "cvecve"}, "exploits": {"id"}, "malicious_packages": {"id"}, "malicious_affected_components": {"id"}, "cve_relationships": {"target_cve", "source_cve", "relationship_type"}}

// maps every table associated with the vulndb to their attributes we want to watch for the diff_update queries
var relevantAttributesFromTables = map[string][]string{"cves": {"date_last_modified"}, "cwes": {"description"}, "affected_components": {}, "cve_affected_component": {}, "exploits": {"*"}, "malicious_packages": {"modified"}, "malicious_affected_components": {}, "cve_relationships": {}}

func (service importService) Import(tx shared.DB, tag string) error {
	begin := time.Now()

	reg := "ghcr.io/l3montree-dev/devguard/vulndb/v1"
	// Connect to a remote repository
	repo, err := remote.NewRepository(reg)
	if err != nil {
		return fmt.Errorf("could not connect to remote repository: %w", err)
	}
	outpath, err := os.MkdirTemp("", "vulndb")
	if err != nil {
		return fmt.Errorf("could not create temp directory: %w", err)
	}

	_, err = downloadAndSaveZipToTemp(repo, tag, outpath)
	if err != nil {
		return err
	}

	//copy csv files to database
	err = service.copyCSVToDB(outpath, nil)
	if err != nil {
		return fmt.Errorf("could not copy csv to db: %w", err)
	}

	slog.Info("importing vulndb completed", "duration", time.Since(begin))

	os.RemoveAll(outpath) //nolint
	return nil
}

func (service importService) CreateTablesWithSuffix(suffix string) error {
	ctx := context.Background()
	// create the tables with the suffix
	return createTablesWithSuffix(ctx, service.pool, suffix)
}

func createTablesWithSuffix(ctx context.Context, pool *pgxpool.Pool, suffix string) error {
	// list of tables to create
	for _, table := range vulndbTables {
		_, err := pool.Exec(ctx, fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s%s (LIKE %s INCLUDING ALL);", table, suffix, table))
		if err != nil {
			return fmt.Errorf("could not create table %s%s: %w", table, suffix, err)
		}
		slog.Info("created table with suffix", "table", table+suffix)
	}
	return nil
}

// the extra table name suffix is just used for exporting incremental diffs
// it allows storing the last full vulndb state in tables with the suffix and then comparing them to the current tables
// if extraTableNameSuffix is not nil, the import will always import from the latest snapshot
func (service importService) ImportFromDiff(extraTableNameSuffix *string) error {
	ctx := context.Background()

	reg := "ghcr.io/l3montree-dev/devguard/vulndb/v1"
	// Connect to a remote repository
	repo, err := remote.NewRepository(reg)
	if err != nil {
		return fmt.Errorf("could not connect to remote repository: %w", err)
	}

	var tags []string
	if extraTableNameSuffix != nil {
		slog.Info("extra table name suffix detected, loading full vulndb state from latest snapshot")
		tags, err = service.GetAllIncrementalTagsSinceSnapshot(ctx, repo)
	} else {
		tags, err = service.GetIncrementalTags(ctx, repo)
	}

	if err != nil {
		return err
	}

	begin := time.Now()
	slog.Info("start updating vulndb", "steps", len(tags))
	for i, tag := range tags {
		slog.Info("updating vulndb", "step", tag, "number", i+1, "of", len(tags))

		outpath, err := os.MkdirTemp("", "vulndb")
		if err != nil {
			return fmt.Errorf("could not create temp directory: %w", err)
		}

		// if the directory already exists we skip the download and verification
		_, err = downloadAndSaveZipToTemp(repo, tag, outpath)
		if err != nil {
			return err
		}
		defer os.RemoveAll(outpath) //nolint

		// if it is a snapshot tag we load the full state
		if strings.Contains(tag, "snapshot") {
			if i != 0 {
				slog.Warn("snapshot tag in between incremental tags, skipping", "tag", tag) //there is no skipping?
			}
			slog.Info("no version detected start loading latest vulndb state")
			err = service.copyCSVToDB(outpath, extraTableNameSuffix)
			if err != nil {
				return err
			}

			slog.Info("finished loading latest snapshot state")
			if extraTableNameSuffix == nil {
				err = service.configService.SetJSONConfig("vulndb.lastIncrementalImport", tag)
				if err != nil {
					slog.Error("could not save last incremental import version", "err", err)
				}
			}
			slog.Info("finished updating tag", "tag", tag)
			continue
		}

		tx, err := service.pool.Begin(ctx)
		if err != nil {
			return err
		}
		defer tx.Rollback(ctx) // nolint:errcheck // rollback is safe even after commit

		dirPath := fmt.Sprintf("%s/diffs-tmp", outpath)

		err = processDiffCSVs(ctx, dirPath, tx, extraTableNameSuffix)
		if err != nil {
			slog.Error("error when trying to update from diff files", "tag", tag, "err", err)
			return err
		}
		err = tx.Commit(ctx)
		if err != nil {
			return err
		}
		if extraTableNameSuffix == nil {
			err = service.configService.SetJSONConfig("vulndb.lastIncrementalImport", tag)
			if err != nil {
				slog.Error("could not save last incremental import version", "err", err)
			}
		}
		slog.Info("finished updating tag", "tag", tag)
	}
	slog.Info("finished updating tags", "duration", time.Since(begin))

	return nil
}

func processDiffCSVs(ctx context.Context, dirPath string, tx pgx.Tx, tableSuffix *string) error {
	files, err := os.ReadDir(dirPath)
	if err != nil {
		return err
	}

	// filter and sort files beforehand because we need to update cve_affected_components after cves and affected component tables have been updated
	sort.Slice(files, func(i, j int) bool {
		if strings.HasPrefix(files[i].Name(), "cve_affected_component") {
			return false
		}
		if strings.HasPrefix(files[j].Name(), "cve_affected_component") {
			return true
		}
		// Move exploits to the end
		if strings.HasPrefix(files[i].Name(), "exploits") {
			return false
		}
		if strings.HasPrefix(files[j].Name(), "exploits") {
			return true
		}
		return strings.Compare(files[i].Name(), files[j].Name()) < 0
	})

	for _, file := range files {
		name := strings.TrimRight(file.Name(), ".csv")
		fields := strings.Split(name, "_")
		// extract table information from the name of the csv file

		mode := fields[len(fields)-1] // insert, delete, update
		table := strings.Replace(strings.Join(fields[:len(fields)-1], "_"), "_diff", "", 1)

		// append the suffix to the tablename
		if tableSuffix != nil {
			table = fmt.Sprintf("%s%s", table, *tableSuffix)
		}

		// could be run concurrent but probably won't yield a lot of performance improvement
		switch mode {
		case "insert":
			err = processInsertDiff(ctx, tx, dirPath+"/"+name+".csv", table)
			if err != nil {
				slog.Error("could not process insert diff, continuing...", "table", table, "err", err)
				tx.Rollback(ctx) //nolint
				return err
			}
		case "delete":
			err = processDeleteDiff(ctx, tx, dirPath+"/"+name+".csv", table, tableSuffix)
			if err != nil {
				slog.Error("could not process delete diff, continuing...", "table", table, "err", err)
				tx.Rollback(ctx) //nolint
				return err
			}
		case "update":
			err = processUpdateDiff(ctx, tx, dirPath+"/"+name+".csv", table, tableSuffix)
			if err != nil {
				slog.Error("could not process update diff, continuing...", "table", table, "err", err)
				tx.Rollback(ctx) //nolint
				return err
			}
		default:
			slog.Warn("invalid mode for diff file", "mode", mode)
		}
	}
	return nil
}

var DisableForeignKeyFix = false

func MakeSureForeignKeysAreSetOnCorrectTables(ctx context.Context, tx pgx.Tx) error {
	if DisableForeignKeyFix {
		slog.Info("foreign key fix is disabled, skipping...")
		return nil
	}
	_, err := tx.Exec(ctx, `
-- Drop the foreign key constraint first
ALTER TABLE dependency_vulns DROP CONSTRAINT IF EXISTS fk_dependency_vulns_cve;

-- Set cve_id to NULL where the referenced CVE doesn't exist anymore
DELETE FROM dependency_vulns 
WHERE NOT EXISTS (
    SELECT 1 FROM cves WHERE cves.cve = dependency_vulns.cve_id
);

-- Now recreate the foreign key constraint
ALTER TABLE dependency_vulns ADD CONSTRAINT fk_dependency_vulns_cve 
  FOREIGN KEY (cve_id) REFERENCES cves(cve);

-- Drop any foreign key constraint (if it exists)
ALTER TABLE cve_affected_component DROP CONSTRAINT IF EXISTS fk_cve_affected_component_cve;

-- Delete orphaned rows where the CVE no longer exists
DELETE FROM cve_affected_component 
WHERE NOT EXISTS (
    SELECT 1 FROM cves WHERE cves.cve = cve_affected_component.cvecve
);

-- Recreate the foreign key constraint
ALTER TABLE cve_affected_component ADD CONSTRAINT fk_cve_affected_component_cve 
  FOREIGN KEY (cvecve) REFERENCES cves(cve);


ALTER TABLE weaknesses DROP CONSTRAINT IF EXISTS fk_cves_weaknesses;

DELETE FROM weaknesses 
WHERE NOT EXISTS (
   SELECT 1 FROM cves WHERE cves.cve = weaknesses.cve_id
);

ALTER TABLE weaknesses ADD CONSTRAINT fk_cves_weaknesses 
FOREIGN KEY (cve_id) REFERENCES cves(cve);

`)
	return err
}

func (service importService) copyCSVToDB(csvDir string, extraTableSuffix *string) error {
	ctx := context.Background()

	// Clean up orphaned tables older than 24 hours at the start of import
	// This helps prevent accumulation of tables from failed imports
	if err := cleanupOrphanedTables(ctx, service.pool, 24); err != nil {
		monitoring.Alert("failed to cleanup orphaned tables", err)
		return fmt.Errorf("failed to cleanup orphaned tables: %w", err)
	}

	// read all csv files in the directory
	files, err := os.ReadDir(csvDir)
	if err != nil {
		log.Fatalf("Failed to read directory: %v", err)
	}

	// process prune tables first (they have dependencies and need to be done sequentially)
	errgroup := utils.ErrGroup[string](5)
	for _, file := range files {
		fileExtension := filepath.Ext(file.Name())
		if fileExtension != ".csv" {
			continue
		}
		errgroup.Go(func() (string, error) {
			startTime := time.Now()
			csvFilePath := fmt.Sprintf("%s/%s", csvDir, file.Name())
			tableName := strings.TrimSuffix(file.Name(), ".csv")
			if extraTableSuffix != nil {
				tableName = fmt.Sprintf("%s%s", tableName, *extraTableSuffix)
			}

			slog.Info("importing CSV (prune)", "file", file, "strategy", "shadowTable")
			backupTableName, err := importWithShadowTable(ctx, service.pool, tableName, csvFilePath)
			if err != nil {
				return "", fmt.Errorf("failed to import CSV %s: %w", file.Name(), err)
			}
			slog.Info("imported CSV (prune)", "file", file, "duration", time.Since(startTime))
			return backupTableName, nil
		})
	}
	backupTableNames, err := errgroup.WaitAndCollect()
	if err != nil {
		return fmt.Errorf("error importing prune tables: %w", err)
	}

	// fix the foreign keys
	tx, err := service.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction for foreign key fix: %w", err)
	}
	defer tx.Rollback(ctx) // nolint:errcheck // rollback is safe even after commit
	err = MakeSureForeignKeysAreSetOnCorrectTables(ctx, tx)

	if err != nil {
		return err
	}

	err = tx.Commit(ctx)

	if err != nil {
		return fmt.Errorf("failed to commit foreign key fix transaction: %w", err)
	}

	for _, backupTableName := range backupTableNames {
		cleanupBackupTable(service.pool, backupTableName)
	}

	return nil
}

// countTableRows returns the number of rows in a table
func countTableRows(ctx context.Context, pool *pgxpool.Pool, tableName string) (int64, error) {
	var count int64
	err := pool.QueryRow(ctx, fmt.Sprintf("SELECT COUNT(*) FROM %s", tableName)).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count rows in table %s: %w", tableName, err)
	}
	return count, nil
}

func createShadowTable(ctx context.Context, pool *pgxpool.Pool, tableName string, shadowTableName string, csvFilePath string) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	var committed = false
	defer func() {
		if !committed {
			tx.Rollback(ctx) // nolint:errcheck
		}
	}()

	slog.Debug("Creating shadow table", "shadowTable", shadowTableName, "originalTable", tableName)
	// Create shadow table with same structure
	_, err = tx.Exec(ctx, fmt.Sprintf("CREATE TABLE %s (LIKE %s INCLUDING ALL);", shadowTableName, tableName))
	if err != nil {
		return fmt.Errorf("failed to create shadow table: %w", err)
	}

	slog.Debug("Disabling triggers for faster import", "table", shadowTableName)
	// Fast import with disabled triggers
	_, err = tx.Exec(ctx, "SET session_replication_role = 'replica';")
	if err != nil {
		return fmt.Errorf("failed to disable triggers: %w", err)
	}

	file, err := os.Open(csvFilePath)
	if err != nil {
		return fmt.Errorf("failed to open CSV file: %w", err)
	}
	defer file.Close() //nolint

	slog.Info("Starting CSV data import to shadow table", "shadowTable", shadowTableName)
	importStart := time.Now()
	_, err = tx.Conn().PgConn().CopyFrom(ctx, file, fmt.Sprintf("COPY %s FROM STDIN WITH CSV HEADER;", shadowTableName))
	if err != nil {
		return fmt.Errorf("failed to import CSV: %w", err)
	}
	slog.Info("Completed CSV data import to shadow table", "shadowTable", shadowTableName, "importDuration", time.Since(importStart))

	slog.Debug("Re-enabling triggers", "table", shadowTableName)
	_, err = tx.Exec(ctx, "SET session_replication_role = 'origin';")
	if err != nil {
		return fmt.Errorf("failed to re-enable triggers: %w", err)
	}

	commitStart := time.Now()
	err = tx.Commit(ctx)
	if err != nil {
		return fmt.Errorf("failed to commit shadow table: %w", err)
	}
	committed = true
	slog.Debug("Committed shadow table transaction", "shadowTable", shadowTableName, "commitDuration", time.Since(commitStart))
	return nil
}

// importWithShadowTable: Create shadow table → Import → Atomic swap → Cleanup
// This keeps the original table available during most of the import process
func importWithShadowTable(ctx context.Context, pool *pgxpool.Pool, tableName, csvFilePath string) (string, error) {
	shadowTable := tableName + "_shadow_" + fmt.Sprintf("%d", time.Now().Unix())

	defer func() {
		// Clean up shadow table if it still exists (swap failed)
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		_, err := pool.Exec(cleanupCtx, fmt.Sprintf("DROP TABLE IF EXISTS %s CASCADE;", shadowTable))
		if err != nil {
			slog.Error("Failed to cleanup shadow table after error", "shadowTable", shadowTable, "error", err)
		} else {
			slog.Info("Cleaned up shadow table after error", "shadowTable", shadowTable)
		}
	}()

	// count initial rows
	initialCount, err := countTableRows(ctx, pool, tableName)
	if err != nil {
		slog.Warn("failed to count initial rows", "table", tableName, "error", err)
		initialCount = -1 // Mark as unknown
	}

	slog.Info("starting shadow table import", "table", tableName, "shadowTable", shadowTable, "csvFile", csvFilePath, "initialRows", initialCount)
	// Phase 1: Create and populate shadow table (no locks on original)
	err = createShadowTable(ctx, pool, tableName, shadowTable, csvFilePath)
	if err != nil {
		return "", err
	}

	// Phase 2: Atomic table swap (minimal lock time)
	slog.Info("Starting atomic table swap", "table", tableName, "shadowTable", shadowTable)
	backupTableName, err := swapTables(ctx, pool, tableName, shadowTable)
	if err != nil {
		return "", err
	}

	// Count final rows after import
	finalCount, err := countTableRows(ctx, pool, tableName)
	if err != nil {
		slog.Warn("Failed to count final rows", "table", tableName, "error", err)
		finalCount = -1 // Mark as unknown
	}

	// Calculate and log the results
	var addedRows int64 = -1
	if initialCount >= 0 && finalCount >= 0 {
		addedRows = finalCount - initialCount
	}

	slog.Info("Shadow table import completed successfully",
		"table", tableName,
		"initialRows", initialCount,
		"finalRows", finalCount,
		"rowsAdded", addedRows)

	return backupTableName, nil
}

// swapTables performs atomic table swap with minimal downtime
func swapTables(ctx context.Context, pool *pgxpool.Pool, originalTable, shadowTable string) (string, error) {
	backupTable := originalTable + "_backup_" + fmt.Sprintf("%d", time.Now().Unix())

	slog.Info("Preparing atomic table swap", "original", originalTable, "shadow", shadowTable, "backup", backupTable)

	tx, err := pool.Begin(ctx)
	if err != nil {
		return backupTable, fmt.Errorf("failed to begin swap transaction: %w", err)
	}
	defer tx.Rollback(ctx) // nolint:errcheck

	swapStart := time.Now()
	slog.Debug("Renaming original table to backup", "original", originalTable, "backup", backupTable)
	// Atomic rename sequence (very fast)
	_, err = tx.Exec(ctx, fmt.Sprintf("ALTER TABLE %s RENAME TO %s;", originalTable, backupTable))
	if err != nil {
		return backupTable, fmt.Errorf("failed to backup original table: %w", err)
	}

	slog.Debug("Renaming shadow table to original", "shadow", shadowTable, "original", originalTable)
	_, err = tx.Exec(ctx, fmt.Sprintf("ALTER TABLE %s RENAME TO %s;", shadowTable, originalTable))
	if err != nil {
		// Restore on failure
		slog.Error("Failed to rename shadow table, attempting to restore original", "error", err)
		tx.Exec(ctx, fmt.Sprintf("ALTER TABLE %s RENAME TO %s;", backupTable, originalTable)) // nolint:errcheck
		return backupTable, fmt.Errorf("failed to rename shadow table: %w", err)
	}

	err = tx.Commit(ctx)
	if err != nil {
		return backupTable, fmt.Errorf("failed to commit table swap: %w", err)
	}

	swapDuration := time.Since(swapStart)
	slog.Info("Atomic table swap completed successfully", "table", originalTable, "swapDuration", swapDuration, "backupTable", backupTable)

	// Clean up backup table asynchronously
	slog.Debug("Scheduling asynchronous cleanup of backup table", "backupTable", backupTable)

	return backupTable, nil
}

// cleanupBackupTable removes the backup table in the background with retry logic
func cleanupBackupTable(pool *pgxpool.Pool, backupTable string) {
	slog.Debug("Starting cleanup of backup table", "backupTable", backupTable)

	// Retry up to 3 times with exponential backoff
	for attempt := 1; attempt <= 3; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		cleanupStart := time.Now()

		_, err := pool.Exec(ctx, fmt.Sprintf("DROP TABLE IF EXISTS %s CASCADE;", backupTable))
		cancel()

		if err == nil {
			slog.Info("Successfully cleaned up backup table", "table", backupTable, "cleanupDuration", time.Since(cleanupStart), "attempt", attempt)
			return
		}

		monitoring.Alert("failed to drop backup table", fmt.Errorf("table: %s, error: %w, attempt: %d", backupTable, err, attempt))

		slog.Warn("Failed to drop backup table", "table", backupTable, "error", err, "attempt", attempt, "maxAttempts", 3)

		if attempt < 3 {
			// Exponential backoff: 10s, 30s
			backoffDuration := time.Duration(attempt*10) * time.Second
			slog.Debug("Retrying cleanup after backoff", "backupTable", backupTable, "backoff", backoffDuration)
			time.Sleep(backoffDuration)
		}
	}

	slog.Error("Failed to drop backup table after all retry attempts", "table", backupTable)
}

func (service importService) CleanupOrphanedTables() error {
	ctx := context.Background()
	return cleanupOrphanedTables(ctx, service.pool, 24)
}

func filterTablesToCleanup(tables []string, olderThanHours int) []string {
	var tablesToDrop []string
	currentTime := time.Now().Unix()
	thresholdTimestamp := currentTime - int64(olderThanHours*3600)

	for _, tableName := range tables {
		// Extract timestamp from table name (format: tablename_backup_1234567890 or tablename_shadow_1234567890)
		parts := strings.Split(tableName, "_")
		if len(parts) < 2 {
			continue
		}

		timestampStr := parts[len(parts)-1]
		tableTimestamp, err := strconv.ParseInt(timestampStr, 10, 64)
		if err != nil {
			slog.Debug("Could not parse timestamp from table name", "table", tableName, "timestamp", timestampStr)
			continue
		}

		if tableTimestamp < thresholdTimestamp {
			tablesToDrop = append(tablesToDrop, tableName)
			tableAge := time.Duration(currentTime-tableTimestamp) * time.Second
			slog.Info("Found orphaned table to clean up", "table", tableName, "age", tableAge)
		}
	}
	return tablesToDrop
}

// cleanupOrphanedTables removes old backup and shadow tables that may have been left behind
// This should be called periodically or at the start of import operations
func cleanupOrphanedTables(ctx context.Context, pool *pgxpool.Pool, olderThanHours int) error {
	slog.Info("Starting cleanup of orphaned backup and shadow tables", "olderThanHours", olderThanHours)

	// Query to find all backup and shadow tables
	query := `
		SELECT tablename 
		FROM pg_tables 
		WHERE schemaname = 'public' 
		AND (tablename LIKE '%_backup_%' OR tablename LIKE '%_shadow_%')
		ORDER BY tablename
	`

	rows, err := pool.Query(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to query orphaned tables: %w", err)
	}
	defer rows.Close()

	var tablesToDrop []string
	for rows.Next() {
		var tableName string
		if err := rows.Scan(&tableName); err != nil {
			slog.Error("Failed to scan table name", "error", err)
			continue
		}
		tablesToDrop = append(tablesToDrop, tableName)
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("error iterating orphaned tables: %w", err)
	}

	// Filter tables based on age
	tablesToDrop = filterTablesToCleanup(tablesToDrop, olderThanHours)
	if len(tablesToDrop) == 0 {
		slog.Info("No orphaned tables found for cleanup")
		return nil
	}
	// make sure the foreign keys are not violated before dropping tables
	tx, err := pool.Begin(ctx)
	if err != nil {
		monitoring.Alert("failed to begin transaction for foreign key check", err)
		return fmt.Errorf("failed to begin transaction for foreign key check: %w", err)
	}
	defer tx.Rollback(ctx) // nolint:errcheck // rollback is safe even after commit

	err = MakeSureForeignKeysAreSetOnCorrectTables(ctx, tx)
	if err != nil {
		monitoring.Alert("failed to ensure foreign keys before dropping orphaned tables", err)
		return fmt.Errorf("failed to ensure foreign keys before dropping orphaned tables: %w", err)
	}

	err = tx.Commit(ctx)
	if err != nil {
		monitoring.Alert("failed to commit foreign key check transaction", err)
		return fmt.Errorf("failed to commit foreign key check transaction: %w", err)
	}

	// Drop the orphaned tables
	for _, tableName := range tablesToDrop {
		slog.Info("Dropping orphaned table", "table", tableName)
		_, err := pool.Exec(ctx, fmt.Sprintf("DROP TABLE IF EXISTS %s CASCADE;", tableName))
		if err != nil {
			monitoring.Alert("failed to drop orphaned table", fmt.Errorf("table: %s, error: %w", tableName, err))
			// Continue with other tables even if one fails
		} else {
			slog.Info("Successfully dropped orphaned table", "table", tableName)
		}
	}

	if len(tablesToDrop) > 0 {
		slog.Info("Orphaned table cleanup completed", "tablesDropped", len(tablesToDrop))
	} else {
		slog.Info("No orphaned tables found to clean up")
	}

	return nil
}

func verifySignature(pubKeyFile string, sigFile string, blobFile string, ctx context.Context) error {
	// Load the public key
	pubKeyData, err := os.ReadFile(pubKeyFile)
	if err != nil {
		return fmt.Errorf("could not read public key: %w", err)
	}

	// PEM-Block dekodieren
	block, _ := pem.Decode(pubKeyData)
	if block == nil {
		return fmt.Errorf("could not decode pem block")
	}

	// Parse the public key
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("could not parse public key: %w", err)
	}

	// ECDSA-key generation
	ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("failed to parse public key")
	}

	// Load the signature file
	sigFileData, err := os.ReadFile(sigFile)
	if err != nil {
		return fmt.Errorf("could not read signature file: %w", err)
	}

	// decode base64 signature
	base64Sig := string(sigFileData)
	sig, err := base64.StdEncoding.DecodeString(base64Sig)
	if err != nil {
		return fmt.Errorf("could not decode base64 signature: %w", err)
	}

	// load the block using a reader
	file, err := os.Open(blobFile)
	if err != nil {
		return fmt.Errorf("could not read blob file: %w", err)
	}

	// setup verifier
	verifier, err := signature.LoadECDSAVerifier(ecdsaPubKey, crypto.SHA256)
	if err != nil {
		return fmt.Errorf("could not load verifier: %w", err)
	}

	// Verify the signature
	err = verifier.VerifySignature(bytes.NewReader(sig), file, options.WithContext(ctx))
	if err != nil {
		return fmt.Errorf("could not verify signature: %w", err)
	}

	return nil
}

func copyCSVFromRemoteToLocal(ctx context.Context, repo *remote.Repository, tag string, fs *file.Store) error {
	// Copy csv from the remote repository to the file store
	_, err := oras.Copy(ctx, repo, tag, fs, tag, oras.DefaultCopyOptions)
	if err != nil {
		return fmt.Errorf("could not copy from remote repository to file store: %w", err)
	}

	// Copy the signature from the remote repository to the file store
	tag = tag + ".sig"
	_, err = oras.Copy(ctx, repo, tag, fs, tag, oras.DefaultCopyOptions)
	if err != nil {
		return fmt.Errorf("could not copy from remote repository to file store: %w", err)
	}

	return nil
}

func processInsertDiff(ctx context.Context, tx pgx.Tx, filePath string, tableName string) error {

	entries, err := utils.ReadCsvFile(filePath)
	if err != nil {
		slog.Error("error when reading csv file", "err", err)
		return err
	}
	slog.Info("start inserting", "table", tableName, "entries", len(entries))

	if len(entries) == 0 {
		slog.Info("nothing to insert", "table", tableName)
		return nil
	}

	for _, entry := range entries {
		columns := []string{}
		placeholders := []string{}
		values := []any{}

		i := 1
		for key, value := range entry {
			columns = append(columns, pgx.Identifier{key}.Sanitize())
			placeholders = append(placeholders, fmt.Sprintf("$%d", i))

			// Handle NULL values
			if value == "NULL" || value == "" {
				values = append(values, nil)
			} else {
				values = append(values, value)
			}
			i++
		}

		sql := fmt.Sprintf(
			"INSERT INTO %s (%s) VALUES (%s) ON CONFLICT DO NOTHING",
			pgx.Identifier{tableName}.Sanitize(),
			strings.Join(columns, ","),
			strings.Join(placeholders, ","),
		)

		_, err := tx.Exec(ctx, "SAVEPOINT sp")
		if err != nil {
			return err
		}

		_, err = tx.Exec(ctx, sql, values...)
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23503" {
				slog.Warn("ignoring missing foreign key", "values", values)
				// rollback only this statement
				_, err = tx.Exec(ctx, "ROLLBACK TO SAVEPOINT sp")
				if err != nil {
					return err
				}
				continue
			}
			return err
		}

		_, _ = tx.Exec(ctx, "RELEASE SAVEPOINT sp")
	}
	slog.Info("insert completed")
	return nil
}

func processDeleteDiff(ctx context.Context, tx pgx.Tx, filePath string, tableName string, extraTableNameSuffix *string) error {
	fd, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer fd.Close() //nolint

	entries, err := utils.ReadCsvFile(filePath)
	if err != nil {
		slog.Error("error when reading csv file", "err", err)
	}
	slog.Info("start deleting", "table", tableName, "entries", len(entries))

	if len(entries) == 0 {
		slog.Info("nothing to delete", "table", tableName)
		return nil
	}

	primaryKeys := primaryKeysFromTables[strings.TrimSuffix(tableName, utils.SafeDereference(extraTableNameSuffix))]
	if len(primaryKeys) == 0 {
		slog.Error("could not determine primary key(s)", "table", tableName)
		return fmt.Errorf("could not determine primary key(s) for table: %s", tableName)
	}

	if len(primaryKeys) > 2 {
		slog.Error("more than 2 primary keys not supported", "table", tableName)
		return fmt.Errorf("more than 2 primary keys not supported for table: %s", tableName)
	}

	if len(primaryKeys) == 1 {
		primaryKeyColumnName := primaryKeys[0]
		for _, entry := range entries {
			primaryKeyValue := entry[primaryKeyColumnName].(string)
			sql := fmt.Sprintf("DELETE FROM %s WHERE %s.%s = %s", tableName, tableName, primaryKeyColumnName, "'"+primaryKeyValue+"'")
			_, err := tx.Exec(ctx, sql)
			if err != nil {
				slog.Error("error when deleting from table", "table", tableName, "id", primaryKeyValue)
				continue
			}
		}
	} else {
		primaryKey1 := primaryKeys[0]
		primaryKey2 := primaryKeys[1]
		for _, entry := range entries {
			primaryKey1Value := entry[primaryKey1].(string)
			primaryKey2Value := entry[primaryKey2].(string)
			sql := fmt.Sprintf("DELETE FROM %s WHERE %s = %s AND %s = %s", tableName, primaryKey1, "'"+primaryKey1Value+"'", primaryKey2, "'"+primaryKey2Value+"'")
			_, err := tx.Exec(ctx, sql)
			if err != nil {
				slog.Error("error when deleting from table", "table", tableName, "id1", primaryKey1Value, "id2", primaryKey2Value)
				continue
			}
		}
	}
	slog.Info("delete completed")
	return nil
}

func processUpdateDiff(ctx context.Context, tx pgx.Tx, filePath string, tableName string, extraTableNameSuffix *string) error {
	slog.Info("start updating", "table", tableName)
	fd, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer fd.Close() //nolint
	// count the number of lines in the file

	csvReader := csv.NewReader(fd)
	record, err := csvReader.Read() // read all the column names from the header row
	if err != nil {
		return err
	}

	primaryKeys := primaryKeysFromTables[strings.TrimSuffix(tableName, utils.SafeDereference(extraTableNameSuffix))]
	if len(primaryKeys) == 0 {
		slog.Error("could not determine primary key(s)", "table", tableName)
		return fmt.Errorf("could not determine primary key(s) for table: %s", tableName)
	}

	if len(primaryKeys) > 2 {
		slog.Error("more than 2 primary keys not supported", "table", tableName)
		return fmt.Errorf("more than 2 primary keys not supported for table: %s", tableName)
	}

	columnsToUpdate := record[len(primaryKeys):] // exclude primary key(s)
	for i, column := range columnsToUpdate {
		columnsToUpdate[i] = fmt.Sprintf("\"%s\" = EXCLUDED.%s", column, column) // escape possible sql syntax column names with ""
	}
	assignSQL := strings.Join(columnsToUpdate, ", ")

	tmpTable := tableName + "_tmp_" + strconv.Itoa(int(time.Now().Unix()))

	_, err = tx.Conn().Exec(ctx, fmt.Sprintf("CREATE TABLE %s (LIKE %s INCLUDING ALL);", tmpTable, tableName))
	if err != nil {
		slog.Error("error when trying to create tmp table used for updating", "table", tableName, "err", err)
		return err
	}
	defer tx.Exec(ctx, fmt.Sprintf("DROP TABLE %s;", tmpTable)) //nolint

	fd, err = os.Open(filePath) // reopen csv file since we read from it once already
	if err != nil {
		return err
	}

	_, err = tx.Conn().PgConn().CopyFrom(ctx, fd, fmt.Sprintf("COPY %s FROM STDIN WITH (FORMAT csv, HEADER true, NULL 'NULL')", tmpTable))
	if err != nil {
		slog.Error("could not copy to tmp table", "table", tableName, "err", err)
		return err
	}

	var upsertSQL string
	if len(primaryKeys) == 1 {
		upsertSQL = fmt.Sprintf("INSERT INTO %s SELECT * FROM %s ON CONFLICT (%s) DO UPDATE SET %s", tableName, tmpTable, primaryKeys[0], assignSQL)
	} else {
		upsertSQL = fmt.Sprintf("INSERT INTO %s SELECT * FROM %s ON CONFLICT (%s, %s) DO UPDATE SET %s", tableName, tmpTable, primaryKeys[0], primaryKeys[1], assignSQL)
	}

	if _, err := tx.Exec(ctx, upsertSQL); err != nil {
		slog.Error("could not insert from tmp table to original table", "table", tableName, "err", err)
		return err
	}
	slog.Info("update completed")

	return nil
}

// downloads the fileName with the tag from the devguard package master, verifies the signature and unzips it into tmp Folder
func downloadAndSaveZipToTemp(repo *remote.Repository, tag string, outpath string) (*file.Store, error) {
	slog.Info("importing vulndb started")

	sigFile := outpath + "/vulndb.zip.sig"
	blobFile := outpath + "/vulndb.zip"
	pubKeyFile := "cosign.pub"

	ctx := context.Background()

	fs, err := file.New(outpath)
	if err != nil {
		panic(err)
	}

	// import the vulndb csv to the file store
	err = copyCSVFromRemoteToLocal(ctx, repo, tag, fs)
	if err != nil {
		return fs, fmt.Errorf("could not copy csv from remote to local: %w", err)
	}

	// verify the signature of the imported data
	err = verifySignature(pubKeyFile, sigFile, blobFile, ctx)
	if err != nil {
		return fs, fmt.Errorf("could not verify signature: %w", err)
	}
	slog.Info("successfully verified signature")

	// open the blob file
	f, err := os.Open(blobFile)
	if err != nil {
		panic(err)
	}
	defer f.Close() //nolint

	// unzip the blob file into vulndb-tmp dir
	err = utils.Unzip(blobFile, outpath+"/")
	if err != nil {
		return fs, fmt.Errorf("error when trying to build zip file: %w", err)
	}
	slog.Info("unzipping vulndb completed", "path", outpath+"/")
	return fs, nil
}

func (service importService) GetAllIncrementalTagsSinceSnapshot(ctx context.Context, repo *remote.Repository) ([]string, error) {

	allTags := make([]string, 0, 1000)

	repo.TagListPageSize = 10_000
	err := repo.Tags(ctx, "", func(tags []string) error {
		slices.Reverse(tags)

		for i := range tags {
			if strings.Contains(tags[i], ".sig") {
				continue
			}
			allTags = append(allTags, tags[i])
			if strings.Contains(tags[i], "snapshot") {
				break
			}
		}
		return nil
	})

	if err != nil {
		return nil, err
	}
	slices.Reverse(allTags)

	return allTags, nil
}

func (service importService) GetIncrementalTags(ctx context.Context, repo *remote.Repository) ([]string, error) {
	lastVersion := ""
	allTags := make([]string, 0, 3000)

	err := service.configService.GetJSONConfig("vulndb.lastIncrementalImport", &lastVersion)
	if err != nil {
		slog.Warn("could not get last incremental import version, assuming no version is set yet", "err", err)
	}

	repo.TagListPageSize = 1000
	err = repo.Tags(ctx, lastVersion, func(tags []string) error {
		slices.Reverse(tags)
		for i := range tags {
			if strings.Contains(tags[i], ".sig") {
				continue
			}
			allTags = append(allTags, tags[i])
			if strings.Contains(tags[i], "snapshot") {
				break
			}
		}

		return nil
	})
	if err != nil {
		return nil, err
	}
	slices.Reverse(allTags)

	if len(allTags) >= 2 && !slices.IsSorted(allTags) {
		slog.Error("slice not sorted")
		return nil, fmt.Errorf("slice not sorted")
	}
	return allTags, nil
}
