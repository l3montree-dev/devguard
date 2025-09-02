package vulndb

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"

	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/file"
	"oras.land/oras-go/v2/registry/remote"
)

var pruneTablesBeforeInsert = []string{
	"affected_components",
	"cve_affected_component",
}

var tableNameToPrimaryKey = map[string][]string{
	"cves":                   {"cve"},
	"cwes":                   {"cwe"},
	"exploits":               {"id"},
	"affected_components":    {"id"},
	"cve_affected_component": {"cvecve", "affected_component_id"},
}

type importService struct {
	cveRepository                core.CveRepository
	cweRepository                core.CweRepository
	exploitRepository            core.ExploitRepository
	affectedComponentsRepository core.AffectedComponentRepository
}

func NewImportService(cvesRepository core.CveRepository, cweRepository core.CweRepository, exploitRepository core.ExploitRepository, affectedComponentsRepository core.AffectedComponentRepository) *importService {
	return &importService{
		cveRepository:                cvesRepository,
		cweRepository:                cweRepository,
		exploitRepository:            exploitRepository,
		affectedComponentsRepository: affectedComponentsRepository,
	}
}

func (s importService) Import(tx core.DB, tag string) error {
	slog.Info("Importing vulndb started")
	begin := time.Now()
	tmp := "./vulndb-tmp"
	sigFile := tmp + "/vulndb.zip.sig"
	blobFile := tmp + "/vulndb.zip"
	pubKeyFile := "cosign.pub"

	ctx := context.Background()

	reg := "ghcr.io/l3montree-dev/devguard/vulndb"

	// create a file store
	defer os.RemoveAll(tmp)
	fs, err := file.New(tmp)
	if err != nil {
		panic(err)
	}
	defer fs.Close()

	//import the vulndb csv to the file store
	err = copyCSVFromRemoteToLocal(ctx, reg, tag, fs)
	if err != nil {
		return fmt.Errorf("could not copy csv from remote to local: %w", err)
	}

	// verify the signature of the imported data
	err = verifySignature(pubKeyFile, sigFile, blobFile, ctx)
	if err != nil {
		return fmt.Errorf("could not verify signature: %w", err)
	}
	slog.Info("successfully verified signature")

	// open the blob file
	f, err := os.Open(blobFile)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	// Unzip the blob file
	err = utils.Unzip(blobFile, tmp+"/")
	if err != nil {
		panic(err)
	}
	slog.Info("Unzipping vulndb completed")

	//copy csv files to database
	err = s.copyCSVToDB(tmp)
	if err != nil {
		return err
	}

	slog.Info("Importing vulndb completed", "duration", time.Since(begin))

	return nil
}

func (s importService) copyCSVToDB(tmp string) error {
	username := os.Getenv("POSTGRES_USER")
	password := os.Getenv("POSTGRES_PASSWORD")
	host := os.Getenv("POSTGRES_HOST")
	port := os.Getenv("POSTGRES_PORT")
	dbname := os.Getenv("POSTGRES_DB")

	// Replace with your PostgreSQL connection string
	connStr := fmt.Sprintf("postgres://%s:%s@%s:%s/%s", username, password, host, port, dbname)

	// Create a connection pool with increased connections for parallel processing
	ctx := context.Background()
	config, err := pgxpool.ParseConfig(connStr)
	if err != nil {
		log.Fatalf("Unable to parse config: %v", err)
	}

	// Increase pool size for parallel operations
	config.MaxConns = 10
	config.MinConns = 2

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		log.Fatalf("Unable to create connection pool: %v", err)
	}
	defer pool.Close()

	// read all csv files in the directory
	files, err := os.ReadDir(tmp)
	if err != nil {
		log.Fatalf("Failed to read directory: %v", err)
	}

	// Separate files by import strategy for optimal processing order
	var pruneFiles, upsertFiles []string
	for _, file := range files {
		if file.IsDir() || filepath.Ext(file.Name()) != ".csv" {
			continue
		}

		tableName := strings.TrimSuffix(file.Name(), ".csv")
		if utils.Contains(pruneTablesBeforeInsert, tableName) {
			pruneFiles = append(pruneFiles, file.Name())
		} else {
			upsertFiles = append(upsertFiles, file.Name())
		}
	}

	// Process prune tables first (they have dependencies and need to be done sequentially)
	for _, fileName := range pruneFiles {
		startTime := time.Now()
		csvFilePath := fmt.Sprintf("%s/%s", tmp, fileName)
		tableName := strings.TrimSuffix(fileName, ".csv")

		slog.Info("Importing CSV (prune)", "file", fileName, "strategy", "shadow_table")
		err = importCSV(ctx, pool, tableName, csvFilePath)
		if err != nil {
			log.Fatalf("Failed to import CSV %s: %v", csvFilePath, err)
		}
		slog.Info("Imported CSV (prune)", "file", fileName, "duration", time.Since(startTime))
	}

	// Process upsert tables in parallel (they can be done concurrently)
	if len(upsertFiles) > 0 {
		const maxConcurrency = 3 // Limit concurrent operations to avoid overwhelming the database
		semaphore := make(chan struct{}, maxConcurrency)
		errChan := make(chan error, len(upsertFiles))

		slog.Info("Starting parallel import of upsert tables", "count", len(upsertFiles), "concurrency", maxConcurrency)

		for _, fileName := range upsertFiles {
			semaphore <- struct{}{} // Acquire semaphore
			go func(fileName string) {
				defer func() { <-semaphore }() // Release semaphore

				startTime := time.Now()
				csvFilePath := fmt.Sprintf("%s/%s", tmp, fileName)
				tableName := strings.TrimSuffix(fileName, ".csv")

				slog.Info("Importing CSV (upsert)", "file", fileName, "strategy", "parallel_upsert")
				err := importCSV(ctx, pool, tableName, csvFilePath)
				if err != nil {
					errChan <- fmt.Errorf("failed to import CSV %s: %w", csvFilePath, err)
					return
				}

				slog.Info("Imported CSV (upsert)", "file", fileName, "duration", time.Since(startTime))
				errChan <- nil
			}(fileName)
		}

		// Wait for all goroutines to complete and check for errors
		for i := 0; i < len(upsertFiles); i++ {
			if err := <-errChan; err != nil {
				log.Fatalf("Parallel import failed: %v", err)
			}
		}

		slog.Info("Completed parallel import of upsert tables")
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

func importCSV(ctx context.Context, pool *pgxpool.Pool, tableName, csvFilePath string) error {
	// Use shadow table pattern for pruned tables to minimize downtime
	if utils.Contains(pruneTablesBeforeInsert, tableName) {
		return importWithShadowTable(ctx, pool, tableName, csvFilePath)
	}

	// Use improved upsert for other tables
	return importWithUpsert(ctx, pool, tableName, csvFilePath)
}

// importWithShadowTable: Create shadow table → Import → Atomic swap → Cleanup
// This keeps the original table available during most of the import process
func importWithShadowTable(ctx context.Context, pool *pgxpool.Pool, tableName, csvFilePath string) error {
	shadowTable := tableName + "_shadow_" + fmt.Sprintf("%d", time.Now().Unix())

	// Count initial rows
	initialCount, err := countTableRows(ctx, pool, tableName)
	if err != nil {
		slog.Warn("Failed to count initial rows", "table", tableName, "error", err)
		initialCount = -1 // Mark as unknown
	}

	slog.Info("Starting shadow table import", "table", tableName, "shadow_table", shadowTable, "csv_file", csvFilePath, "initial_rows", initialCount)

	// Phase 1: Create and populate shadow table (no locks on original)
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx) // nolint:errcheck

	slog.Debug("Creating shadow table", "shadow_table", shadowTable, "original_table", tableName)
	// Create shadow table with same structure
	_, err = tx.Exec(ctx, fmt.Sprintf("CREATE TABLE %s (LIKE %s INCLUDING ALL);", shadowTable, tableName))
	if err != nil {
		return fmt.Errorf("failed to create shadow table: %w", err)
	}

	slog.Debug("Disabling triggers for faster import", "table", shadowTable)
	// Fast import with disabled triggers
	_, err = tx.Exec(ctx, "SET session_replication_role = 'replica';")
	if err != nil {
		return fmt.Errorf("failed to disable triggers: %w", err)
	}

	file, err := os.Open(csvFilePath)
	if err != nil {
		return fmt.Errorf("failed to open CSV file: %w", err)
	}
	defer file.Close()

	slog.Info("Starting CSV data import to shadow table", "shadow_table", shadowTable)
	importStart := time.Now()
	_, err = tx.Conn().PgConn().CopyFrom(ctx, file, fmt.Sprintf("COPY %s FROM STDIN WITH CSV HEADER;", shadowTable))
	if err != nil {
		return fmt.Errorf("failed to import CSV: %w", err)
	}
	slog.Info("Completed CSV data import to shadow table", "shadow_table", shadowTable, "import_duration", time.Since(importStart))

	slog.Debug("Re-enabling triggers", "table", shadowTable)
	_, err = tx.Exec(ctx, "SET session_replication_role = 'origin';")
	if err != nil {
		return fmt.Errorf("failed to re-enable triggers: %w", err)
	}

	commitStart := time.Now()
	err = tx.Commit(ctx)
	if err != nil {
		return fmt.Errorf("failed to commit shadow table: %w", err)
	}
	slog.Debug("Committed shadow table transaction", "shadow_table", shadowTable, "commit_duration", time.Since(commitStart))

	// Phase 2: Atomic table swap (minimal lock time)
	slog.Info("Starting atomic table swap", "table", tableName, "shadow_table", shadowTable)
	if err := swapTables(ctx, pool, tableName, shadowTable); err != nil {
		return err
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
		"initial_rows", initialCount,
		"final_rows", finalCount,
		"rows_added", addedRows)

	return nil
}

// swapTables performs atomic table swap with minimal downtime
func swapTables(ctx context.Context, pool *pgxpool.Pool, originalTable, shadowTable string) error {
	backupTable := originalTable + "_backup_" + fmt.Sprintf("%d", time.Now().Unix())

	slog.Info("Preparing atomic table swap", "original", originalTable, "shadow", shadowTable, "backup", backupTable)

	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin swap transaction: %w", err)
	}
	defer tx.Rollback(ctx) // nolint:errcheck

	swapStart := time.Now()
	slog.Debug("Renaming original table to backup", "original", originalTable, "backup", backupTable)
	// Atomic rename sequence (very fast)
	_, err = tx.Exec(ctx, fmt.Sprintf("ALTER TABLE %s RENAME TO %s;", originalTable, backupTable))
	if err != nil {
		return fmt.Errorf("failed to backup original table: %w", err)
	}

	slog.Debug("Renaming shadow table to original", "shadow", shadowTable, "original", originalTable)
	_, err = tx.Exec(ctx, fmt.Sprintf("ALTER TABLE %s RENAME TO %s;", shadowTable, originalTable))
	if err != nil {
		// Restore on failure
		slog.Error("Failed to rename shadow table, attempting to restore original", "error", err)
		tx.Exec(ctx, fmt.Sprintf("ALTER TABLE %s RENAME TO %s;", backupTable, originalTable)) // nolint:errcheck
		return fmt.Errorf("failed to rename shadow table: %w", err)
	}

	err = tx.Commit(ctx)
	if err != nil {
		return fmt.Errorf("failed to commit table swap: %w", err)
	}

	swapDuration := time.Since(swapStart)
	slog.Info("Atomic table swap completed successfully", "table", originalTable, "swap_duration", swapDuration, "backup_table", backupTable)

	// Clean up backup table asynchronously
	slog.Debug("Scheduling asynchronous cleanup of backup table", "backup_table", backupTable)
	go cleanupBackupTable(pool, backupTable)

	return nil
}

// cleanupBackupTable removes the backup table in the background
func cleanupBackupTable(pool *pgxpool.Pool, backupTable string) {
	slog.Debug("Starting cleanup of backup table", "backup_table", backupTable)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cleanupStart := time.Now()
	_, err := pool.Exec(ctx, fmt.Sprintf("DROP TABLE IF EXISTS %s;", backupTable))
	if err != nil {
		slog.Error("Failed to drop backup table", "table", backupTable, "error", err, "cleanup_duration", time.Since(cleanupStart))
	} else {
		slog.Info("Successfully cleaned up backup table", "table", backupTable, "cleanup_duration", time.Since(cleanupStart))
	}
}

// importWithUpsert handles upsert operations for non-pruned tables
func importWithUpsert(ctx context.Context, pool *pgxpool.Pool, tableName, csvFilePath string) error {
	// Count initial rows
	initialCount, err := countTableRows(ctx, pool, tableName)
	if err != nil {
		slog.Warn("Failed to count initial rows", "table", tableName, "error", err)
		initialCount = -1 // Mark as unknown
	}

	slog.Info("Starting upsert import", "table", tableName, "csv_file", csvFilePath, "initial_rows", initialCount)

	startTime := time.Now()
	defer func() {
		slog.Debug("Completed upsert import", "table", tableName, "total_duration", time.Since(startTime))
	}()

	tx, err := pool.Begin(ctx)
	if err != nil {
		slog.Error("Failed to begin transaction", "table", tableName, "error", err)
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	committed := false
	defer func() {
		if !committed && err != nil {
			slog.Error("Rolling back transaction", "table", tableName, "error", err)
			tx.Rollback(ctx) // nolint:errcheck
		}
	}()

	// Create temporary table for staging
	tempTable := fmt.Sprintf("tmp_%s_%d", tableName, time.Now().Unix())
	slog.Debug("Creating temporary staging table", "temp_table", tempTable, "original_table", tableName)
	_, err = tx.Exec(ctx, fmt.Sprintf("CREATE TEMP TABLE %s AS SELECT * FROM %s LIMIT 0;", tempTable, tableName))
	if err != nil {
		slog.Error("Failed to create temporary table", "temp_table", tempTable, "error", err)
		return fmt.Errorf("failed to create temp table: %w", err)
	}

	// Fast import with disabled triggers
	slog.Debug("Disabling triggers for fast import", "table", tableName)
	_, err = tx.Exec(ctx, "SET session_replication_role = 'replica';")
	if err != nil {
		slog.Error("Failed to disable triggers", "table", tableName, "error", err)
		return fmt.Errorf("failed to disable triggers: %w", err)
	}

	file, err := os.Open(csvFilePath)
	if err != nil {
		slog.Error("Failed to open CSV file", "file", csvFilePath, "error", err)
		return fmt.Errorf("failed to open CSV file: %w", err)
	}
	defer file.Close()

	copyStart := time.Now()
	slog.Debug("Starting COPY operation to temporary table", "temp_table", tempTable, "csv_file", csvFilePath)
	_, err = tx.Conn().PgConn().CopyFrom(ctx, file, fmt.Sprintf("COPY %s FROM STDIN WITH CSV HEADER;", tempTable))
	if err != nil {
		slog.Error("Failed to import CSV to temporary table", "temp_table", tempTable, "error", err)
		return fmt.Errorf("failed to import CSV: %w", err)
	}

	copyDuration := time.Since(copyStart)
	slog.Debug("Completed COPY operation", "temp_table", tempTable, "copy_duration", copyDuration)

	slog.Debug("Re-enabling triggers", "table", tableName)
	_, err = tx.Exec(ctx, "SET session_replication_role = 'origin';")
	if err != nil {
		slog.Error("Failed to re-enable triggers", "table", tableName, "error", err)
		return fmt.Errorf("failed to re-enable triggers: %w", err)
	}

	// Perform bulk upsert
	slog.Debug("Starting bulk upsert operation", "table", tableName, "temp_table", tempTable)
	if err := performBulkUpsert(ctx, tx, tableName, tempTable); err != nil {
		slog.Error("Failed to perform bulk upsert", "table", tableName, "temp_table", tempTable, "error", err)
		return err
	}

	// Count final rows after upsert (note: we need to commit first to see the changes)
	slog.Debug("Committing transaction", "table", tableName)
	err = tx.Commit(ctx)
	if err != nil {
		slog.Error("Failed to commit upsert transaction", "table", tableName, "error", err)
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	committed = true

	// Count final rows
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

	slog.Info("Upsert import completed successfully",
		"table", tableName,
		"total_duration", time.Since(startTime),
		"initial_rows", initialCount,
		"final_rows", finalCount,
		"rows_added", addedRows)

	return nil
}

// performBulkUpsert executes an efficient bulk upsert operation
func performBulkUpsert(ctx context.Context, tx pgx.Tx, tableName, tempTable string) error {
	slog.Debug("Starting bulk upsert operation", "table", tableName, "temp_table", tempTable)

	startTime := time.Now()
	defer func() {
		slog.Debug("Completed bulk upsert operation", "table", tableName, "upsert_duration", time.Since(startTime))
	}()

	// Get primary key for conflict resolution
	primaryKey := tableNameToPrimaryKey[tableName]
	if len(primaryKey) == 0 {
		slog.Error("No primary key defined for table", "table", tableName)
		return fmt.Errorf("no primary key defined for table %s", tableName)
	}
	slog.Debug("Retrieved primary key for table", "table", tableName, "primary_key", primaryKey)

	// Get all columns
	queryStart := time.Now()
	rows, err := tx.Query(ctx, "SELECT column_name FROM information_schema.columns WHERE table_name = $1 ORDER BY ordinal_position", tableName)
	if err != nil {
		slog.Error("Failed to get column names", "table", tableName, "error", err)
		return fmt.Errorf("failed to get column names: %w", err)
	}
	defer rows.Close()

	var columns []string
	for rows.Next() {
		var columnName string
		if err := rows.Scan(&columnName); err != nil {
			slog.Error("Failed to scan column name", "table", tableName, "error", err)
			return fmt.Errorf("failed to scan column name: %w", err)
		}
		columns = append(columns, columnName)
	}

	if len(columns) == 0 {
		slog.Error("No columns found for table", "table", tableName)
		return fmt.Errorf("no columns found for table %s", tableName)
	}

	queryDuration := time.Since(queryStart)
	slog.Debug("Retrieved table columns", "table", tableName, "column_count", len(columns), "query_duration", queryDuration)

	// Build UPDATE clauses (exclude primary key columns)
	var updateClauses []string
	for _, col := range columns {
		isPrimaryKey := false
		for _, pk := range primaryKey {
			if col == pk {
				isPrimaryKey = true
				break
			}
		}
		if !isPrimaryKey {
			updateClauses = append(updateClauses, fmt.Sprintf(`"%s" = EXCLUDED."%s"`, col, col))
		}
	}
	slog.Debug("Built update clauses", "table", tableName, "update_clause_count", len(updateClauses))

	// Execute bulk upsert
	quotedColumns := make([]string, len(columns))
	for i, col := range columns {
		quotedColumns[i] = fmt.Sprintf(`"%s"`, col)
	}

	quotedPrimaryKey := make([]string, len(primaryKey))
	for i, pk := range primaryKey {
		quotedPrimaryKey[i] = fmt.Sprintf(`"%s"`, pk)
	}

	upsertSQL := fmt.Sprintf(`
		INSERT INTO %s (%s)
		SELECT %s FROM %s
		ON CONFLICT (%s) DO UPDATE SET %s`,
		tableName,
		strings.Join(quotedColumns, ","),
		strings.Join(quotedColumns, ","),
		tempTable,
		strings.Join(quotedPrimaryKey, ","),
		strings.Join(updateClauses, ","))

	upsertStart := time.Now()
	slog.Debug("Executing bulk upsert SQL", "table", tableName, "temp_table", tempTable)
	_, err = tx.Exec(ctx, upsertSQL)
	if err != nil {
		slog.Error("Failed to execute bulk upsert", "table", tableName, "temp_table", tempTable, "error", err)
		return fmt.Errorf("failed to upsert data: %w", err)
	}

	upsertDuration := time.Since(upsertStart)
	slog.Info("Successfully completed bulk upsert", "table", tableName, "upsert_duration", upsertDuration, "total_duration", time.Since(startTime))

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

func copyCSVFromRemoteToLocal(ctx context.Context, reg string, tag string, fs *file.Store) error {
	// Connect to a remote repository
	repo, err := remote.NewRepository(reg)
	if err != nil {
		return fmt.Errorf("could not connect to remote repository: %w", err)
	}

	// Copy csv from the remote repository to the file store
	_, err = oras.Copy(ctx, repo, tag, fs, tag, oras.DefaultCopyOptions)
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
