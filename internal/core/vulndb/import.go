package vulndb

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
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

// maps every table associated with the vulndb to their respective primary key(s) used in the diff queries
var primaryKeysFromTables = map[string][]string{"cves": {"cve"}, "cwes": {"cwe"}, "affected_components": {"id"}, "cve_affected_component": {"affected_component_id", "cvecve"}, "exploits": {"id"}}

// maps every table associated with the vulndb to their attributes we want to watch for the diff_update queries
var relevantAttributesFromTables = map[string][]string{"cves": {"date_last_modified"}, "cwes": {"description"}, "affected_components": {}, "cve_affected_component": {}, "exploits": {"*"}}

func (s importService) Import(tx core.DB, tag string) error {
	slog.Info("importing vulndb started")
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

	// unzip the blob file into vulndb-tmp dir
	err = utils.Unzip(blobFile, tmp+"/")
	if err != nil {
		panic(err)
	}
	slog.Info("unzipping vulndb completed")

	//copy csv files to database
	err = s.copyCSVToDB(tmp)
	if err != nil {
		return err
	}

	slog.Info("importing vulndb completed", "duration", time.Since(begin))

	return nil
}

func (s importService) copyCSVToDB(tmp string) error {
	username := os.Getenv("POSTGRES_USER")
	password := os.Getenv("POSTGRES_PASSWORD")
	host := os.Getenv("POSTGRES_HOST")
	port := os.Getenv("POSTGRES_PORT")
	dbname := os.Getenv("POSTGRES_DB")

	// replace with your PostgreSQL connection string
	connStr := fmt.Sprintf("postgres://%s:%s@%s:%s/%s", username, password, host, port, dbname)

	// create a connection pool with increased connections for parallel processing
	ctx := context.Background()
	config, err := pgxpool.ParseConfig(connStr)
	if err != nil {
		log.Fatalf("Unable to parse config: %v", err)
	}

	// increase pool size for parallel operations
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

	// process prune tables first (they have dependencies and need to be done sequentially)
	wg := sync.WaitGroup{}
	for _, file := range files {
		fileExtension := filepath.Ext(file.Name())
		if fileExtension != ".csv" {
			continue
		}
		wg.Go(func() {
			startTime := time.Now()
			csvFilePath := fmt.Sprintf("%s/%s", tmp, file.Name())
			tableName := strings.TrimSuffix(file.Name(), ".csv")

			slog.Info("importing CSV (prune)", "file", file, "strategy", "shadowTable")
			err = importCSV(ctx, pool, tableName, csvFilePath)
			if err != nil {
				log.Fatalf("Failed to import CSV %s: %v", csvFilePath, err)
			}
			slog.Info("imported CSV (prune)", "file", file, "duration", time.Since(startTime))
		})
	}
	wg.Wait()
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
	return importWithShadowTable(ctx, pool, tableName, csvFilePath)
}

// importWithShadowTable: Create shadow table → Import → Atomic swap → Cleanup
// This keeps the original table available during most of the import process
func importWithShadowTable(ctx context.Context, pool *pgxpool.Pool, tableName, csvFilePath string) error {

	shadowTable := tableName + "_shadow_" + fmt.Sprintf("%d", time.Now().Unix())
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
		return err
	}

	// Phase 2: Atomic table swap (minimal lock time)
	tableSwap := os.Getenv("MAKE_TABLE_DIFF")
	if tableSwap != "true" {
		slog.Info("Starting atomic table swap", "table", tableName, "shadowTable", shadowTable)
		if err := swapTables(ctx, pool, tableName, shadowTable); err != nil {
			return err
		}
	} else {
		dirPath := "vulndb-tmp/"
		slog.Info("start producing diff tables", "table", tableName)
		tx, err := pool.Begin(ctx)
		if err != nil {
			return fmt.Errorf("failed to begin transaction: %w", err)
		}
		primaryKeys := primaryKeysFromTables[tableName]
		if len(primaryKeys) == 0 {
			slog.Error("no primary key found", "table", tableName)
			return fmt.Errorf("no primary key found")
		}

		// all the new entries
		var rows pgx.Rows
		if len(primaryKeys) == 1 {
			rows, err = tx.Query(ctx, fmt.Sprintf("SELECT shadow.* FROM %s shadow LEFT JOIN %s old USING (%s) WHERE old.%s IS NULL;", shadowTable, tableName, primaryKeys[0], primaryKeys[0]))
		} else {
			rows, err = tx.Query(ctx, fmt.Sprintf("SELECT shadow.* FROM %s shadow LEFT JOIN %s old USING (%s) WHERE old.%s IS NULL OR old.%s IS NULL;", shadowTable, tableName, primaryKeys[0]+", "+primaryKeys[1], primaryKeys[0], primaryKeys[1]))
		}

		if err != nil {
			return err
		}
		err = rowsToCSV(rows, dirPath+tableName+"_diff_insert")
		if err != nil {
			return err
		}
		rows.Close()

		// all the deleted entries
		if len(primaryKeys) == 1 {
			rows, err = tx.Query(ctx, fmt.Sprintf("SELECT old.* FROM %s old LEFT JOIN %s shadow USING (%s) WHERE shadow.%s IS NULL;", tableName, shadowTable, primaryKeys[0], primaryKeys[0]))
		} else {
			rows, err = tx.Query(ctx, fmt.Sprintf("SELECT old.* FROM %s old LEFT JOIN %s shadow USING (%s) WHERE shadow.%s IS NULL OR shadow.%s IS NULL;", tableName, shadowTable, primaryKeys[0]+", "+primaryKeys[1], primaryKeys[0], primaryKeys[1]))
		}

		if err != nil {
			return err
		}
		err = rowsToCSV(rows, dirPath+tableName+"_diff_delete")
		if err != nil {
			return err
		}
		rows.Close()

		// all the updated rows need table for all relevant attributes per table
		columns := relevantAttributesFromTables[tableName]
		if len(columns) == 0 {
			slog.Info("no update diff table needed", "table", tableName)
			return nil
		}
		oldFlags := "old." + columns[0]
		shadowFlags := "shadow." + columns[0]
		for _, column := range columns[1:] {
			oldFlags += ",old." + column
			shadowFlags += ",shadow." + column
		}

		slog.Debug("Calling update", "table", tableName, "oldFlags", oldFlags, "shadowFlags", shadowFlags)
		rows, err = tx.Query(ctx, fmt.Sprintf(`SELECT shadow.* FROM %s old
			JOIN %s shadow USING (%s) WHERE (%s) 
			IS DISTINCT FROM (%s);`, tableName, shadowTable, primaryKeys[0], shadowFlags, oldFlags))
		if err != nil {
			return err
		}
		err = rowsToCSV(rows, dirPath+tableName+"_diff_update")
		if err != nil {
			return err
		}
		rows.Close()
		slog.Info("finished producing diff tables", "table", tableName)

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

	return nil
}

func rowsToCSV(rows pgx.Rows, csvFileName string) error {
	fd, err := os.Create(csvFileName + ".csv")
	if err != nil {
		return err
	}
	defer fd.Close()
	csvWriter := csv.NewWriter(fd)

	columnNames := rows.FieldDescriptions()
	headers := make([]string, len(columnNames))
	for i, column := range columnNames {
		headers[i] = column.Name
	}

	err = csvWriter.Write(headers)
	if err != nil {
		return err
	}

	record := make([]string, len(headers))
	for rows.Next() {
		values, err := rows.Values()
		if err != nil {
			continue // continue with the next row maybe in the future count erroneous rows
		}
		for i, value := range values {
			record[i] = anyToString(value)
		}
		err = csvWriter.Write(record)
		if err != nil {
			continue //continue with the next row
		}
	}
	csvWriter.Flush()
	if err := csvWriter.Error(); err != nil {
		return err
	}
	return nil
}

func anyToString(value any) string {
	if value == nil {
		return "NULL"
	}
	switch t := value.(type) {
	case string:
		return t
	case bool:
		if t {
			return "true"
		}
		return "false"
	case int:
		strconv.Itoa(t)
	default:
		b, err := json.Marshal(t)
		if err == nil {
			return string(b)
		}
		return fmt.Sprint(t)
	}
	return "NULL"
}

func createShadowTable(ctx context.Context, pool *pgxpool.Pool, tableName, shadowTableName, csvFilePath string) error {

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
	defer file.Close()

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
	slog.Info("Atomic table swap completed successfully", "table", originalTable, "swapDuration", swapDuration, "backupTable", backupTable)

	// Clean up backup table asynchronously
	slog.Debug("Scheduling asynchronous cleanup of backup table", "backupTable", backupTable)
	go cleanupBackupTable(pool, backupTable)

	return nil
}

// cleanupBackupTable removes the backup table in the background
func cleanupBackupTable(pool *pgxpool.Pool, backupTable string) {
	slog.Debug("Starting cleanup of backup table", "backupTable", backupTable)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cleanupStart := time.Now()
	_, err := pool.Exec(ctx, fmt.Sprintf("DROP TABLE IF EXISTS %s;", backupTable))
	if err != nil {
		slog.Error("Failed to drop backup table", "table", backupTable, "error", err, "cleanupDuration", time.Since(cleanupStart))
	} else {
		slog.Info("Successfully cleaned up backup table", "table", backupTable, "cleanupDuration", time.Since(cleanupStart))
	}
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
