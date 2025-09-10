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
	"strconv"
	"strings"
	"time"

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
	configService                core.ConfigService
}

func NewImportService(cvesRepository core.CveRepository, cweRepository core.CweRepository, exploitRepository core.ExploitRepository, affectedComponentsRepository core.AffectedComponentRepository, configService core.ConfigService) *importService {
	return &importService{
		cveRepository:                cvesRepository,
		cweRepository:                cweRepository,
		exploitRepository:            exploitRepository,
		affectedComponentsRepository: affectedComponentsRepository,
		configService:                configService,
	}
}

// maps every table associated with the vulndb to their respective primary key(s) used in the diff queries
var primaryKeysFromTables = map[string][]string{"cves": {"cve"}, "cwes": {"cwe"}, "affected_components": {"id"}, "cve_affected_component": {"affected_component_id", "cvecve"}, "exploits": {"id"}}

// maps every table associated with the vulndb to their attributes we want to watch for the diff_update queries
var relevantAttributesFromTables = map[string][]string{"cves": {"date_last_modified"}, "cwes": {"description"}, "affected_components": {}, "cve_affected_component": {}, "exploits": {"*"}}

func (s importService) Import(tx core.DB, tag string) error {
	begin := time.Now()

	reg := "ghcr.io/l3montree-dev/devguard/vulndb"
	// Connect to a remote repository
	repo, err := remote.NewRepository(reg)
	if err != nil {
		return fmt.Errorf("could not connect to remote repository: %w", err)
	}

	tmp, _, err := downloadAndSaveZipToTemp(repo, tag)
	if err != nil {
		return err
	}

	//copy csv files to database
	err = s.copyCSVToDB(tmp)
	if err != nil {
		return err
	}

	slog.Info("importing vulndb completed", "duration", time.Since(begin))

	return nil
}

func (service importService) ImportFromDiff() error {
	ctx := context.Background()
	pool, err := establishConnection(ctx)
	if err != nil {
		return err
	}
	defer pool.Close()
	reg := "ghcr.io/l3montree-dev/devguard/vulndb-diff"
	// Connect to a remote repository
	repo, err := remote.NewRepository(reg)
	if err != nil {
		return fmt.Errorf("could not connect to remote repository: %w", err)
	}

	tags, err := service.GetIncrementalTags(ctx, repo)
	if err != nil {
		return err
	}
	if len(tags) == 0 {
		slog.Info("vulndb is already up to date")
		return nil
	}
	var snapshot string
	if strings.Contains(tags[0], "snapshot") {
		slog.Info("no version detected start loading latest vulndb state")
		snapshot = tags[0]
		tmp, _, err := downloadAndSaveZipToTemp(repo, snapshot)
		if err != nil {
			return err
		}

		//copy csv files to database
		err = service.copyCSVToDB(tmp)
		if err != nil {
			return err
		}
		slog.Info("finished loading latest vulndb state")
		tags = tags[1:]
	}
	begin := time.Now()
	slog.Info("start updating tags", "amount", len(tags))
	for i, tag := range tags {
		slog.Info("", "tag", tag)
		os.RemoveAll("vulndb-tmp/")
		tmp, _, err := downloadAndSaveZipToTemp(repo, tag)
		if err != nil {
			if i != 0 { // avoid out of bounds error
				service.configService.SetJSONConfig("vulndb.lastIncrementalImport", tags[i-1]) // save the last successful updated tag
			}
			slog.Error("error when trying to get diff files", "tag", tag)
			return err
		}
		dirPath := tmp + "/diffs-tmp"

		err = processDiffCSVs(ctx, dirPath, pool)
		if err != nil {
			if i != 0 { // avoid out of bounds error
				service.configService.SetJSONConfig("vulndb.lastIncrementalImport", tags[i-1]) // save the last successful updated tag
			}
			slog.Error("error when trying to update from diff files", "tag", tag)
			return err
		}
	}
	slog.Info("finished updating tags", "duration", time.Since(begin))
	if len(tags) >= 1 {
		service.configService.SetJSONConfig("vulndb.lastIncrementalImport", "{\""+tags[len(tags)-1]+"\"}")
	} else if snapshot != "" {
		service.configService.SetJSONConfig("vulndb.lastIncrementalImport", "{\""+snapshot+"\"}")
	}

	return nil
}

// read envs to connect to postgres db and returns a pgx pool for it
func establishConnection(ctx context.Context) (*pgxpool.Pool, error) {
	username := os.Getenv("POSTGRES_USER")
	password := os.Getenv("POSTGRES_PASSWORD")
	host := os.Getenv("POSTGRES_HOST")
	port := os.Getenv("POSTGRES_PORT")
	dbname := os.Getenv("POSTGRES_DB")

	// replace with your PostgreSQL connection string
	connStr := fmt.Sprintf("postgres://%s:%s@%s:%s/%s", username, password, host, port, dbname)
	// create a connection pool with increased connections for parallel processing
	config, err := pgxpool.ParseConfig(connStr)
	if err != nil {
		return nil, err
	}
	// increase pool size for parallel operations
	config.MaxConns = 10
	config.MinConns = 2

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		slog.Error("could not create pool", "err", err)
		return nil, err
	}
	return pool, nil
}

func processDiffCSVs(ctx context.Context, dirPath string, pool *pgxpool.Pool) error {
	files, err := os.ReadDir(dirPath)
	if err != nil {
		return err
	}
	for _, file := range files {
		name := file.Name()
		if filepath.Ext(name) != ".csv" {
			continue
		}
		name = strings.TrimRight(name, ".csv")
		fields := strings.Split(name, "_")
		// only handle csv files
		if len(fields) <= 2 || fields[len(fields)-2] != "diff" {
			continue
		}

		// extract table information from the name of the csv file
		mode := fields[len(fields)-1]
		table := fields[0]
		for _, field := range fields[1:(len(fields) - 2)] {
			table += "_" + field
		}

		// could be run concurrent but probably won't yield a lot of performance improvement
		switch mode {
		case "insert":
			err = processInsertDiff(ctx, pool, dirPath+"/"+name+".csv", table)
			if err != nil {
				slog.Error("could not process insert diff, continuing...", "table", table, "err", err)
				continue
			}
		case "delete":
			err = processDeleteDiff(ctx, pool, dirPath+"/"+name+".csv", table)
			if err != nil {
				slog.Error("could not process delete diff, continuing...", "table", table, "err", err)
				continue
			}
		case "update":
			err = processUpdateDiff(ctx, pool, dirPath+"/"+name+".csv", table)
			if err != nil {
				slog.Error("could not process update diff, continuing...", "table", table, "err", err)
				continue
			}
		default:
			slog.Warn("invalid mode for diff file")
		}
	}
	return nil
}

func (s importService) copyCSVToDB(tmp string) error {
	ctx := context.Background()
	pool, err := establishConnection(ctx)
	if err != nil {
		return err
	}
	defer pool.Close()

	// read all csv files in the directory
	files, err := os.ReadDir(tmp)
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
			csvFilePath := fmt.Sprintf("%s/%s", tmp, file.Name())
			tableName := strings.TrimSuffix(file.Name(), ".csv")

			slog.Info("importing CSV (prune)", "file", file, "strategy", "shadowTable")
			backupTableName, err := importCSV(ctx, pool, tableName, csvFilePath)
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
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction for foreign key fix: %w", err)
	}
	_, err = tx.Exec(ctx, `
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
 FOREIGN KEY (cve_id) REFERENCES cves(cve);`)
	if err != nil {
		return tx.Rollback(ctx)
	}

	err = tx.Commit(ctx)

	if err != nil {
		return fmt.Errorf("failed to commit foreign key fix transaction: %w", err)
	}

	for _, backupTableName := range backupTableNames {
		cleanupBackupTable(pool, backupTableName)
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

func importCSV(ctx context.Context, pool *pgxpool.Pool, tableName, csvFilePath string) (string, error) {
	// Use shadow table pattern for pruned tables to minimize downtime
	if os.Getenv("MAKE_DIFF_TABLES") == "true" {
		_, err := importWithShadowTable(ctx, pool, tableName, csvFilePath)
		if err != nil {
			return "", err
		}
		err = createShadowTable(ctx, pool, tableName, tableName+"_diff", csvFilePath)
		return "", err
	} else {
		return importWithShadowTable(ctx, pool, tableName, csvFilePath)
	}
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

// importWithShadowTable: Create shadow table → Import → Atomic swap → Cleanup
// This keeps the original table available during most of the import process
func importWithShadowTable(ctx context.Context, pool *pgxpool.Pool, tableName, csvFilePath string) (string, error) {
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

// cleanupBackupTable removes the backup table in the background
func cleanupBackupTable(pool *pgxpool.Pool, backupTable string) {
	slog.Debug("Starting cleanup of backup table", "backupTable", backupTable)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cleanupStart := time.Now()
	_, err := pool.Exec(ctx, fmt.Sprintf("DROP TABLE IF EXISTS %s CASCADE;", backupTable))
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

func processInsertDiff(ctx context.Context, pool *pgxpool.Pool, filePath string, tableName string) error {
	slog.Info(fmt.Sprintf("start inserting for table=%s", tableName))
	fd, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer fd.Close()
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()

	_, err = conn.Conn().PgConn().CopyFrom(ctx, fd, fmt.Sprintf("COPY %s FROM STDIN WITH (FORMAT csv, HEADER true, NULL 'NULL')", tableName))
	if err != nil {
		slog.Error("error when trying to insert into table", "err", err)
		return err
	}
	slog.Info("insert completed")
	return nil
}

func processDeleteDiff(ctx context.Context, pool *pgxpool.Pool, filePath string, tableName string) error {
	slog.Info(fmt.Sprintf("start deleting for table=%s", tableName))
	fd, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer fd.Close()
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()

	csvReader := csv.NewReader(fd)
	allRecords, err := csvReader.ReadAll() // could use rows.Next() to hold less space in memory
	if err != nil {
		return err
	}

	if len(allRecords) == 0 {
		slog.Info("nothing to delete", "table", tableName)
		return nil
	}

	primaryKeys := primaryKeysFromTables[tableName]
	if len(primaryKeys) == 0 {
		slog.Error("could not determine primary key(s)", "table", tableName)
		return fmt.Errorf("could not determine primary key(s) for table: %s", tableName)
	}

	// sql needs to be adjusted based on the number of primary keys
	allRecords = allRecords[1:] // cut off the header row
	if len(primaryKeys) == 1 {
		primaryKey := primaryKeys[0]
		for i := range allRecords {
			key := allRecords[i][0]
			sql := fmt.Sprintf("DELETE FROM %s WHERE %s.%s = %s", tableName, tableName, primaryKey, "'"+key+"'")
			_, err := conn.Exec(ctx, sql)
			if err != nil {
				slog.Error("error when deleting from table", "table", tableName, "id", key)
				continue
			}
		}
	} else {
		primaryKey1 := primaryKeys[0]
		primaryKey2 := primaryKeys[1]
		for i := range allRecords {
			key1 := allRecords[i][0]
			key2 := allRecords[i][1]
			sql := fmt.Sprintf("DELETE FROM %s WHERE %s = %s AND %s = %s", tableName, primaryKey1, "'"+key1+"'", primaryKey2, "'"+key2+"'")
			_, err := conn.Exec(ctx, sql)
			if err != nil {
				slog.Error("error when deleting from table", "table", tableName, "id1", key1, "id2", key2)
				continue
			}
		}
	}
	slog.Info("delete completed")
	return nil
}

func processUpdateDiff(ctx context.Context, pool *pgxpool.Pool, filePath string, tableName string) error {
	slog.Info(fmt.Sprintf("start updating for table=%s", tableName))
	fd, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer fd.Close()
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()

	csvReader := csv.NewReader(fd)
	record, err := csvReader.Read() // read all the column names from the header row
	if err != nil {
		return err
	}

	primaryKeys := primaryKeysFromTables[tableName]
	if len(primaryKeys) == 0 {
		slog.Error("could not determine primary key(s)", "table", tableName)
		return fmt.Errorf("could not determine primary key(s) for table: %s", tableName)
	}

	columnsToUpdate := record[len(primaryKeys):] // exclude primary key(s)
	for i, column := range columnsToUpdate {
		columnsToUpdate[i] = fmt.Sprintf("\"%s\" = EXCLUDED.%s", column, column) // escape possible sql syntax column names with ""
	}
	assignSQL := strings.Join(columnsToUpdate, ", ")

	tmpTable := tableName + "_tmp_" + strconv.Itoa(int(time.Now().Unix()))

	_, err = conn.Conn().Exec(ctx, fmt.Sprintf("CREATE TABLE %s (LIKE %s INCLUDING ALL);", tmpTable, tableName))
	if err != nil {
		slog.Error("error when trying to create tmp table used for updating", "table", tableName, "err", err)
		return err
	}
	defer conn.Conn().Exec(ctx, fmt.Sprintf("DROP TABLE %s;", tmpTable))

	fd, err = os.Open(filePath) // reopen csv file since we read from it once already
	if err != nil {
		return err
	}

	_, err = conn.Conn().PgConn().CopyFrom(ctx, fd, fmt.Sprintf("COPY %s FROM STDIN WITH (FORMAT csv, HEADER true, NULL 'NULL')", tmpTable))
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

	if _, err := conn.Exec(ctx, upsertSQL); err != nil {
		slog.Error("could not insert from tmp table to original table", "table", tableName, "err", err)
		return err
	}
	slog.Info("update completed")

	return nil
}

// downloads the fileName with the tag from the devguard package master, verifies the signature and unzips it into tmp Folder
func downloadAndSaveZipToTemp(repo *remote.Repository, tag string) (string, *file.Store, error) {
	slog.Info("importing vulndb started")
	tmp := "./vulndb-tmp"
	sigFile := tmp + "/vulndb.zip.sig"
	blobFile := tmp + "/vulndb.zip"
	pubKeyFile := "cosign.pub"

	ctx := context.Background()

	fs, err := file.New(tmp)
	if err != nil {
		panic(err)
	}

	// import the vulndb csv to the file store
	err = copyCSVFromRemoteToLocal(ctx, repo, tag, fs)
	if err != nil {
		return tmp, fs, fmt.Errorf("could not copy csv from remote to local: %w", err)
	}

	// verify the signature of the imported data
	err = verifySignature(pubKeyFile, sigFile, blobFile, ctx)
	if err != nil {
		return tmp, fs, fmt.Errorf("could not verify signature: %w", err)
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
		return tmp, fs, fmt.Errorf("error when trying to build zip file: %w", err)
	}
	slog.Info("unzipping vulndb completed")
	return tmp, fs, nil
}

func (service importService) GetIncrementalTags(ctx context.Context, repo *remote.Repository) ([]string, error) {
	var allTags []string = make([]string, 0, 3000)
	var lastVersion string
	err := service.configService.GetJSONConfig("vulndb.lastIncrementalImport", &lastVersion)
	if err != nil || lastVersion == "" {
		// we do not have a database version yet, we get the latest snapshot and each incremental update since then
		repo.TagListPageSize = 1000
		var index int
		err = repo.Tags(ctx, "", func(tags []string) error {
			for i := range tags {
				if strings.Contains(tags[len(tags)-1-i], "snapshot") && !strings.Contains(tags[len(tags)-1-i], ".sig") {
					index = len(tags) - 1 - i
				}
			}
			for index < len(tags) {
				if !strings.Contains(tags[index], ".sig") {
					allTags = append(allTags, tags[index])
				}
				index++
			}
			return nil
		})
		return allTags, nil
	}

	repo.TagListPageSize = 1000
	err = repo.Tags(ctx, lastVersion, func(tags []string) error {
		for _, tag := range tags {
			if !strings.Contains(tag, ".") {
				_, err := strconv.Atoi(tag)
				if err == nil {
					allTags = append(allTags, tag)
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	if len(allTags) >= 2 && !slices.IsSorted(allTags) {
		slog.Error("slice not sorted")
		return nil, fmt.Errorf("slice not sorted")
	}
	return allTags, nil
}

func MakeSnapshot(ctx context.Context) error {
	vulndb := "ghcr.io/l3montree-dev/devguard/vulndb"
	vulndbDiff := "ghcr.io/l3montree-dev/devguard/vulndb-diffs"
	repo, err := remote.NewRepository(vulndb)
	if err != nil {
		slog.Error("could not create vulndb repository")
		return err
	}
	repoDiff, err := remote.NewRepository(vulndbDiff)
	if err != nil {
		slog.Error("could not create vulndb-diff repository")
		return err
	}

	_, fs, err := downloadAndSaveZipToTemp(repo, "latest")
	if err != nil {
		if fs != nil {
			fs.Close()
		}
		return err
	}
	defer fs.Close()

	_, err = oras.Copy(ctx, fs, "latest", repoDiff, "latest", oras.DefaultCopyOptions)
	if err != nil {
		slog.Error("could not copy to remote repository", "err", err)
		return err
	}
	slog.Info("successfully made snapshot")
	return nil
}
