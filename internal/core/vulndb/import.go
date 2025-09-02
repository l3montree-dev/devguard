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
	"sync"
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

	// unzip the blob file
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
ALTER TABLE dependency_vulns DROP CONSTRAINT fk_dependency_vulns_cve;

-- Set cve_id to NULL where the referenced CVE doesn't exist anymore
UPDATE dependency_vulns 
SET cve_id = NULL 
WHERE cve_id IS NOT NULL 
  AND NOT EXISTS (
    SELECT 1 FROM cves WHERE cves.cve = dependency_vulns.cve_id
  );

-- Now recreate the foreign key constraint
ALTER TABLE dependency_vulns ADD CONSTRAINT fk_dependency_vulns_cve 
  FOREIGN KEY (cve_id) REFERENCES cves(cve);

-- Drop the foreign key constraint (if it exists)
ALTER TABLE cve_cpe_match DROP CONSTRAINT IF EXISTS fk_cve_cpe_match_cve;

-- Clean up orphaned rows
DELETE FROM cve_cpe_match 
WHERE NOT EXISTS (
    SELECT 1 FROM cves WHERE cves.cve = cve_cpe_match.cvecve
);

-- Recreate the foreign key constraint
ALTER TABLE cve_cpe_match ADD CONSTRAINT fk_cve_cpe_match_cve 
  FOREIGN KEY (cvecve) REFERENCES cves(cve);

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

	var wg sync.WaitGroup
	// now drop the backup tables asynchronously
	for _, backupTableName := range backupTableNames {
		wg.Go(func() {
			cleanupBackupTable(pool, backupTableName)
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

func importCSV(ctx context.Context, pool *pgxpool.Pool, tableName, csvFilePath string) (string, error) {
	// Use shadow table pattern for pruned tables to minimize downtime
	return importWithShadowTable(ctx, pool, tableName, csvFilePath)
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
	tx, err := pool.Begin(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to begin transaction: %w", err)
	}
	var committed = false
	defer func() {
		if !committed {
			tx.Rollback(ctx) // nolint:errcheck
		}
	}()

	slog.Debug("Creating shadow table", "shadowTable", shadowTable, "originalTable", tableName)
	// Create shadow table with same structure
	_, err = tx.Exec(ctx, fmt.Sprintf("CREATE TABLE %s (LIKE %s INCLUDING ALL);", shadowTable, tableName))
	if err != nil {
		return "", fmt.Errorf("failed to create shadow table: %w", err)
	}

	slog.Debug("Disabling triggers for faster import", "table", shadowTable)
	// Fast import with disabled triggers
	_, err = tx.Exec(ctx, "SET session_replication_role = 'replica';")
	if err != nil {
		return "", fmt.Errorf("failed to disable triggers: %w", err)
	}

	file, err := os.Open(csvFilePath)
	if err != nil {
		return "", fmt.Errorf("failed to open CSV file: %w", err)
	}
	defer file.Close()

	slog.Info("Starting CSV data import to shadow table", "shadowTable", shadowTable)
	importStart := time.Now()
	_, err = tx.Conn().PgConn().CopyFrom(ctx, file, fmt.Sprintf("COPY %s FROM STDIN WITH CSV HEADER;", shadowTable))
	if err != nil {
		return "", fmt.Errorf("failed to import CSV: %w", err)
	}
	slog.Info("Completed CSV data import to shadow table", "shadowTable", shadowTable, "importDuration", time.Since(importStart))

	slog.Debug("Re-enabling triggers", "table", shadowTable)
	_, err = tx.Exec(ctx, "SET session_replication_role = 'origin';")
	if err != nil {
		return "", fmt.Errorf("failed to re-enable triggers: %w", err)
	}

	commitStart := time.Now()
	err = tx.Commit(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to commit shadow table: %w", err)
	}
	committed = true
	slog.Debug("Committed shadow table transaction", "shadowTable", shadowTable, "commitDuration", time.Since(commitStart))

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
