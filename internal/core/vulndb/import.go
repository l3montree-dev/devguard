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

	// Create a connection pool
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		log.Fatalf("Unable to create connection pool: %v", err)
	}
	defer pool.Close()

	// read all csv files in the directory
	files, err := os.ReadDir(tmp)
	if err != nil {
		log.Fatalf("Failed to read directory: %v", err)
	}

	for _, file := range files {

		if file.IsDir() {
			continue
		}

		// check if csv
		if filepath.Ext(file.Name()) != ".csv" {
			continue
		}
		startTime := time.Now()

		csvFilePath := fmt.Sprintf("%s/%s", tmp, file.Name())

		slog.Info("Importing CSV", "file", file.Name())
		// Perform the data import
		err = importCSV(ctx, pool, strings.TrimSuffix(file.Name(), ".csv"), csvFilePath)
		if err != nil {
			log.Fatalf("%s, Failed to import CSV: %v", err, csvFilePath)
		}

		slog.Info("Imported CSV", "file", file.Name(), "duration", time.Since(startTime))
	}

	return nil
}

func importCSV(ctx context.Context, pool *pgxpool.Pool, tableName, csvFilePath string) error {
	// Open the CSV file
	file, err := os.Open(csvFilePath)
	if err != nil {
		return fmt.Errorf("failed to open CSV file: %w", err)
	}
	defer file.Close()

	// Begin a transaction
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	defer func() {
		if err != nil {
			tx.Rollback(ctx) // nolint:errcheck
		} else {
			tx.Commit(ctx) // nolint:errcheck
		}
	}()

	_, err = tx.Exec(ctx, "SET session_replication_role = 'replica';")
	if err != nil {
		return fmt.Errorf("failed to disable triggers: %w", err)
	}

	// Truncate the table
	if utils.Contains(pruneTablesBeforeInsert, tableName) {
		_, err = tx.Exec(ctx, fmt.Sprintf("TRUNCATE %s CASCADE;", tableName))
		if err != nil {
			return fmt.Errorf("failed to truncate table: %w", err)
		}

		slog.Info("Truncated table", "table", tableName)
		// paste the csv straight into the table
		// Import the CSV
		_, err = tx.Conn().PgConn().CopyFrom(ctx, file, fmt.Sprintf("COPY %s FROM STDIN WITH CSV HEADER;", tableName))
		if err != nil {
			return fmt.Errorf("failed to import CSV: %w", err)
		}
		_, err = tx.Exec(ctx, "SET session_replication_role = 'origin';")
		return nil
	}

	tx.Exec(ctx, fmt.Sprintf("CREATE TEMP TABLE tmp_%s AS SELECT * from %s LIMIT 0;", tableName, tableName)) // nolint:errcheck

	// Import the CSV
	_, err = tx.Conn().PgConn().CopyFrom(ctx, file, fmt.Sprintf("COPY tmp_%s FROM STDIN WITH CSV HEADER;", tableName))
	if err != nil {
		return fmt.Errorf("failed to import CSV: %w", err)
	}

	_, err = tx.Exec(ctx, fmt.Sprintf(`
        INSERT INTO %s
        SELECT * FROM tmp_%s
        ON CONFLICT DO NOTHING;
    `, tableName, tableName))

	_, err = tx.Exec(ctx, "SET session_replication_role = 'origin';")

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
