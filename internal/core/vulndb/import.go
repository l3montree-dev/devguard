package vulndb

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"

	"gorm.io/gorm"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/file"
	"oras.land/oras-go/v2/registry/remote"
)

type cvesRepository interface {
	repositories.Repository[string, models.CVE, database.DB]
	GetAllCVEsID() ([]string, error)
	GetAllCPEMatchesID() ([]string, error)
	Save(tx database.DB, cve *models.CVE) error
	SaveBatchCPEMatch(tx database.DB, matches []models.CPEMatch) error
	SaveCveAffectedComponents(tx core.DB, cveId string, affectedComponentHashes []string) error
}
type cwesRepository interface {
	GetAllCWEsID() ([]string, error)
	SaveBatch(tx database.DB, cwes []models.CWE) error
}

type exploitsRepository interface {
	GetAllExploitsID() ([]string, error)
	SaveBatch(tx core.DB, exploits []models.Exploit) error
}

type affectedComponentsRepository interface {
	GetAllAffectedComponentsID() ([]string, error)
	Save(tx database.DB, affectedComponent *models.AffectedComponent) error
	SaveBatch(tx core.DB, affectedPkgs []models.AffectedComponent) error
}
type importService struct {
	cveRepository                cvesRepository
	cweRepository                cwesRepository
	exploitRepository            exploitsRepository
	affectedComponentsRepository affectedComponentsRepository
}

type configService interface {
	GetJSONConfig(key string, v any) error
	SetJSONConfig(key string, v any) error
}

type leaderElector interface {
	IfLeader(ctx context.Context, fn func() error)
}

func StartMirror(db core.DB, leaderElector leaderElector, configService configService) {
	cveRepository := repositories.NewCVERepository(db)
	cweRepository := repositories.NewCWERepository(db)
	exploitsRepository := repositories.NewExploitRepository(db)
	affectedComponentsRepository := repositories.NewAffectedComponentRepository(db)

	v := NewImportService(cveRepository, cweRepository, exploitsRepository, affectedComponentsRepository)
	leaderElector.IfLeader(context.Background(), func() error {
		var lastMirror struct {
			Time time.Time `json:"time"`
		}

		err := configService.GetJSONConfig("vulndb.lastMirror", &lastMirror)
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			slog.Error("could not get last mirror time", "err", err)
			return nil
		} else if errors.Is(err, gorm.ErrRecordNotFound) {
			slog.Info("no last mirror time found. Setting to 0")
			lastMirror.Time = time.Time{}
		}

		if time.Since(lastMirror.Time) > 2*time.Hour {
			slog.Info("last mirror was more than 2 hours ago. Starting mirror process")

			if err := v.Import(db, "latest"); err != nil {
				slog.Error("could not import vulndb", "err", err)
			}
		} else {
			slog.Info("last mirror was less than 2 hours ago. Not mirroring", "lastMirror", lastMirror.Time, "now", time.Now())
		}
		slog.Info("done. Waiting for 2 hours to check again")
		time.Sleep(2 * time.Hour)
		return nil
	})
}

func NewImportService(cvesRepository cvesRepository, cweRepository cwesRepository, exploitRepository exploitsRepository, affectedComponentsRepository affectedComponentsRepository) *importService {
	return &importService{
		cveRepository:                cvesRepository,
		cweRepository:                cweRepository,
		exploitRepository:            exploitRepository,
		affectedComponentsRepository: affectedComponentsRepository,
	}
}

func (s importService) Import(tx database.DB, tag string) error {
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

	if err != nil {
		return fmt.Errorf("failed to lock table: %w", err)
	}

	_, err = tx.Exec(ctx, "SET session_replication_role = 'replica';")
	if err != nil {
		return fmt.Errorf("failed to disable triggers: %w", err)
	}

	// Truncate the table
	/*_, err = tx.Exec(ctx, fmt.Sprintf("DELETE FROM %s;", tableName))
	if err != nil {
		return fmt.Errorf("failed to truncate table: %w", err)
	}*/

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
