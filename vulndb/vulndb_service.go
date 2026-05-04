package vulndb

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/klauspost/compress/zstd"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
	"golang.org/x/sync/errgroup"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/file"
	"oras.land/oras-go/v2/registry/remote"
)

func writeGobFile(object any, fileName string) error {
	gobFile, err := os.Create(fileName)
	if err != nil {
		return fmt.Errorf("could not create gob file: %w", err)
	}
	defer gobFile.Close()
	if err := gob.NewEncoder(gobFile).Encode(object); err != nil {
		return fmt.Errorf("could not encode object to gob file: %w", err)
	}
	return nil
}

// VulnDBService orchestrates the full vulnerability database export and import,
// covering OSV, EPSS, CISA KEV, exploits (ExploitDB + GitHub PoC),
// and malicious packages.
type VulnDBService struct {
	osv               osvService
	epss              epssService
	cisaKEV           cisaKEVService
	githubExploits    githubExploitDBService
	exploitDB         exploitDBService
	maliciousPackages *MaliciousPackageChecker
	exploitRepository shared.ExploitRepository
	cveRepository     shared.CveRepository
	configService     shared.ConfigService
	pool              *pgxpool.Pool
}

func NewVulnDBService(
	cveRepository shared.CveRepository,
	cveRelationshipRepository shared.CVERelationshipRepository,
	affectedCmpRepository shared.AffectedComponentRepository,
	exploitRepository shared.ExploitRepository,
	maliciousPackageChecker *MaliciousPackageChecker,
	configService shared.ConfigService,
	pool *pgxpool.Pool,
) *VulnDBService {
	return &VulnDBService{
		osv:               NewOSVService(affectedCmpRepository, cveRepository, cveRelationshipRepository, configService, pool),
		epss:              NewEPSSService(cveRepository, cveRelationshipRepository),
		cisaKEV:           NewCISAKEVService(cveRepository, cveRelationshipRepository),
		githubExploits:    NewGithubExploitDBService(exploitRepository),
		exploitDB:         NewExploitDBService(exploitRepository),
		maliciousPackages: maliciousPackageChecker,
		exploitRepository: exploitRepository,
		cveRepository:     cveRepository,
		configService:     configService,
		pool:              pool,
	}
}

// ExportRC fetches all vulnerability data sources, writes gob files for each,
// populates the database, and writes a full integrity_checks.json.
func (s *VulnDBService) ExportRC(ctx context.Context) error {
	slog.Info("start vulndb export")
	start := time.Now()

	group, groupCtx := errgroup.WithContext(ctx)

	group.Go(func() error {
		osvEntries, err := s.osv.fetchOSVEntries(groupCtx, start)
		if err != nil {
			return fmt.Errorf("OSV fetch failed: %w", err)
		}
		if err := writeGobFile(osvEntries, "osv.gob"); err != nil {
			return fmt.Errorf("could not write OSV gob: %w", err)
		}
		slog.Info("wrote osv.gob", "entries", len(osvEntries))
		return nil
	})

	group.Go(func() error {
		slog.Info("fetching EPSS data")
		epssData, err := s.epss.Fetch(groupCtx)
		if err != nil {
			return fmt.Errorf("could not fetch EPSS data: %w", err)
		}
		if err := writeGobFile(epssData, "epss.gob"); err != nil {
			return fmt.Errorf("could not write EPSS gob: %w", err)
		}
		slog.Info("wrote epss.gob", "entries", len(epssData))
		return nil
	})

	group.Go(func() error {
		slog.Info("fetching CISA KEV data")
		kevFetchCtx, kevCancel := context.WithTimeout(groupCtx, 30*time.Second)
		defer kevCancel()
		kevCVEs, err := s.cisaKEV.Fetch(kevFetchCtx)
		if err != nil {
			return fmt.Errorf("could not fetch CISA KEV data: %w", err)
		}
		if err := writeGobFile(cisaKEVEntriesToGob(kevCVEs), "cisakev.gob"); err != nil {
			return fmt.Errorf("could not write CISA KEV gob: %w", err)
		}
		slog.Info("wrote cisakev.gob", "entries", len(kevCVEs))
		return nil
	})

	group.Go(func() error {
		slog.Info("fetching exploit data")
		exploitFetchCtx, exploitCancel := context.WithTimeout(groupCtx, 5*time.Minute)
		defer exploitCancel()
		edbExploits, err := s.exploitDB.Fetch(exploitFetchCtx)
		if err != nil {
			return fmt.Errorf("could not fetch ExploitDB data: %w", err)
		}

		ghFetchCtx, ghCancel := context.WithTimeout(groupCtx, 10*time.Minute)
		defer ghCancel()
		ghExploits, err := s.githubExploits.Fetch(ghFetchCtx)
		if err != nil {
			return fmt.Errorf("could not fetch GitHub exploit data: %w", err)
		}

		allExploits := make([]GobExploit, 0, len(edbExploits)+len(ghExploits))
		for _, e := range edbExploits {
			allExploits = append(allExploits, exploitToGob(e))
		}
		for _, e := range ghExploits {
			allExploits = append(allExploits, exploitToGob(e))
		}
		if err := writeGobFile(allExploits, "exploits.gob"); err != nil {
			return fmt.Errorf("could not write exploits gob: %w", err)
		}
		slog.Info("wrote exploits.gob", "entries", len(allExploits))
		return nil
	})

	group.Go(func() error {
		slog.Info("fetching malicious packages")
		packages, components, err := s.maliciousPackages.FetchAll(groupCtx)
		if err != nil {
			return fmt.Errorf("could not fetch malicious packages: %w", err)
		}
		if err := writeGobFile(malPackagesExportToGob(packages, components), "maliciouspackages.gob"); err != nil {
			return fmt.Errorf("could not write malicious packages gob: %w", err)
		}
		slog.Info("wrote maliciouspackages.gob", "packages", len(packages), "components", len(components))
		return nil
	})

	if err := group.Wait(); err != nil {
		return err
	}

	// --- Integrity check (covers all tables including exploits + malicious) ---
	tableIntegrity, err := calculateTotalIntegrityInformation(ctx, s.pool)
	if err != nil {
		return fmt.Errorf("could not calculate integrity information: %w", err)
	}
	slices.SortFunc(tableIntegrity, func(a, b tableIntegrityInformation) int {
		return strings.Compare(a.TableName, b.TableName)
	})

	integrityFD, err := os.Create("integrity_checks.json")
	if err != nil {
		return fmt.Errorf("could not create integrity_checks.json: %w", err)
	}
	defer integrityFD.Close()

	jsonContents, err := json.Marshal(integrityInformation{TableIntegrity: tableIntegrity, ImportTimestamp: start})
	if err != nil {
		return fmt.Errorf("could not marshal integrity information: %w", err)
	}
	if _, err := integrityFD.Write(jsonContents); err != nil {
		return fmt.Errorf("could not write integrity_checks.json: %w", err)
	}

	if err := writeVulnDBTarZst("vulndb.tar.zst", []string{
		"osv.gob",
		"epss.gob",
		"cisakev.gob",
		"exploits.gob",
		"maliciouspackages.gob",
		"integrity_checks.json",
	}); err != nil {
		return fmt.Errorf("could not write vulndb tar: %w", err)
	}
	slog.Info("wrote vulndb.tar.zst")

	slog.Info("finished vulndb export", "time", time.Since(start))
	return nil
}

// ImportRC pulls the latest vulndb artifact from the OCI registry and applies
// all data sources (OSV, CISA KEV, exploits, malicious packages) to the database.
func (s *VulnDBService) ImportRC(ctx context.Context) error {
	slog.Info("start vulndb import")
	start := time.Now()

	workingDir, err := pullVulnDBFromPackageRegistry(ctx)
	if err != nil {
		return fmt.Errorf("could not pull from remote repository: %w", err)
	}
	defer os.RemoveAll(workingDir)

	var lastImportTime time.Time
	var lastImportStr string
	if err := s.configService.GetJSONConfig(ctx, "vulndb.lastRCImport", &lastImportStr); err == nil {
		lastImportTime, _ = time.Parse(time.RFC3339Nano, lastImportStr)
	}

	// --- OSV ---
	slog.Info("applying OSV data")
	var osvEntries []OSVEntry
	if err := readGobFile(workingDir+"/osv.gob", &osvEntries); err != nil {
		return fmt.Errorf("could not read OSV gob: %w", err)
	}
	slog.Info("decoded OSV gob file", "amount", len(osvEntries))
	if err := s.osv.applyOSVEntries(ctx, osvEntries); err != nil {
		return fmt.Errorf("OSV import failed: %w", err)
	}

	// Decode and transform the standalone gob payloads in parallel before opening the transaction.
	group, _ := errgroup.WithContext(ctx)
	var (
		epssModels []models.CVE
		kevModels  []models.CVE
		exploits   []models.Exploit
		pkgs       []models.MaliciousPackage
		comps      []models.MaliciousAffectedComponent
	)
	group.Go(func() error {
		var epssData map[string]dtos.EPSS
		if err := readGobFile(workingDir+"/epss.gob", &epssData); err != nil {
			return fmt.Errorf("could not read EPSS gob: %w", err)
		}
		epssModels = make([]models.CVE, 0, len(epssData))
		for cveID, e := range epssData {
			epss := e.EPSS
			pct := float32(e.Percentile)
			epssModels = append(epssModels, models.CVE{CVE: cveID, EPSS: &epss, Percentile: &pct})
		}
		return nil
	})
	group.Go(func() error {
		var kevEntries []CISAKEVEntry
		if err := readGobFile(workingDir+"/cisakev.gob", &kevEntries); err != nil {
			return fmt.Errorf("could not read CISA KEV gob: %w", err)
		}
		kevModels = gobCISAKEVEntriesToModels(kevEntries)
		return nil
	})
	group.Go(func() error {
		var gobExploits []GobExploit
		if err := readGobFile(workingDir+"/exploits.gob", &gobExploits); err != nil {
			return fmt.Errorf("could not read exploits gob: %w", err)
		}
		exploits = gobExploitsToModels(gobExploits)
		if lastImportTime != (time.Time{}) {
			filtered := exploits[:0]
			for _, e := range exploits {
				if e.Updated != nil && e.Updated.After(lastImportTime) {
					filtered = append(filtered, e)
				}
			}
			exploits = filtered
		}
		return nil
	})
	group.Go(func() error {
		var malExport GobMaliciousPackagesExport
		if err := readGobFile(workingDir+"/maliciouspackages.gob", &malExport); err != nil {
			return fmt.Errorf("could not read malicious packages gob: %w", err)
		}
		pkgs, comps = gobMalPackagesExportToModels(malExport, lastImportTime)
		return nil
	})
	if err := group.Wait(); err != nil {
		return err
	}

	// Apply everything in a single transaction.
	tx := s.cveRepository.Begin(ctx)
	defer tx.Rollback()

	slog.Info("applying EPSS data")
	if err := s.cveRepository.UpdateEpssBatch(ctx, tx, epssModels); err != nil {
		return fmt.Errorf("could not apply EPSS data: %w", err)
	}
	slog.Info("applied EPSS data", "entries", len(epssModels))

	slog.Info("applying CISA KEV data")
	if err := s.cisaKEV.Apply(ctx, tx, kevModels); err != nil {
		return fmt.Errorf("could not apply CISA KEV data: %w", err)
	}
	slog.Info("applied CISA KEV data", "entries", len(kevModels))

	slog.Info("applying exploit data")
	if err := s.exploitRepository.SaveBatch(ctx, tx, exploits); err != nil {
		return fmt.Errorf("could not apply exploit data: %w", err)
	}
	slog.Info("applied exploit data", "entries", len(exploits))

	slog.Info("applying malicious packages")
	if err := s.maliciousPackages.ApplyToDB(ctx, tx, pkgs, comps); err != nil {
		return fmt.Errorf("could not apply malicious packages: %w", err)
	}
	slog.Info("applied malicious packages", "packages", len(pkgs), "components", len(comps))

	if err := tx.Commit().Error; err != nil {
		return fmt.Errorf("could not commit import transaction: %w", err)
	}

	// --- Integrity validation ---
	localIntegrity, err := calculateTotalIntegrityInformation(ctx, s.pool)
	if err != nil {
		return fmt.Errorf("could not calculate integrity information: %w", err)
	}
	valid, databaseStateTime, err := validateIntegrityInformation(workingDir, localIntegrity)
	if err != nil {
		return fmt.Errorf("could not validate integrity: %w", err)
	}
	if !valid {
		return fmt.Errorf("integrity validation failed")
	}
	slog.Info("successfully validated checksums")

	if err := s.configService.SetJSONConfig(ctx, "vulndb.lastRCImport", databaseStateTime.Format(time.RFC3339Nano)); err != nil {
		return fmt.Errorf("could not update last import time: %w", err)
	}

	slog.Info("finished vulndb import", "time", time.Since(start))
	return nil
}

// readGobFile is the counterpart of writeGobFile — decodes a plain gob file.
func readGobFile(path string, out any) error {
	fd, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("could not open gob file %s: %w", path, err)
	}
	defer fd.Close()
	if err := gob.NewDecoder(fd).Decode(out); err != nil {
		return fmt.Errorf("could not decode gob file %s: %w", path, err)
	}
	return nil
}

func writeVulnDBTarZst(tarZstFileName string, fileNames []string) error {
	outFile, err := os.Create(tarZstFileName)
	if err != nil {
		return fmt.Errorf("could not create tar.zst file: %w", err)
	}
	defer outFile.Close()

	zstdWriter, err := zstd.NewWriter(outFile,
		zstd.WithEncoderLevel(zstd.EncoderLevelFromZstd(22)),
		zstd.WithWindowSize(zstd.MaxWindowSize),
	)
	if err != nil {
		return fmt.Errorf("could not create zstd writer: %w", err)
	}
	defer zstdWriter.Close()

	tarWriter := tar.NewWriter(zstdWriter)
	defer tarWriter.Close()

	for _, fileName := range fileNames {
		inputFile, err := os.Open(fileName)
		if err != nil {
			return fmt.Errorf("could not open %s: %w", fileName, err)
		}

		info, err := inputFile.Stat()
		if err != nil {
			inputFile.Close()
			return fmt.Errorf("could not stat %s: %w", fileName, err)
		}

		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			inputFile.Close()
			return fmt.Errorf("could not build tar header for %s: %w", fileName, err)
		}
		header.Name = filepath.Base(fileName)

		if err := tarWriter.WriteHeader(header); err != nil {
			inputFile.Close()
			return fmt.Errorf("could not create tar entry for %s: %w", fileName, err)
		}
		if _, err := io.Copy(tarWriter, inputFile); err != nil {
			inputFile.Close()
			return fmt.Errorf("could not write %s to tar: %w", fileName, err)
		}
		if err := inputFile.Close(); err != nil {
			return fmt.Errorf("could not close %s: %w", fileName, err)
		}
	}

	if err := tarWriter.Close(); err != nil {
		return fmt.Errorf("could not finalize tar file: %w", err)
	}
	return nil
}

func untarZstd(src, dest string) error {
	fd, err := os.Open(src)
	if err != nil {
		return err
	}
	defer fd.Close()

	zstdReader, err := zstd.NewReader(fd)
	if err != nil {
		return fmt.Errorf("could not create zstd reader: %w", err)
	}
	defer zstdReader.Close()

	tarReader := tar.NewReader(zstdReader)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			return nil
		}

		if err != nil {
			return err
		}

		fpath := filepath.Join(dest, header.Name)
		if header.FileInfo().IsDir() {
			if err := os.MkdirAll(fpath, os.ModePerm); err != nil {
				return err
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
			return err
		}

		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, header.FileInfo().Mode())
		if err != nil {
			return err
		}

		if _, err := io.Copy(outFile, tarReader); err != nil {
			outFile.Close()
			return err
		}
		if err := outFile.Close(); err != nil {
			return err
		}
	}
}

func pullVulnDBFromPackageRegistry(ctx context.Context) (string, error) {
	reg := "ghcr.io/l3montree-dev/devguard/vulndb/v2"
	repo, err := remote.NewRepository(reg)
	if err != nil {
		return "", fmt.Errorf("could not connect to remote repository: %w", err)
	}

	outpath, err := os.MkdirTemp("", "vulndb")
	if err != nil {
		return "", fmt.Errorf("could not create temp directory: %w", err)
	}

	fs, err := file.New(outpath)
	if err != nil {
		os.RemoveAll(outpath)
		return "", fmt.Errorf("could not create file store: %w", err)
	}

	// pull the single tar.zst artifact and unpack it locally before reading the gob files
	const tag = "latest"
	if _, err = oras.Copy(ctx, repo, tag, fs, vulnDBArchiveName, oras.DefaultCopyOptions); err != nil {
		os.RemoveAll(outpath)
		return "", fmt.Errorf("could not copy artifact from remote repository: %w", err)
	}

	// pull the matching signatures (one .sig per file) from the sibling tag
	const sigTag = tag + ".sig"
	if _, err = oras.Copy(ctx, repo, sigTag, fs, vulnDBArchiveName+".sig", oras.DefaultCopyOptions); err != nil {
		os.RemoveAll(outpath)
		return "", fmt.Errorf("could not copy signatures from remote repository: %w", err)
	}

	if err := verifySignature(ctx, vulnDBPubKeyFile, outpath+"/"+vulnDBArchiveName+".sig", outpath+"/"+vulnDBArchiveName); err != nil {
		os.RemoveAll(outpath)
		return "", fmt.Errorf("could not verify signature for %s: %w", vulnDBArchiveName, err)
	}

	if err := untarZstd(outpath+"/"+vulnDBArchiveName, outpath+"/"); err != nil {
		os.RemoveAll(outpath)
		return "", fmt.Errorf("could not untar vulndb archive: %w", err)
	}
	slog.Info("successfully verified and untarred vulndb archive")
	return outpath, nil
}

func verifySignature(ctx context.Context, pubKeyFile string, sigFile string, blobFile string) error {
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

type tableIntegrityInformation struct {
	TableName  string `json:"table_name"`
	Checksum   []byte `json:"checksum"`
	TotalCount int    `json:"total_count"`
}

type integrityInformation struct {
	TableIntegrity  []tableIntegrityInformation `json:"table_integrity"`
	ImportTimestamp time.Time                   `json:"import_timestamp"`
}

func validateIntegrityInformation(workingDir string, localIntegrityInformation []tableIntegrityInformation) (bool, time.Time, error) {
	fd, err := os.Open(workingDir + "/integrity_checks.json")
	if err != nil {
		return false, time.Time{}, fmt.Errorf("could not open integrity check json file: %w", err)
	}

	var groundTruth integrityInformation
	err = json.NewDecoder(fd).Decode(&groundTruth)
	if err != nil {
		return false, time.Time{}, fmt.Errorf("could not decode remote integrity information")
	}

	for _, tableIntegrity := range localIntegrityInformation {
		found := false
		for _, tableGroundTruth := range groundTruth.TableIntegrity {
			if tableGroundTruth.TableName == tableIntegrity.TableName {
				if !tableIntegrity.isEqual(tableGroundTruth) {
					slog.Error("invalid checksum when importing", "table", tableIntegrity.TableName)
					return false, time.Time{}, nil
				} else {
					found = true
					break
				}
			}
		}
		if !found {
			return false, time.Time{}, fmt.Errorf("could not find integrity information for table %s", tableIntegrity.TableName)
		}
	}
	return true, groundTruth.ImportTimestamp, nil
}
func calculateTotalIntegrityInformation(ctx context.Context, pool *pgxpool.Pool) ([]tableIntegrityInformation, error) {

	queries := map[string]string{
		"cves": `
			SELECT count(*) AS row_count,
			       md5(string_agg(row_hash, '' ORDER BY id)) AS checksum
			FROM (
				SELECT id, md5(
					coalesce(id::text, '\0') || '|' ||
					coalesce(description, '\0') || '|' ||
					coalesce(cvss::text, '\0') || '|' ||
					coalesce(vector, '\0')
				) AS row_hash
				FROM cves
			) sub;`,

		"cve_relationships": `
			SELECT count(*) AS row_count,
			       md5(string_agg(row_hash, '' ORDER BY source_cve, target_cve, relationship_type)) AS checksum
			FROM (
				SELECT source_cve, target_cve, relationship_type, md5(
					source_cve || '|' || target_cve || '|' || relationship_type
				) AS row_hash
				FROM cve_relationships
			) sub;`,

		"cve_affected_component": `
			SELECT count(*) AS row_count,
			       md5(
				   count(*)::text || '|' ||
				   coalesce(bit_xor(hashtextextended(cve_id::text || '|' || affected_component_id::text, 0))::text, '0') || '|' ||
				   coalesce(bit_xor(hashtextextended(cve_id::text || '|' || affected_component_id::text, 1))::text, '0')
			   ) AS checksum
			FROM cve_affected_component;`,

		"affected_components": `
			SELECT count(*) AS row_count,
			       md5(string_agg(id::text, '' ORDER BY id)) AS checksum
			FROM affected_components;`,

		"exploits": `
			SELECT count(*) AS row_count,
			       md5(string_agg(row_hash, '' ORDER BY id, cve_id, source_url, row_hash)) AS checksum
			FROM (
				SELECT id, md5(
					coalesce(id, '\0') || '|' ||
					coalesce(cve_id, '\0') || '|' ||
					coalesce(source_url, '\0')
				) AS row_hash
				, cve_id, source_url
				FROM exploits
			) sub;`,

		"malicious_packages": `
			SELECT count(*) AS row_count,
			       md5(string_agg(row_hash, '' ORDER BY id)) AS checksum
			FROM (
				SELECT id, md5(
					coalesce(id, '\0') || '|' ||
					coalesce(modified::text, '\0')
				) AS row_hash
				FROM malicious_packages
			) sub;`,

		"malicious_affected_components": `
			SELECT count(*) AS row_count,
			       md5(string_agg(id::text, '' ORDER BY id)) AS checksum
			FROM malicious_affected_components;`,
	}

	mutex := &sync.Mutex{}
	waitGroup := &sync.WaitGroup{}

	results := make([]tableIntegrityInformation, 0, 4)
	errors := make([]error, 0, 4)

	// launch 1 go routine per table for parallelization of the calculations
	for table, query := range queries {
		waitGroup.Add(1)
		go func(table, query string) {
			defer waitGroup.Done()

			result, err := calculateIntegrityInformationForTable(ctx, pool, table, query)

			mutex.Lock()
			defer mutex.Unlock()
			if err != nil {
				errors = append(errors, err)
			} else {
				results = append(results, result)
			}
		}(table, query)
	}

	waitGroup.Wait()

	if len(errors) > 0 {
		return results, fmt.Errorf("ran into one or multiple errors whilst trying to calculate integrity information: %v", errors)
	}

	return results, nil
}

// computes and returns the tables integrity information using the provided query
func calculateIntegrityInformationForTable(ctx context.Context, pool *pgxpool.Pool, table string, query string) (tableIntegrityInformation, error) {
	var result tableIntegrityInformation
	result.TableName = table

	start := time.Now()
	slog.Info("start calculating integrity information", "table", table)

	err := pool.QueryRow(ctx, query).Scan(&result.TotalCount, &result.Checksum)
	if err != nil {
		return result, fmt.Errorf("could not calculate integrity information for table %s: %w", table, err)
	}

	slog.Info("finished calculating integrity information", "table", table, "time", time.Since(start))

	return result, nil
}

func (integrity tableIntegrityInformation) isEqual(compareInformation tableIntegrityInformation) bool {
	return integrity.TotalCount == compareInformation.TotalCount && bytes.Equal(integrity.Checksum, compareInformation.Checksum)
}
