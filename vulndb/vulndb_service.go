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

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/klauspost/compress/zstd"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/monitoring"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
	"go.opentelemetry.io/otel/codes"
	"golang.org/x/sync/errgroup"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/file"
	"oras.land/oras-go/v2/registry/remote"
)

const vulnDBArchiveName = "vulndb.tar.zst"
const vulnDBPubKeyFile = "cosign.pub"

// VulnDBService orchestrates the full vulnerability database export and import,
// covering OSV, EPSS, CISA KEV, exploits (ExploitDB + GitHub PoC),
// and malicious packages.
type VulnDBService struct {
	osv               osvService
	epss              epssService
	cisaKEV           cisaKEVService
	githubExploits    *githubExploitDBService
	exploitDB         exploitDBService
	maliciousPackages *MaliciousPackageChecker
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
		osv:               NewOSVService(affectedCmpRepository, cveRepository, cveRelationshipRepository, pool),
		epss:              NewEPSSService(cveRepository, cveRelationshipRepository),
		cisaKEV:           NewCISAKEVService(cveRepository, cveRelationshipRepository),
		githubExploits:    NewGithubExploitDBService(exploitRepository),
		exploitDB:         NewExploitDBService(exploitRepository),
		maliciousPackages: maliciousPackageChecker,
		configService:     configService,
		pool:              pool,
	}
}

// ExportRC fetches all vulnerability data sources, writes gob files for each,
// populates the database, and writes a full integrity_checks.json.
func (s *VulnDBService) ExportRC(ctx context.Context) error {
	slog.Info("start vulndb export")
	start := time.Now()

	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("could not acquire db connection: %w", err)
	}
	defer conn.Release()

	tx, err := conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("could not begin transaction: %w", err)
	}
	defer func() {
		if err := tx.Rollback(ctx); err != nil && err != pgx.ErrTxClosed {
			slog.Error("could not rollback export transaction", "error", err)
		}
	}()

	// OSV must run first: it populates the DB (including cleanup) so we know
	// which CVE IDs exist before fetching the other sources.
	osvEntries, survivingCVEs, err := s.osv.fetchAndImportOSV(ctx, tx, start)
	if err != nil {
		return fmt.Errorf("OSV fetch failed: %w", err)
	}
	if err := writeGobFile(osvEntries, "osv.gob"); err != nil {
		return fmt.Errorf("could not write OSV gob: %w", err)
	}
	slog.Info("wrote osv.gob", "entries", len(osvEntries))

	// Fetch the remaining sources in parallel (network only — no DB writes yet).
	var (
		epssData    map[string]dtos.EPSS
		kevEntries  []CISAKEVEntry
		allExploits []models.Exploit
		malPkgs     []models.MaliciousPackage
		malComps    []models.MaliciousAffectedComponent
	)
	group, groupCtx := errgroup.WithContext(ctx)

	group.Go(func() error {
		slog.Info("start fetching EPSS data")
		data, err := s.epss.Fetch(groupCtx)
		if err != nil {
			return fmt.Errorf("could not fetch EPSS data: %w", err)
		}
		for cve := range data {
			if _, ok := survivingCVEs[cve]; !ok {
				delete(data, cve)
			}
		}
		epssData = data
		return nil
	})

	group.Go(func() error {
		slog.Info("start fetching CISA KEV data")
		kevFetchCtx, kevCancel := context.WithTimeout(groupCtx, 30*time.Second)
		defer kevCancel()
		kevCVEs, err := s.cisaKEV.Fetch(kevFetchCtx)
		if err != nil {
			return fmt.Errorf("could not fetch CISA KEV data: %w", err)
		}
		filtered := kevCVEs[:0]
		for _, c := range kevCVEs {
			if _, ok := survivingCVEs[c.CVE]; ok {
				filtered = append(filtered, c)
			}
		}
		kevEntries = cisaKEVEntriesToGob(filtered)
		return nil
	})

	group.Go(func() error {
		slog.Info("start fetching exploit data")
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
		combined := make([]models.Exploit, 0, len(edbExploits)+len(ghExploits))
		for _, e := range edbExploits {
			if _, ok := survivingCVEs[e.CVEID]; ok {
				combined = append(combined, e)
			}
		}
		for _, e := range ghExploits {
			if _, ok := survivingCVEs[e.CVEID]; ok {
				combined = append(combined, e)
			}
		}
		allExploits = combined
		return nil
	})

	group.Go(func() error {
		slog.Info("start fetching malicious packages")
		packages, components, err := s.maliciousPackages.FetchAll(groupCtx)
		if err != nil {
			return fmt.Errorf("could not fetch malicious packages: %w", err)
		}
		fakePkgs, fakeComps := buildFakePackages()

		// unique pkgs and comps
		pkgMap := make(map[string]struct{})
		uniquePkgs := make([]models.MaliciousPackage, 0, len(packages))
		for _, p := range packages {
			if _, exists := pkgMap[p.ID]; !exists {
				pkgMap[p.ID] = struct{}{}
				uniquePkgs = append(uniquePkgs, p)
			}
		}

		compMap := make(map[string]struct{})
		uniqueComps := make([]models.MaliciousAffectedComponent, 0, len(components))
		for _, c := range components {
			if _, exists := compMap[c.ID]; !exists {
				compMap[c.ID] = struct{}{}
				uniqueComps = append(uniqueComps, c)
			}
		}

		malPkgs = append(uniquePkgs, fakePkgs...)
		malComps = append(uniqueComps, fakeComps...)
		return nil
	})

	if err := group.Wait(); err != nil {
		return err
	}

	// Write all fetched data to the DB within the same transaction.
	slog.Info("writing EPSS data to database")
	if err := insertEPSSBulk(ctx, tx, epssData); err != nil {
		return fmt.Errorf("could not write EPSS data: %w", err)
	}
	slog.Info("writing CISA KEV data to database")
	if err := insertCISAKEVBulk(ctx, tx, kevEntries); err != nil {
		return fmt.Errorf("could not write CISA KEV data: %w", err)
	}
	slog.Info("writing exploit data to database")
	if err := insertExploitsBulk(ctx, tx, allExploits); err != nil {
		return fmt.Errorf("could not write exploit data: %w", err)
	}
	slog.Info("writing malicious packages to database")
	if err := insertMaliciousPackagesBulk(ctx, tx, malPkgs, malComps); err != nil {
		return fmt.Errorf("could not write malicious packages: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("could not commit export transaction: %w", err)
	}

	// Write gob files from in-memory data (DB is now committed).
	gobExploits := make([]GobExploit, len(allExploits))
	for i, e := range allExploits {
		gobExploits[i] = exploitToGob(e)
	}
	if err := writeGobFile(epssData, "epss.gob"); err != nil {
		return fmt.Errorf("could not write EPSS gob: %w", err)
	}
	if err := writeGobFile(kevEntries, "cisakev.gob"); err != nil {
		return fmt.Errorf("could not write CISA KEV gob: %w", err)
	}
	if err := writeGobFile(gobExploits, "exploits.gob"); err != nil {
		return fmt.Errorf("could not write exploits gob: %w", err)
	}
	if err := writeGobFile(malPackagesExportToGob(malPkgs, malComps), "maliciouspackages.gob"); err != nil {
		return fmt.Errorf("could not write malicious packages gob: %w", err)
	}
	slog.Info("wrote all gob files")

	// --- Integrity check (covers all tables including exploits + malicious) ---
	tableIntegrity, err := calculateTotalIntegrityInformation(ctx, s.pool)
	if err != nil {
		return fmt.Errorf("could not calculate integrity information: %w", err)
	}
	slices.SortFunc(tableIntegrity, func(a, b tableIntegrityInformation) int {
		return strings.Compare(a.TableName, b.TableName)
	})

	for _, ti := range tableIntegrity {
		if ti.TotalCount == 0 || len(ti.Checksum) == 0 {
			return fmt.Errorf("refusing to export: table %q has zero rows or empty checksum — database is likely incomplete", ti.TableName)
		}
		slog.Info("table integrity", "table", ti.TableName, "count", ti.TotalCount, "checksum", string(ti.Checksum))
	}

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
// If the integrity check fails after an incremental import, it alerts and retries
// as a full import (ignoring the last-import watermark).
func (s *VulnDBService) ImportRC(ctx context.Context) (err error) {
	ctx, span := vulndbTracer.Start(ctx, "VulnDBService.ImportRC")
	defer func() {
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
		}
		span.End()
	}()

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

	databaseStateTime, err := s.applyFromWorkingDir(ctx, workingDir, lastImportTime)
	if err != nil {
		return err
	}

	// Integrity check failed on the incremental import — alert and retry as a full import.
	if databaseStateTime.IsZero() {
		monitoring.Alert("vulndb integrity check failed after incremental import — retrying as full import", fmt.Errorf("integrity validation failed"))
		slog.Warn("integrity check failed, retrying as full import")
		databaseStateTime, err = s.applyFromWorkingDir(ctx, workingDir, time.Time{})
		if err != nil {
			return err
		}
		if databaseStateTime.IsZero() {
			err := fmt.Errorf("integrity validation failed after full import fallback")
			monitoring.Alert("vulndb integrity check failed after full import fallback", err)
			return err
		}
	}

	slog.Info("successfully validated checksums")

	if err := s.configService.SetJSONConfig(ctx, "vulndb.lastRCImport", databaseStateTime.Format(time.RFC3339Nano)); err != nil {
		return fmt.Errorf("could not update last import time: %w", err)
	}

	slog.Info("finished vulndb import", "time", time.Since(start))
	return nil
}

// applyFromWorkingDir decodes all gob files in workingDir and applies them to the database.
// lastImportTime controls which entries are treated as new (zero value = full import).
// populateDBFromGobs reads all gob files from workingDir and writes them to the database.
// lastImportTime is used to filter incremental updates; pass time.Time{} for a full import.
func (s *VulnDBService) populateDBFromGobs(ctx context.Context, workingDir string, lastImportTime time.Time) error {
	// Decode all gob payloads in parallel before touching the database.
	group, _ := errgroup.WithContext(ctx)
	var (
		osvEntries []OSVEntry
		epssData   map[string]dtos.EPSS
		kevEntries []CISAKEVEntry
		gobExploit []GobExploit
		malExport  GobMaliciousPackagesExport
	)
	group.Go(func() error {
		if err := readGobFile(workingDir+"/osv.gob", &osvEntries); err != nil {
			return fmt.Errorf("could not read OSV gob: %w", err)
		}
		slog.Info("decoded OSV gob file", "amount", len(osvEntries))
		return nil
	})
	group.Go(func() error {
		if err := readGobFile(workingDir+"/epss.gob", &epssData); err != nil {
			return fmt.Errorf("could not read EPSS gob: %w", err)
		}
		return nil
	})
	group.Go(func() error {
		if err := readGobFile(workingDir+"/cisakev.gob", &kevEntries); err != nil {
			return fmt.Errorf("could not read CISA KEV gob: %w", err)
		}
		return nil
	})
	group.Go(func() error {
		if err := readGobFile(workingDir+"/exploits.gob", &gobExploit); err != nil {
			return fmt.Errorf("could not read exploits gob: %w", err)
		}
		return nil
	})
	group.Go(func() error {
		if err := readGobFile(workingDir+"/maliciouspackages.gob", &malExport); err != nil {
			return fmt.Errorf("could not read malicious packages gob: %w", err)
		}
		return nil
	})
	if err := group.Wait(); err != nil {
		return err
	}

	// Convert gob types to models.
	exploits := gobExploitsToModels(gobExploit, lastImportTime)
	pkgs, comps := gobMalPackagesExportToModels(malExport, lastImportTime)

	// Open a single pgx connection and transaction for all DB writes.
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("could not acquire db connection: %w", err)
	}
	defer conn.Release()

	tx, err := conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("could not begin transaction: %w", err)
	}
	defer func() {
		if err := tx.Rollback(ctx); err != nil && err != pgx.ErrTxClosed {
			slog.Error("could not rollback import transaction", "error", err)
		}
	}()

	if lastImportTime.IsZero() {
		slog.Info("full import: truncating vulndb tables")
		if err := truncateVulnDBTables(ctx, tx); err != nil {
			return fmt.Errorf("could not truncate vulndb tables for full import: %w", err)
		}
	}

	slog.Info("applying OSV data")
	if err := s.osv.applyOSVEntries(ctx, tx, osvEntries, lastImportTime); err != nil {
		return fmt.Errorf("OSV import failed: %w", err)
	}

	slog.Info("applying EPSS data")
	if err := insertEPSSBulk(ctx, tx, epssData); err != nil {
		return fmt.Errorf("could not apply EPSS data: %w", err)
	}
	slog.Info("applied EPSS data", "entries", len(epssData))

	slog.Info("applying CISA KEV data")
	if err := insertCISAKEVBulk(ctx, tx, kevEntries); err != nil {
		return fmt.Errorf("could not apply CISA KEV data: %w", err)
	}
	slog.Info("applied CISA KEV data", "entries", len(kevEntries))

	slog.Info("applying exploit data")
	if err := insertExploitsBulk(ctx, tx, exploits); err != nil {
		return fmt.Errorf("could not apply exploit data: %w", err)
	}
	slog.Info("applied exploit data", "entries", len(exploits))

	slog.Info("applying malicious packages")
	if err := insertMaliciousPackagesBulk(ctx, tx, pkgs, comps); err != nil {
		return fmt.Errorf("could not apply malicious packages: %w", err)
	}
	slog.Info("applied malicious packages", "packages", len(pkgs), "components", len(comps))

	if lastImportTime.IsZero() {
		slog.Info("full import: deleting dependency_vulns with unknown CVEs")
		if _, err := tx.Exec(ctx, `DELETE FROM dependency_vulns WHERE cve_id NOT IN (SELECT cve FROM cves)`); err != nil {
			return fmt.Errorf("could not delete orphaned dependency_vulns: %w", err)
		}
		slog.Info("full import: re-adding foreign key constraint on dependency_vulns")
		if _, err := tx.Exec(ctx, `ALTER TABLE dependency_vulns ADD CONSTRAINT fk_dependency_vulns_cve FOREIGN KEY (cve_id) REFERENCES cves (cve) ON DELETE CASCADE`); err != nil {
			return fmt.Errorf("could not re-add FK on dependency_vulns: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("could not commit import transaction: %w", err)
	}
	return nil
}

func truncateVulnDBTables(ctx context.Context, tx pgx.Tx) error {
	// Drop the FK from dependency_vulns so TRUNCATE on cves doesn't cascade into user data.
	if _, err := tx.Exec(ctx, `ALTER TABLE dependency_vulns DROP CONSTRAINT IF EXISTS fk_dependency_vulns_cve`); err != nil {
		return fmt.Errorf("could not drop FK fk_dependency_vulns_cve: %w", err)
	}
	// CASCADE handles the remaining vulndb-internal FKs (exploits, weaknesses, vex_rules, cve_relationships, cve_affected_component).
	if _, err := tx.Exec(ctx, `TRUNCATE cves, affected_components, malicious_packages, malicious_affected_components CASCADE`); err != nil {
		return fmt.Errorf("could not truncate vulndb tables: %w", err)
	}
	return nil
}

// Returns the import timestamp from the integrity manifest on success, zero time if integrity fails.
func (s *VulnDBService) applyFromWorkingDir(ctx context.Context, workingDir string, lastImportTime time.Time) (time.Time, error) {
	if err := s.populateDBFromGobs(ctx, workingDir, lastImportTime); err != nil {
		return time.Time{}, err
	}

	// --- Integrity validation ---
	localIntegrity, err := calculateTotalIntegrityInformation(ctx, s.pool)
	if err != nil {
		return time.Time{}, fmt.Errorf("could not calculate integrity information: %w", err)
	}
	valid, databaseStateTime, err := validateIntegrityInformation(workingDir, localIntegrity)
	if err != nil {
		return time.Time{}, fmt.Errorf("could not validate integrity: %w", err)
	}
	if !valid {
		return time.Time{}, nil
	}
	return databaseStateTime, nil
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
					slog.Error("invalid checksum when importing", "table", tableIntegrity.TableName, "expectedCount", tableGroundTruth.TotalCount, "actualCount", tableIntegrity.TotalCount, "expectedChecksum", fmt.Sprintf("%x", tableGroundTruth.Checksum), "actualChecksum", fmt.Sprintf("%x", tableIntegrity.Checksum))
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
				WHERE id NOT LIKE 'FAKE-TEST-%'
			) sub;`,

		"malicious_affected_components": `
			SELECT count(*) AS row_count,
			       md5(string_agg(id::text, '' ORDER BY id)) AS checksum
			FROM malicious_affected_components
			WHERE malicious_package_id NOT LIKE 'FAKE-TEST-%';`,
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

func (integrity tableIntegrityInformation) isEqual(compareInformation tableIntegrityInformation) bool {
	return integrity.TotalCount == compareInformation.TotalCount && bytes.Equal(integrity.Checksum, compareInformation.Checksum)
}
