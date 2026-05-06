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
		seen := make(map[string]struct{}, len(edbExploits)+len(ghExploits))
		combined := make([]models.Exploit, 0, len(edbExploits)+len(ghExploits))
		for _, e := range append(edbExploits, ghExploits...) {
			if _, ok := survivingCVEs[e.CVEID]; !ok {
				continue
			}
			if _, dup := seen[e.ID]; dup {
				continue
			}
			seen[e.ID] = struct{}{}
			combined = append(combined, e)
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
	tableIntegrity, err := calculateTotalIntegrityInformation(ctx, tx)
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

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("could not commit export transaction: %w", err)
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

func readIntegrityInformation(workingDir string) (integrityInformation, error) {
	fd, err := os.Open(workingDir + "/integrity_checks.json")
	if err != nil {
		return integrityInformation{}, fmt.Errorf("could not open integrity_checks.json: %w", err)
	}
	defer fd.Close()
	var integrity integrityInformation
	if err := json.NewDecoder(fd).Decode(&integrity); err != nil {
		return integrityInformation{}, fmt.Errorf("could not decode integrity_checks.json: %w", err)
	}

	return integrity, nil
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

	integrity, err := readIntegrityInformation(workingDir)
	if err != nil {
		return fmt.Errorf("could not read integrity information: %w", err)
	}

	if integrity.ImportTimestamp.Equal(lastImportTime) {
		slog.Info("vulndb is up to date, skipping import", "lastImportTime", lastImportTime)
		return nil
	}

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

	err = s.applyFromWorkingDir(ctx, tx, workingDir, lastImportTime, integrity)
	if err != nil {
		slog.Error("could not import vulndb incrementally, attempting full import", "error", err)
		monitoring.Alert("vulndb integrity check failed, retrying as full import", err)
		// we need to create a new transaction for the retry, so we rollback the previous one and start a new one
		if rbErr := tx.Rollback(ctx); rbErr != nil && rbErr != pgx.ErrTxClosed {
			return fmt.Errorf("could not rollback transaction after failed import: %w (rollback error: %v)", err, rbErr)
		}

		tx, err = conn.Begin(ctx) //nolint:errcheck
		if err != nil {
			return fmt.Errorf("could not begin transaction for full import retry: %w", err)
		}

		err = s.applyFromWorkingDir(ctx, tx, workingDir, time.Time{}, integrity)
		if err != nil {
			if rbErr := tx.Rollback(ctx); rbErr != nil && rbErr != pgx.ErrTxClosed {
				monitoring.Alert("could not rollback transaction after failed full import retry", fmt.Errorf("rollback failed: %w", rbErr))
				return fmt.Errorf("could not rollback transaction after failed full import retry: %w (rollback error: %v)", err, rbErr)
			}

			monitoring.Alert("vulndb integrity check failed after full import fallback", err)
			return fmt.Errorf("integrity validation failed after full import fallback: %w", err)
		}
	}

	slog.Info("successfully validated checksums")

	if err := s.configService.SetJSONConfig(ctx, "vulndb.lastRCImport", integrity.ImportTimestamp.Format(time.RFC3339Nano)); err != nil {
		return fmt.Errorf("could not update last import time: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("could not commit import transaction: %w", err)
	}

	slog.Info("finished vulndb import", "time", time.Since(start))
	return nil
}

// applyFromWorkingDir decodes all gob files in workingDir and applies them to the database.
// lastImportTime controls which entries are treated as new (zero value = full import).
// populateDBFromGobs reads all gob files from workingDir and writes them to the database.
// lastImportTime is used to filter incremental updates; pass time.Time{} for a full import.
func (s *VulnDBService) populateDBFromGobs(ctx context.Context, tx pgx.Tx, workingDir string, lastImportTime time.Time) error {
	// Decode all gob payloads in parallel before touching the database.
	group, _ := errgroup.WithContext(ctx)
	var (
		osvEntries []OSVEntry
		epssData   map[string]dtos.EPSS
		kevEntries []CISAKEVEntry
		gobExploit []GobExploit
		malExport  GobMaliciousPackagesExport
	)

	if lastImportTime.IsZero() {
		group.Go(func() error {
			t := time.Now()
			slog.Info("start truncating vulndb tables")
			if err := truncateVulnDBTables(ctx, tx); err != nil {
				return err
			}
			slog.Info("finished truncating vulndb tables", "took", time.Since(t).Round(time.Millisecond))
			return nil
		})
	}

	group.Go(func() error {
		t := time.Now()
		if err := readGobFile(workingDir+"/osv.gob", &osvEntries); err != nil {
			return fmt.Errorf("could not read OSV gob: %w", err)
		}
		slog.Info("finished decoding OSV gob", "entries", len(osvEntries), "took", time.Since(t).Round(time.Millisecond))
		return nil
	})
	group.Go(func() error {
		t := time.Now()
		if err := readGobFile(workingDir+"/epss.gob", &epssData); err != nil {
			return fmt.Errorf("could not read EPSS gob: %w", err)
		}
		slog.Info("finished decoding EPSS gob", "entries", len(epssData), "took", time.Since(t).Round(time.Millisecond))
		return nil
	})
	group.Go(func() error {
		t := time.Now()
		if err := readGobFile(workingDir+"/cisakev.gob", &kevEntries); err != nil {
			return fmt.Errorf("could not read CISA KEV gob: %w", err)
		}
		slog.Info("finished decoding CISA KEV gob", "entries", len(kevEntries), "took", time.Since(t).Round(time.Millisecond))
		return nil
	})
	group.Go(func() error {
		t := time.Now()
		if err := readGobFile(workingDir+"/exploits.gob", &gobExploit); err != nil {
			return fmt.Errorf("could not read exploits gob: %w", err)
		}
		slog.Info("finished decoding exploits gob", "entries", len(gobExploit), "took", time.Since(t).Round(time.Millisecond))
		return nil
	})
	group.Go(func() error {
		t := time.Now()
		if err := readGobFile(workingDir+"/maliciouspackages.gob", &malExport); err != nil {
			return fmt.Errorf("could not read malicious packages gob: %w", err)
		}
		slog.Info("finished decoding malicious packages gob", "took", time.Since(t).Round(time.Millisecond))
		return nil
	})
	if err := group.Wait(); err != nil {
		return err
	}

	// Convert gob types to models.
	exploits := gobExploitsToModels(gobExploit, lastImportTime)
	pkgs, comps := gobMalPackagesExportToModels(malExport, lastImportTime)

	t := time.Now()
	slog.Info("start applying OSV data", "entries", len(osvEntries), "incremental", !lastImportTime.IsZero())
	if err := s.osv.applyOSVEntries(ctx, tx, osvEntries, lastImportTime); err != nil {
		return fmt.Errorf("OSV import failed: %w", err)
	}
	slog.Info("finished applying OSV data", "took", time.Since(t).Round(time.Millisecond))

	t = time.Now()
	slog.Info("start applying EPSS data", "entries", len(epssData))
	if err := insertEPSSBulk(ctx, tx, epssData); err != nil {
		return fmt.Errorf("could not apply EPSS data: %w", err)
	}
	slog.Info("finished applying EPSS data", "took", time.Since(t).Round(time.Millisecond))

	t = time.Now()
	slog.Info("start applying CISA KEV data", "entries", len(kevEntries))
	if err := insertCISAKEVBulk(ctx, tx, kevEntries); err != nil {
		return fmt.Errorf("could not apply CISA KEV data: %w", err)
	}
	slog.Info("finished applying CISA KEV data", "took", time.Since(t).Round(time.Millisecond))

	t = time.Now()
	slog.Info("start applying exploit data", "entries", len(exploits))
	if err := insertExploitsBulk(ctx, tx, exploits); err != nil {
		return fmt.Errorf("could not apply exploit data: %w", err)
	}
	slog.Info("finished applying exploit data", "took", time.Since(t).Round(time.Millisecond))

	t = time.Now()
	slog.Info("start applying malicious packages", "packages", len(pkgs), "components", len(comps))
	if err := insertMaliciousPackagesBulk(ctx, tx, pkgs, comps); err != nil {
		return fmt.Errorf("could not apply malicious packages: %w", err)
	}
	slog.Info("finished applying malicious packages", "took", time.Since(t).Round(time.Millisecond))

	return nil
}

func truncateVulnDBTables(ctx context.Context, tx pgx.Tx) error {
	// CASCADE handles the remaining vulndb-internal FKs (exploits, weaknesses, vex_rules, cve_relationships, cve_affected_component).
	if _, err := tx.Exec(ctx, `TRUNCATE cves, affected_components, malicious_packages, malicious_affected_components CASCADE`); err != nil {
		return fmt.Errorf("could not truncate vulndb tables: %w", err)
	}
	return nil
}

// Returns the import timestamp from the integrity manifest on success, zero time if integrity fails.
func (s *VulnDBService) applyFromWorkingDir(ctx context.Context, tx pgx.Tx, workingDir string, lastImportTime time.Time, integrityGroundTruth integrityInformation) error {
	if err := s.populateDBFromGobs(ctx, tx, workingDir, lastImportTime); err != nil {
		return err
	}

	// --- Integrity validation ---
	localIntegrity, err := calculateTotalIntegrityInformation(ctx, tx)
	if err != nil {
		return fmt.Errorf("could not calculate integrity information: %w", err)
	}
	err = validateIntegrityInformation(workingDir, integrityGroundTruth, localIntegrity)
	if err != nil {
		return fmt.Errorf("could not validate integrity: %w", err)
	}
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

func validateIntegrityInformation(workingDir string, groundTruth integrityInformation, localIntegrityInformation []tableIntegrityInformation) error {
	didErr := false
	for _, tableIntegrity := range localIntegrityInformation {
		found := false
		for _, tableGroundTruth := range groundTruth.TableIntegrity {
			if tableGroundTruth.TableName == tableIntegrity.TableName {
				if !tableIntegrity.isEqual(tableGroundTruth) {
					slog.Error("invalid checksum when importing", "table", tableIntegrity.TableName, "expectedCount", tableGroundTruth.TotalCount, "actualCount", tableIntegrity.TotalCount, "expectedChecksum", fmt.Sprintf("%x", tableGroundTruth.Checksum), "actualChecksum", fmt.Sprintf("%x", tableIntegrity.Checksum))

					didErr = true
				} else {
					found = true
					break
				}
			}
		}
		if !found {
			return fmt.Errorf("could not find integrity information for table %s", tableIntegrity.TableName)
		}
	}
	if didErr {
		return fmt.Errorf("integrity validation failed for one or more tables when importing from %s", workingDir)
	}

	return nil
}

func calculateTotalIntegrityInformation(ctx context.Context, tx pgx.Tx) ([]tableIntegrityInformation, error) {
	const query = `
		WITH
		cves_integrity AS (
			SELECT 'cves' AS table_name, count(*) AS row_count,
			       md5(string_agg(row_hash, '' ORDER BY id)) AS checksum
			FROM (
				SELECT id, md5(
					coalesce(id::text, '\0') || '|' ||
					coalesce(description, '\0') || '|' ||
					coalesce(cvss::text, '\0') || '|' ||
					coalesce(vector, '\0')
				) AS row_hash FROM cves
			) sub
		),
		cve_relationships_integrity AS (
			SELECT 'cve_relationships' AS table_name, count(*) AS row_count,
			       md5(string_agg(row_hash, '' ORDER BY source_cve, target_cve, relationship_type)) AS checksum
			FROM (
				SELECT source_cve, target_cve, relationship_type,
				       md5(source_cve || '|' || target_cve || '|' || relationship_type) AS row_hash
				FROM cve_relationships
			) sub
		),
		cve_affected_component_integrity AS (
			SELECT 'cve_affected_component' AS table_name, count(*) AS row_count,
			       md5(
			           count(*)::text || '|' ||
			           coalesce(bit_xor(hashtextextended(cve_id::text || '|' || affected_component_id::text, 0))::text, '0') || '|' ||
			           coalesce(bit_xor(hashtextextended(cve_id::text || '|' || affected_component_id::text, 1))::text, '0')
			       ) AS checksum
			FROM cve_affected_component
		),
		affected_components_integrity AS (
			SELECT 'affected_components' AS table_name, count(*) AS row_count,
			       md5(string_agg(id::text, '' ORDER BY id)) AS checksum
			FROM affected_components
		),
		exploits_integrity AS (
			SELECT 'exploits' AS table_name, count(*) AS row_count,
			       md5(string_agg(row_hash, '' ORDER BY id, cve_id, source_url, row_hash)) AS checksum
			FROM (
				SELECT id, cve_id, source_url, md5(
					coalesce(id, '\0') || '|' ||
					coalesce(cve_id, '\0') || '|' ||
					coalesce(source_url, '\0')
				) AS row_hash FROM exploits
			) sub
		),
		malicious_packages_integrity AS (
			SELECT 'malicious_packages' AS table_name, count(*) AS row_count,
			       md5(string_agg(row_hash, '' ORDER BY id)) AS checksum
			FROM (
				SELECT id, md5(coalesce(id, '\0') || '|' || coalesce(modified::text, '\0')) AS row_hash
				FROM malicious_packages WHERE id NOT LIKE 'FAKE-TEST-%'
			) sub
		),
		malicious_affected_components_integrity AS (
			SELECT 'malicious_affected_components' AS table_name, count(*) AS row_count,
			       md5(string_agg(id::text, '' ORDER BY id)) AS checksum
			FROM malicious_affected_components WHERE malicious_package_id NOT LIKE 'FAKE-TEST-%'
		)
		SELECT table_name, row_count, checksum FROM cves_integrity
		UNION ALL SELECT table_name, row_count, checksum FROM cve_relationships_integrity
		UNION ALL SELECT table_name, row_count, checksum FROM cve_affected_component_integrity
		UNION ALL SELECT table_name, row_count, checksum FROM affected_components_integrity
		UNION ALL SELECT table_name, row_count, checksum FROM exploits_integrity
		UNION ALL SELECT table_name, row_count, checksum FROM malicious_packages_integrity
		UNION ALL SELECT table_name, row_count, checksum FROM malicious_affected_components_integrity
	`

	slog.Info("start calculating integrity information")
	start := time.Now()
	rows, err := tx.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("could not calculate integrity information: %w", err)
	}
	defer rows.Close()

	results := make([]tableIntegrityInformation, 0, 7)
	for rows.Next() {
		var r tableIntegrityInformation
		if err := rows.Scan(&r.TableName, &r.TotalCount, &r.Checksum); err != nil {
			return nil, fmt.Errorf("could not scan integrity row: %w", err)
		}
		results = append(results, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("could not read integrity rows: %w", err)
	}
	slog.Info("finished calculating integrity information", "took", time.Since(start).Round(time.Millisecond))
	for _, r := range results {
		slog.Info("integrity", "table", r.TableName, "rows", r.TotalCount, "checksum", fmt.Sprintf("%x", r.Checksum))
	}

	return results, nil
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
