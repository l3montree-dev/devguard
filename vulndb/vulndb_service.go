package vulndb

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/monitoring"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"golang.org/x/sync/errgroup"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/file"
	"oras.land/oras-go/v2/registry/remote"
)

const vulnDBArchiveName = "vulndb.tar.zst"
const vulnDBPubKeyFile = "cosign.pub"

var _ shared.VulnDBService = (*VulnDBService)(nil)

// debugImport reuses a previously downloaded archive from the current working directory
// instead of pulling from the OCI registry. Set to true only for local profiling/benchmarking.
const debugImport = false

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

	if err := truncateCveRelatedTables(ctx, tx); err != nil {
		return fmt.Errorf("could not truncate vulndb tables: %w", err)
	}

	if err := truncateMaliciousPackageRelatedTables(ctx, tx); err != nil {
		return fmt.Errorf("could not truncate malicious package tables: %w", err)
	}

	// OSV must run first: it populates the DB (including cleanup) so we know
	// which CVE IDs exist before fetching the other sources.
	osvEntries, survivingCVEs, err := s.osv.fetchAndImportOSV(ctx, tx, start)
	if err != nil {
		return fmt.Errorf("OSV fetch failed: %w", err)
	}
	if err := writeGobFileItems(osvEntries, "osv.gob"); err != nil {
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
	if err := flushNonOSVStagingTables(ctx, tx); err != nil {
		return fmt.Errorf("could not flush staging tables: %w", err)
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
	if err := writeGobFile(epssData, "epss.gob"); err != nil {
		return fmt.Errorf("could not write EPSS gob: %w", err)
	}
	if err := writeGobFile(kevEntries, "cisakev.gob"); err != nil {
		return fmt.Errorf("could not write CISA KEV gob: %w", err)
	}
	if err := writeGobFileItems(exploitToGobTransformer(allExploits), "exploits.gob"); err != nil {
		return fmt.Errorf("could not write exploits gob: %w", err)
	}
	slog.Info("wrote all gob files")

	// --- Integrity check (covers all tables including exploits + malicious) ---

	if err := writeVulnDBTarZst("vulndb.tar.zst", []string{
		"osv.gob",
		"epss.gob",
		"cisakev.gob",
		"exploits.gob",
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
func (s *VulnDBService) ImportRC(ctx context.Context, opts shared.ImportOptions) (err error) {
	ctx, span := vulndbTracer.Start(ctx, "VulnDBService.ImportRC")

	if len(opts.LimitedToTables) == 0 {
		opts.LimitedToTables = []string{
			"cves",
			"affected_components",
			"cve_relationships",
			"cve_affected_component",
			"exploits",
			"malicious_packages",
			"malicious_affected_components",
		}
	}

	defer func() {
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
		}
		span.End()
	}()

	if opts.BatchSize > 0 {
		batchSize = opts.BatchSize
	}

	importMode := "incremental"
	if opts.Full {
		importMode = "full"
	}
	processingMode := "streaming"
	if opts.Bulk {
		processingMode = "bulk"
	}
	span.SetAttributes(
		attribute.String("vulndb.mode", importMode),
		attribute.String("vulndb.processing", processingMode),
		attribute.Bool("vulndb.retried", false),
	)
	slog.Info("start vulndb import", "mode", importMode, "processing", processingMode, "limitedToTables", opts.LimitedToTables)
	start := time.Now()

	workingDir, err := pullVulnDBFromPackageRegistry(ctx)
	if err != nil {
		return fmt.Errorf("could not pull from remote repository: %w", err)
	}
	defer os.RemoveAll(workingDir)

	var lastImportTime time.Time
	if !opts.Full {
		var lastImportStr string
		if err := s.configService.GetJSONConfig(ctx, "vulndb.lastRCImport", &lastImportStr); err == nil {
			lastImportTime, _ = time.Parse(time.RFC3339Nano, lastImportStr)
		}
	}

	integrity, err := readIntegrityInformation(workingDir)
	if err != nil {
		return fmt.Errorf("could not read integrity information: %w", err)
	}

	if integrity.ImportTimestamp.Equal(lastImportTime) {
		slog.Info("vulndb is up to date, skipping import", "lastImportTime", lastImportTime)
		return nil
	} else if !lastImportTime.IsZero() {
		slog.Info("last import time", "currentState", lastImportTime, "updatingToVersion", integrity.ImportTimestamp)
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

	failingTables, err := s.applyFromWorkingDir(ctx, tx, workingDir, lastImportTime, integrity, opts.Bulk, opts.LimitedToTables)

	if err != nil {
		slog.Error("integrity validation failed, attempting fallback retry", "failingTables", failingTables, "error", err)
		if opts.Debug {
			showImportDebug(ctx, tx, workingDir, failingTables)
			return fmt.Errorf("integrity validation failed; debug logs printed for failing tables: %v: %w", failingTables, err)
		}
		monitoring.Alert("vulndb integrity check failed, retrying with limited table set", err)

		span.SetAttributes(
			attribute.Bool("vulndb.retried", true),
			attribute.StringSlice("vulndb.retry.failing_tables", failingTables),
		)
		slog.Info("retrying with full import for limited tables", "tables", failingTables)

		// since we did not commit anything until now, the staging tables still contain some data
		// for the import, we just need to make sure to clean them up before re-applying the data from the working directory
		if err := clearStagingTables(ctx, tx); err != nil {
			return fmt.Errorf("could not clear staging tables for retry: %w", err)
		}

		_, err = s.applyFromWorkingDir(ctx, tx, workingDir, time.Time{}, integrity, opts.Bulk, failingTables)
		if err != nil {
			if rbErr := tx.Rollback(ctx); rbErr != nil && rbErr != pgx.ErrTxClosed {
				monitoring.Alert("could not rollback transaction after failed full import retry", fmt.Errorf("rollback failed: %w", rbErr))
				return fmt.Errorf("could not rollback transaction after failed full import retry: %w (rollback error: %v)", err, rbErr)
			}

			span.SetAttributes(attribute.String("vulndb.retry.outcome", "failure"))
			monitoring.Alert("vulndb integrity check failed after full import fallback", err)
			return fmt.Errorf("integrity validation failed after full import fallback: %w", err)
		}
		span.SetAttributes(attribute.String("vulndb.retry.outcome", "success"))
	}

	slog.Info("successfully passed integrity validation", "importTimestamp", integrity.ImportTimestamp)

	if err := s.configService.SetJSONConfig(ctx, "vulndb.lastRCImport", integrity.ImportTimestamp.Format(time.RFC3339Nano)); err != nil {
		return fmt.Errorf("could not update last import time: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("could not commit import transaction: %w", err)
	}

	slog.Info("finished vulndb import", "totalTime", time.Since(start), "timestamp", integrity.ImportTimestamp)
	return nil
}

// applyFromWorkingDir decodes all gob files in workingDir and applies them to the database.
// lastImportTime controls which entries are treated as new (zero value = full import).
// populateDBFromGobsStream reads all gob files from workingDir and streams them to the
// database per-batch with live indexes — no table-wide lock is taken.
// lastImportTime is used to filter incremental updates; pass time.Time{} for a full import.
func (s *VulnDBService) populateDBFromGobsStream(ctx context.Context, tx pgx.Tx, workingDir string, lastImportTime time.Time, limitedToTables []string) error {
	// Decode all gob payloads in parallel before touching the database.
	group, groupCtx := errgroup.WithContext(ctx)

	var (
		epssData   map[string]dtos.EPSS
		kevEntries []CISAKEVEntry
	)

	vulndbChan := make(chan vulndbRows, 4)
	exploitChan := make(chan []models.Exploit, 4)
	malPkgChan := make(chan malRows, 4)

	if utils.ContainsAny(limitedToTables, []string{"cves", "affected_components", "cve_relationships", "cve_affected_component", "malicious_packages", "malicious_affected_components"}) {
		if lastImportTime.IsZero() {
			slog.Info("starting full import: truncating affected tables before streaming data")
			if err := truncateTablesForLimitedImport(ctx, tx, limitedToTables); err != nil {
				return fmt.Errorf("could not truncate tables for full import: %w", err)
			}
		}
	}

	if utils.ContainsAny(limitedToTables, []string{"cves", "affected_components", "cve_relationships", "cve_affected_component"}) {
		var existingAffectedComponents map[int64][]int64
		if !lastImportTime.IsZero() {
			var loadErr error
			existingAffectedComponents, loadErr = getCurrentAffectedComponents(ctx, tx)
			if loadErr != nil {
				return fmt.Errorf("could not get current affected components: %w", loadErr)
			}
			slog.Info("loaded existing affected components for deduplication", "count", len(existingAffectedComponents))
		}
		group.Go(func() error {
			defer close(vulndbChan)
			t := time.Now()
			if err := readGobFileStream(groupCtx, workingDir+"/osv.gob", gobOSVStreamer(groupCtx, lastImportTime, existingAffectedComponents, vulndbChan)); err != nil {
				return fmt.Errorf("could not read OSV gob: %w", err)
			}
			slog.Info("decoded osv.gob (CVE/affected component data)", "took", time.Since(t))
			return nil
		})
	} else {
		close(vulndbChan)
	}

	if utils.ContainsAny(limitedToTables, []string{"malicious_packages", "malicious_affected_components"}) {
		group.Go(func() error {
			defer close(malPkgChan)
			t := time.Now()
			if err := readGobFileStream(groupCtx, workingDir+"/osv.gob", gobOSVMalPkgStreamer(groupCtx, lastImportTime, malPkgChan)); err != nil {
				return fmt.Errorf("could not read OSV gob for malicious package data: %w", err)
			}
			slog.Info("decoded osv.gob (malicious package data)", "took", time.Since(t))
			return nil
		})
	} else {
		close(malPkgChan)
		slog.Debug("skipping malicious package import")
	}

	if utils.ContainsAny(limitedToTables, []string{"cves", "affected_components", "cve_relationships", "cve_affected_component"}) {
		group.Go(func() error {
			t := time.Now()
			if err := readGobFile(workingDir+"/epss.gob", &epssData); err != nil {
				return fmt.Errorf("could not read EPSS gob: %w", err)
			}
			slog.Info("decoded epss.gob", "entries", len(epssData), "took", time.Since(t))
			return nil
		})
		group.Go(func() error {
			t := time.Now()
			if err := readGobFile(workingDir+"/cisakev.gob", &kevEntries); err != nil {
				return fmt.Errorf("could not read CISA KEV gob: %w", err)
			}
			slog.Info("decoded cisakev.gob", "entries", len(kevEntries), "took", time.Since(t))
			return nil
		})
	}
	if slices.Contains(limitedToTables, "exploits") {
		group.Go(func() error {
			defer close(exploitChan)
			t := time.Now()
			if err := readGobFileStream(groupCtx, workingDir+"/exploits.gob", gobExploitStreamer(groupCtx, lastImportTime, exploitChan)); err != nil {
				return fmt.Errorf("could not read exploits gob: %w", err)
			}
			slog.Info("decoded exploits.gob", "took", time.Since(t))
			return nil
		})
	} else {
		close(exploitChan)
		slog.Debug("skipping exploits import")
	}
	group.Go(func() error {
		return streamToDatabase(groupCtx, tx, vulndbChan, exploitChan, malPkgChan, lastImportTime)
	})

	if err := group.Wait(); err != nil {
		return err
	}

	t := time.Now()
	if err := insertEPSSBulk(ctx, tx, epssData); err != nil {
		return fmt.Errorf("could not apply EPSS data: %w", err)
	}
	slog.Info("applied epss data", "entries", len(epssData), "took", time.Since(t))

	t = time.Now()
	if err := insertCISAKEVBulk(ctx, tx, kevEntries); err != nil {
		return fmt.Errorf("could not apply CISA KEV data: %w", err)
	}
	slog.Info("applied cisa kev data", "entries", len(kevEntries), "took", time.Since(t))

	return nil
}

func truncateTablesForLimitedImport(ctx context.Context, tx pgx.Tx, limitedToTables []string) error {
	if utils.ContainsAny(limitedToTables, []string{"cves", "affected_components", "cve_relationships", "cve_affected_component"}) {
		if err := truncateCveRelatedTables(ctx, tx); err != nil {
			return fmt.Errorf("could not truncate CVE-related tables: %w", err)
		}
	}
	if utils.ContainsAny(limitedToTables, []string{"malicious_packages", "malicious_affected_components"}) {
		if err := truncateMaliciousPackageRelatedTables(ctx, tx); err != nil {
			return fmt.Errorf("could not truncate malicious package-related tables: %w", err)
		}
	}
	return nil
}

// populateDBFromGobsBulk reads all gob files fully into RAM, then writes everything to the
// database in one shot via writeToDatabase. Faster than streaming for full imports but uses
// significantly more memory (~2-3 GB).
func (s *VulnDBService) populateDBFromGobsBulk(ctx context.Context, tx pgx.Tx, workingDir string, lastImportTime time.Time, limitedToTables []string) error {
	group, _ := errgroup.WithContext(ctx)

	var (
		osvEntries []OSVEntry
		epssData   map[string]dtos.EPSS
		kevEntries []CISAKEVEntry
		gobExploit []GobExploit
	)

	if utils.ContainsAny(limitedToTables, []string{"cves", "affected_components", "cve_relationships", "cve_affected_component", "malicious_packages", "malicious_affected_components"}) {
		if lastImportTime.IsZero() {
			t := time.Now()
			slog.Info("start truncating vulndb tables")
			if err := truncateTablesForLimitedImport(ctx, tx, limitedToTables); err != nil {
				return err
			}
			slog.Info("finished truncating vulndb tables", "took", time.Since(t))
		}
		group.Go(func() error {
			t := time.Now()
			var err error
			osvEntries, err = readAllGobItems[OSVEntry](workingDir + "/osv.gob")
			if err != nil {
				return fmt.Errorf("could not read OSV gob: %w", err)
			}
			slog.Info("decoded osv.gob", "entries", len(osvEntries), "took", time.Since(t))
			return nil
		})
	}

	if utils.ContainsAny(limitedToTables, []string{"cves", "affected_components", "cve_relationships", "cve_affected_component"}) {
		group.Go(func() error {
			t := time.Now()
			if err := readGobFile(workingDir+"/epss.gob", &epssData); err != nil {
				return fmt.Errorf("could not read EPSS gob: %w", err)
			}
			slog.Info("decoded epss.gob", "entries", len(epssData), "took", time.Since(t))
			return nil
		})
		group.Go(func() error {
			t := time.Now()
			if err := readGobFile(workingDir+"/cisakev.gob", &kevEntries); err != nil {
				return fmt.Errorf("could not read CISA KEV gob: %w", err)
			}
			slog.Info("decoded cisakev.gob", "entries", len(kevEntries), "took", time.Since(t))
			return nil
		})
	}

	if slices.Contains(limitedToTables, "exploits") {
		group.Go(func() error {
			t := time.Now()
			var err error
			gobExploit, err = readAllGobItems[GobExploit](workingDir + "/exploits.gob")
			if err != nil {
				return fmt.Errorf("could not read exploits gob: %w", err)
			}
			slog.Info("decoded exploits.gob", "entries", len(gobExploit), "took", time.Since(t))
			return nil
		})
	}

	if err := group.Wait(); err != nil {
		return err
	}

	existingAffectedComponents := make(map[int64][]int64)
	if !lastImportTime.IsZero() {
		var loadErr error
		existingAffectedComponents, loadErr = getCurrentAffectedComponents(ctx, tx)
		if loadErr != nil {
			return fmt.Errorf("could not get current affected components: %w", loadErr)
		}
	}

	var vulnRows vulndbRows
	var malRows malRows
	if utils.ContainsAny(limitedToTables, []string{"cves", "affected_components", "cve_relationships", "cve_affected_component"}) {
		vulnRows = gobOSVToVulnFilterTransformer(lastImportTime, existingAffectedComponents)(osvEntries)
	}
	if utils.ContainsAny(limitedToTables, []string{"malicious_packages", "malicious_affected_components"}) {
		malRows = gobOSVToMalFilterTransformer(lastImportTime)(osvEntries)
	}

	exploits := gobExploitFilterTransformer(lastImportTime, gobExploit)

	if err := writeToDatabase(ctx, tx, vulnRows, exploits, malRows, epssData, kevEntries, lastImportTime); err != nil {
		return err
	}
	return nil
}

// writeToDatabase inserts all pre-accumulated rows in a single pass.
// For full imports (lastImportTime.IsZero()) it drops indexes before inserting and rebuilds
// them afterwards — no channels, no per-batch overhead.
func heapMB() uint64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc / 1024 / 1024
}

func writeToDatabase(ctx context.Context, tx pgx.Tx, rows vulndbRows, exploits []models.Exploit, mal malRows, epssData map[string]dtos.EPSS, kevEntries []CISAKEVEntry, lastImportTime time.Time) error {
	slog.Info("start writing rows to database", "heap_alloc_mb", heapMB())
	start := time.Now()

	if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
		return fmt.Errorf("could not disable FK checks: %w", err)
	}

	if lastImportTime.IsZero() {
		if err := PrepareBulkInsert(ctx, tx); err != nil {
			return fmt.Errorf("could not prepare bulk insert: %w", err)
		}
	}
	if err := createStagingTables(ctx, tx); err != nil {
		return fmt.Errorf("could not create staging tables: %w", err)
	}

	t := time.Now()
	if err := insertCVEsBulk(ctx, tx, rows.CVEs); err != nil {
		return fmt.Errorf("could not copy cves to staging: %w", err)
	}
	slog.Info("copied cves to staging", "count", len(rows.CVEs), "took", time.Since(t), "heap_alloc_mb", heapMB())

	t = time.Now()
	if err := insertCVERelationshipsBulk(ctx, tx, rows.CVERelationships); err != nil {
		return fmt.Errorf("could not copy cve relationships to staging: %w", err)
	}
	slog.Info("copied cve_relationships to staging", "count", len(rows.CVERelationships), "took", time.Since(t), "heap_alloc_mb", heapMB())

	t = time.Now()
	if err := insertAffectedComponentsBulk(ctx, tx, rows.AffectedComponents); err != nil {
		return fmt.Errorf("could not copy affected_components to staging: %w", err)
	}
	slog.Info("copied affected_components to staging", "count", len(rows.AffectedComponents), "took", time.Since(t), "heap_alloc_mb", heapMB())

	t = time.Now()
	if err := insertCVEAffectedComponentsBulk(ctx, tx, rows.CVEAffectedComponents); err != nil {
		return fmt.Errorf("could not insert cve_affected_component: %w", err)
	}
	slog.Info("inserted cve_affected_component", "count", len(rows.CVEAffectedComponents), "took", time.Since(t), "heap_alloc_mb", heapMB())

	t = time.Now()
	if err := insertExploitsBulk(ctx, tx, exploits); err != nil {
		return fmt.Errorf("could not copy exploits to staging: %w", err)
	}
	slog.Info("copied exploits to staging", "count", len(exploits), "took", time.Since(t), "heap_alloc_mb", heapMB())

	t = time.Now()
	if err := insertMaliciousPackagesBulk(ctx, tx, mal.pkgs, mal.comps); err != nil {
		return fmt.Errorf("could not copy malicious packages to staging: %w", err)
	}
	slog.Info("copied malicious_packages to staging", "count", len(mal.pkgs), "took", time.Since(t), "heap_alloc_mb", heapMB())

	t = time.Now()
	if err := insertEPSSBulk(ctx, tx, epssData); err != nil {
		return fmt.Errorf("could not insert epss: %w", err)
	}
	slog.Info("inserted epss", "count", len(epssData), "took", time.Since(t), "heap_alloc_mb", heapMB())

	t = time.Now()
	if err := insertCISAKEVBulk(ctx, tx, kevEntries); err != nil {
		return fmt.Errorf("could not insert cisa kev: %w", err)
	}
	slog.Info("inserted cisa_kev", "count", len(kevEntries), "took", time.Since(t), "heap_alloc_mb", heapMB())

	t = time.Now()
	if err := flushStagingTables(ctx, tx); err != nil {
		return fmt.Errorf("could not flush staging tables: %w", err)
	}
	slog.Info("flushed staging tables", "took", time.Since(t), "heap_alloc_mb", heapMB())

	if lastImportTime.IsZero() {
		if err := AddIndexesAndConstraints(ctx, tx); err != nil {
			return fmt.Errorf("could not rebuild indexes and constraints: %w", err)
		}
	}

	slog.Info("finished writing rows to database", "took", time.Since(start), "heap_alloc_mb", heapMB())
	return nil
}

func truncateCveRelatedTables(ctx context.Context, tx pgx.Tx) error {
	// Drop the FK from exploits before truncating so that CASCADE does not silently
	// wipe exploit rows — exploits may not be part of the current import batch.
	// AddIndexesAndConstraints re-adds the constraint after CVE rows are flushed.
	if _, err := tx.Exec(ctx, `
		ALTER TABLE public.exploits DROP CONSTRAINT IF EXISTS fk_cves_exploits;
		TRUNCATE cves, affected_components, cve_relationships, cve_affected_component CASCADE;
	`); err != nil {
		return fmt.Errorf("could not truncate cve-related tables: %w", err)
	}
	return nil
}

func truncateMaliciousPackageRelatedTables(ctx context.Context, tx pgx.Tx) error {
	if _, err := tx.Exec(ctx, `TRUNCATE malicious_packages, malicious_affected_components CASCADE`); err != nil {
		return fmt.Errorf("could not truncate malicious package-related tables: %w", err)
	}
	return nil
}

// Returns the import timestamp from the integrity manifest on success, zero time if integrity fails.
func (s *VulnDBService) applyFromWorkingDir(ctx context.Context, tx pgx.Tx, workingDir string, lastImportTime time.Time, integrityGroundTruth integrityInformation, bulk bool, limitedToTables []string) ([]string, error) {
	if bulk {
		if err := s.populateDBFromGobsBulk(ctx, tx, workingDir, lastImportTime, limitedToTables); err != nil {
			return nil, err
		}
	} else {
		if err := s.populateDBFromGobsStream(ctx, tx, workingDir, lastImportTime, limitedToTables); err != nil {
			return nil, err
		}
	}

	localIntegrity, err := calculateTotalIntegrityInformation(ctx, tx)
	if err != nil {
		return nil, fmt.Errorf("could not calculate integrity information: %w", err)
	}
	failingTables, success := validateIntegrityInformation(workingDir, integrityGroundTruth, localIntegrity)
	if !success {
		slog.Warn("integrity validation failed for tables", "failingTables", failingTables)
		return failingTables, fmt.Errorf("integrity validation failed: %v", failingTables)
	}
	slog.Info("integrity validation successful", "tables_checked", len(localIntegrity))
	return nil, nil
}

func pullVulnDBFromPackageRegistry(ctx context.Context) (string, error) {
	if debugImport {
		return pullVulnDBDebug(ctx)
	}
	return pullVulnDBFromOCI(ctx)
}

// pullVulnDBDebug reuses vulndb.tar.zst from the current working directory when it already
// exists, skipping the OCI pull and signature verification. Intended for local benchmarking only.
func pullVulnDBDebug(ctx context.Context) (string, error) {
	archivePath := vulnDBArchiveName
	if _, err := os.Stat(archivePath); os.IsNotExist(err) {
		slog.Info("debug-import: no local archive found, downloading once")
		dir, err := pullVulnDBFromOCI(ctx)
		if err != nil {
			return "", err
		}
		data, err := os.ReadFile(dir + "/" + vulnDBArchiveName)
		if err != nil {
			os.RemoveAll(dir)
			return "", fmt.Errorf("could not read downloaded archive: %w", err)
		}
		if err := os.WriteFile(archivePath, data, 0o644); err != nil {
			os.RemoveAll(dir)
			return "", fmt.Errorf("could not cache archive: %w", err)
		}
		slog.Info("debug-import: cached archive", "path", archivePath)
		return dir, nil
	}

	slog.Info("debug-import: reusing cached archive", "path", archivePath)
	outpath, err := os.MkdirTemp("", "vulndb")
	if err != nil {
		return "", fmt.Errorf("could not create temp directory: %w", err)
	}
	if err := untarZstd(archivePath, outpath+"/"); err != nil {
		os.RemoveAll(outpath)
		return "", fmt.Errorf("could not untar vulndb archive: %w", err)
	}
	return outpath, nil
}

func pullVulnDBFromOCI(ctx context.Context) (string, error) {
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

// streamToDatabase drains all three input channels in a single goroutine and writes
// the received rows to the database. The caller is responsible for Begin/Commit/Rollback.
func streamToDatabase(ctx context.Context, tx pgx.Tx, vulnRowsIn <-chan vulndbRows, exploitsIn <-chan []models.Exploit, malPkgIn <-chan malRows, lastImportTime time.Time) error {
	slog.Info("start writing rows to database")
	start := time.Now()

	if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
		return fmt.Errorf("could not disable FK checks: %w", err)
	}

	rebuildIndexes := lastImportTime.IsZero() || time.Since(lastImportTime) > 7*24*time.Hour
	if rebuildIndexes {
		if err := PrepareBulkInsert(ctx, tx); err != nil {
			return fmt.Errorf("could not prepare transaction: %w", err)
		}
	}
	if err := createStagingTables(ctx, tx); err != nil {
		return fmt.Errorf("could not create staging tables: %w", err)
	}

	var cveCount, relationshipCount, affectedComponentCount, cveAffectedComponentCount, exploitCount, malPkgCount, malAffectedComponentCount int
	var cvesTime, relationshipsTime, affectedComponentsTime, cveAffectedComponentsTime, exploitsTime, malPkgTime time.Duration
	ticker := time.NewTicker(4 * time.Second)
	defer ticker.Stop()

	openChans := 0
	if vulnRowsIn != nil {
		openChans++
	}
	if exploitsIn != nil {
		openChans++
	}
	if malPkgIn != nil {
		openChans++
	}

	go func() {
		for range ticker.C {
			if openChans == 0 {
				return
			}
			slog.Info("streaming to database",
				"cves", cveCount, "cves_insert_time", cvesTime.Round(time.Millisecond),
				"relationships", relationshipCount, "relationships_insert_time", relationshipsTime.Round(time.Millisecond),
				"affected_components", affectedComponentCount, "affected_components_insert_time", affectedComponentsTime.Round(time.Millisecond),
				"cve_affected_component", cveAffectedComponentCount, "cve_affected_component_insert_time", cveAffectedComponentsTime.Round(time.Millisecond),
				"exploits", exploitCount, "exploits_insert_time", exploitsTime.Round(time.Millisecond),
				"malicious_packages", malPkgCount, "malicious_packages_insert_time", malPkgTime.Round(time.Millisecond),
				"heap_alloc_mb", heapMB(),
				"took", time.Since(start),
			)
		}
	}()

	for openChans > 0 {
		select {
		case rows, ok := <-vulnRowsIn:
			if !ok {
				vulnRowsIn = nil
				openChans--
				continue
			}
			t := time.Now()
			if err := insertCVEsBulk(ctx, tx, rows.CVEs); err != nil {
				return fmt.Errorf("could not insert cves: %w", err)
			}
			cvesTime += time.Since(t)
			cveCount += len(rows.CVEs)
			t = time.Now()
			if err := insertCVERelationshipsBulk(ctx, tx, rows.CVERelationships); err != nil {
				return fmt.Errorf("could not insert cve relationships: %w", err)
			}
			relationshipsTime += time.Since(t)
			relationshipCount += len(rows.CVERelationships)
			t = time.Now()
			if err := insertAffectedComponentsBulk(ctx, tx, rows.AffectedComponents); err != nil {
				return fmt.Errorf("could not insert affected_components: %w", err)
			}
			affectedComponentsTime += time.Since(t)
			affectedComponentCount += len(rows.AffectedComponents)
			t = time.Now()
			if err := insertCVEAffectedComponentsBulk(ctx, tx, rows.CVEAffectedComponents); err != nil {
				return fmt.Errorf("could not insert cve_affected_component: %w", err)
			}
			cveAffectedComponentsTime += time.Since(t)
			cveAffectedComponentCount += len(rows.CVEAffectedComponents)
		case exploits, ok := <-exploitsIn:
			if !ok {
				exploitsIn = nil
				openChans--
				continue
			}
			t := time.Now()
			if err := insertExploitsBulk(ctx, tx, exploits); err != nil {
				return fmt.Errorf("could not insert exploits: %w", err)
			}
			exploitsTime += time.Since(t)
			exploitCount += len(exploits)
		case malPkg, ok := <-malPkgIn:
			if !ok {
				malPkgIn = nil
				openChans--
				continue
			}
			t := time.Now()
			if err := insertMaliciousPackagesBulk(ctx, tx, malPkg.pkgs, malPkg.comps); err != nil {
				return fmt.Errorf("could not insert malicious packages: %w", err)
			}
			malPkgTime += time.Since(t)
			malPkgCount += len(malPkg.pkgs)
			malAffectedComponentCount += len(malPkg.comps)
		}
	}

	if err := flushStagingTables(ctx, tx); err != nil {
		return fmt.Errorf("could not flush staging tables: %w", err)
	}

	if rebuildIndexes {
		if err := AddIndexesAndConstraints(ctx, tx); err != nil {
			return fmt.Errorf("could not re-add constraints and indexes on table: %w", err)
		}
	}

	slog.Info("finished writing rows to database",
		"cves", cveCount,
		"relationships", relationshipCount,
		"affected_components", affectedComponentCount,
		"cve_affected_component", cveAffectedComponentCount,
		"exploits", exploitCount,
		"malicious_packages", malPkgCount,
		"malicious_affected_components", malAffectedComponentCount,
		"took", time.Since(start),
	)
	return nil
}
