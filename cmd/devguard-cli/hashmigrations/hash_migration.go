package hashmigrations

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/l3montree-dev/devguard/database"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/database/repositories"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/l3montree-dev/devguard/vulndb/scan"
	"github.com/package-url/packageurl-go"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const (
	// Increment this when the hash calculation algorithm changes
	CurrentHashVersion = 8
	// Config key for tracking hash migration version
	HashMigrationVersionKey = "hash_migration_version"
)

func RunHashMigrationsIfNeeded(pool *pgxpool.Pool, daemonRunner shared.DaemonRunner, vulndbService shared.VulnDBService, configService shared.ConfigService) error {
	// Check current version from config table
	var config models.Config
	db := database.NewGormDB(pool)
	err := db.Where("key = ?", HashMigrationVersionKey).First(&config).Error

	if shared.IsNotFound(err) {
		config = models.Config{
			Key: HashMigrationVersionKey,
			Val: "4",
		}
		// save initial version - no migration needed if empty
		if err := db.Create(&config).Error; err != nil {
			return fmt.Errorf("failed to initialize hash migration version: %w", err)
		}

		return nil
	}
	currentVersion := 0
	if err == nil {
		// Parse the version from config
		if parsedVersion, parseErr := strconv.Atoi(config.Val); parseErr == nil {
			currentVersion = parsedVersion
		}
	} else if err != gorm.ErrRecordNotFound {
		return fmt.Errorf("failed to check hash migration version: %w", err)
	}

	if err != nil {
		return err
	}

	// If version is outdated, run migrations
	if currentVersion < CurrentHashVersion {
		slog.Info("Hash algorithm version changed, running hash migrations",
			"current_version", currentVersion,
			"target_version", CurrentHashVersion)

		// Run version 2 migration (CVE hash migration) if needed
		if currentVersion < 2 {
			if err := runCVEHashMigration(pool, daemonRunner); err != nil {
				return fmt.Errorf("failed to run CVE hash migration (v2): %w", err)
			}
		}

		// Run version 3 migration (vulnerability path hash migration) if needed
		if currentVersion < 3 {
			if err := runVulnerabilityPathHashMigration(pool); err != nil {
				return fmt.Errorf("failed to run vulnerability path hash migration (v3): %w", err)
			}
		}

		if currentVersion < 4 {
			// Clear the last import timestamp so ImportRC runs as a full import.
			ctx := context.Background()
			if err := configService.SetJSONConfig(ctx, "vulndb.lastRCImport", ""); err != nil {
				slog.Warn("could not clear vulndb.lastRCImport config", "err", err)
			}
			slog.Info("triggering full vulndb import after hash migration")
			if err := vulndbService.ImportRC(ctx, shared.ImportOptions{}); err != nil {
				return fmt.Errorf("full vulndb import after hash migration failed: %w", err)
			}

			// Persist the new version so this migration does not re-run on the next startup.
			config.Val = strconv.Itoa(CurrentHashVersion)
			if err := db.Save(&config).Error; err != nil {
				return fmt.Errorf("failed to update hash migration version after v4: %w", err)
			}
		}

		if currentVersion < 5 {
			// we need to calculate the signature for all existing dependency_vulns and update them in the database
			if err := runDependencyVulnSignatureMigration(pool); err != nil {
				return fmt.Errorf("failed to run dependency_vuln signature migration (v5): %w", err)
			}

			// cve_scope was added as a plain column with no backfill - existing
			// vex_rules/upstream_vex_rules rows need it computed from their
			// cel_expression, same as SetCELExpression/EnsureID now do for new rows.
			if err := runVEXRuleCVEScopeBackfill(pool); err != nil {
				return fmt.Errorf("failed to backfill VEX rule cve_scope (v5): %w", err)
			}

			// Persist the new version so this migration does not re-run on the next startup.
			config.Val = strconv.Itoa(CurrentHashVersion)
			if err := db.Save(&config).Error; err != nil {
				return fmt.Errorf("failed to update hash migration version after v5: %w", err)
			}
		}

		if currentVersion < 6 {
			// v5 replaced one_vuln_parent with
			// vuln_events_dependency_vuln_id_or_asset_signature, but that
			// constraint originally omitted security_advisory_id, so it
			// rejected every advisory-created vuln event (which only sets
			// SecurityAdvisoryID). Installations that already ran v5 are
			// stuck with the broken constraint and never re-enter that
			// branch, so fix it here explicitly.
			if err := runVulnEventsSecurityAdvisoryConstraintFix(pool); err != nil {
				return fmt.Errorf("failed to fix vuln_events security_advisory_id constraint (v6): %w", err)
			}

			// Persist the new version so this migration does not re-run on the next startup.
			config.Val = strconv.Itoa(CurrentHashVersion)
			if err := db.Save(&config).Error; err != nil {
				return fmt.Errorf("failed to update hash migration version after v6: %w", err)
			}
		}

		if currentVersion < 7 {
			// Rebuild the content-addressed SBOM storage from the legacy
			// component_dependencies table, so upgrading instances keep their
			// SBOMs rather than having to rescan everything.
			if err := runMerkleBackfill(pool); err != nil {
				return fmt.Errorf("failed to backfill merkle sboms (v7): %w", err)
			}

			// Persist the new version so this migration does not re-run on the next startup.
			config.Val = strconv.Itoa(CurrentHashVersion)
			if err := db.Save(&config).Error; err != nil {
				return fmt.Errorf("failed to update hash migration version after v7: %w", err)
			}
		}

		if currentVersion < 8 {
			// dividing merkle edges into edges and nodes tables
			// removing artifact names from subtree_hash calculation
			// in order to achieve better deduplication
			if err := rewireMerkleTreeRootsAndSplitNodes(pool); err != nil {
				return fmt.Errorf("failed fixing artifact names in merkle subtree hashes (v8): %w", err)
			}

			// Persist the new version so this migration does not re-run on the next startup.
			config.Val = strconv.Itoa(CurrentHashVersion)
			if err := db.Save(&config).Error; err != nil {
				return fmt.Errorf("failed to update hash migration version after v8: %w", err)
			}

			startVacuum := time.Now()
			slog.Info("start vacuum and analyzing all tables")
			_, err = pool.Exec(context.Background(), `
				VACUUM FULL public.sbom_merkle_edges;`)
			if err != nil {
				return fmt.Errorf("could not full vacuum edges table: %w", err)
			}

			_, err = pool.Exec(context.Background(), `
				VACUUM ANALYZE;`)
			if err != nil {
				return fmt.Errorf("could not vacuum and analyze all tables: %w", err)
			}
			slog.Info("finished vacuum and analyzing all tables", "time", time.Since(startVacuum))
		}

		slog.Info("Hash migrations completed successfully", "version", CurrentHashVersion)
	}

	return nil
}

func rewireMerkleTreeRootsAndSplitNodes(pool *pgxpool.Pool) error {
	start := time.Now()
	slog.Info("start hash migration v8")
	ctx := context.Background()

	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("could not start transaction for v8: %w", err)
	}
	defer tx.Rollback(ctx)

	// drop unique constraint to temporarily allow duplicates inside the transaction
	// also improves performance on DML operations
	_, err = tx.Exec(ctx, `
	ALTER TABLE sbom_merkle_edges DROP CONSTRAINT sbom_merkle_edges_unique;`)
	if err != nil {
		return fmt.Errorf("could not drop unique constraint on edges table: %w", err)
	}

	// first remove the component_id from root nodes
	_, err = tx.Exec(ctx, `
		UPDATE sbom_merkle_edges sm
		SET component_id = $1
		WHERE EXISTS (
				SELECT FROM sboms s 
				WHERE s.root_subtree_hash = sm.subtree_hash
		);`, normalize.MerkleRootID)
	if err != nil {
		return fmt.Errorf("could not remove component_id from root edges: %w", err)
	}
	slog.Info("removed component_id from root nodes")

	// now recalculate the hash based on only the subtree's hashes
	rows, err := tx.Query(ctx, `
		SELECT subtree_hash, direct_dependency_subtree_hash
		FROM sbom_merkle_edges sm 
		WHERE EXISTS (
			SELECT FROM sboms s 
			WHERE s.root_subtree_hash = sm.subtree_hash
		);`)
	if err != nil {
		return fmt.Errorf("could not query root nodes from merkle edge table: %w", err)
	}
	defer rows.Close()

	edgesPerRoot := make(map[uuid.UUID][]uuid.UUID, 75_000)
	var root uuid.UUID
	var edge *uuid.UUID
	for rows.Next() {
		err = rows.Scan(&root, &edge)
		if err != nil {
			return fmt.Errorf("could not scan row: %w", err)
		}
		// also collect nodes with nil edges
		if _, ok := edgesPerRoot[root]; !ok {
			edgesPerRoot[root] = nil
		}
		if edge != nil {
			edgesPerRoot[root] = append(edgesPerRoot[root], *edge)
		}
	}
	rows.Close()

	if err := rows.Err(); err != nil {
		return fmt.Errorf("error occurred whilst scanning rows: %w", err)
	}
	slog.Info("collected root nodes")

	// now we build the new hashes for the root nodes without including the component_id
	oldHashes := make([]uuid.UUID, len(edgesPerRoot))
	newHashes := make([]uuid.UUID, len(edgesPerRoot))
	i := 0
	for root, edges := range edgesPerRoot {
		oldHashes[i] = root
		newHashes[i] = normalize.HashSubtree(normalize.MerkleRootID, edges)
		i++
	}

	_, err = tx.Exec(ctx, `
	UPDATE sbom_merkle_edges sm SET subtree_hash = sub.new_hash
		FROM (
			SELECT 
				UNNEST($1::uuid[]) as old_hash,
				UNNEST($2::uuid[]) as new_hash
		) as sub
	WHERE sub.old_hash = sm.subtree_hash;
	`, oldHashes, newHashes)
	if err != nil {
		return fmt.Errorf("could not update edges root nodes: %w", err)
	}
	slog.Info("updated edges root nodes")

	_, err = tx.Exec(ctx, `
	UPDATE sboms s SET root_subtree_hash = sub.new_hash
		FROM (
			SELECT 
				UNNEST($1::uuid[]) as old_hash,
				UNNEST($2::uuid[]) as new_hash
		) as sub
	WHERE sub.old_hash = s.root_subtree_hash;
	`, oldHashes, newHashes)
	if err != nil {
		return fmt.Errorf("could not update sbom root nodes: %w", err)
	}
	slog.Info("updated sbom root nodes")

	results, err := tx.Exec(ctx, `
	DELETE FROM sbom_merkle_edges a
	USING sbom_merkle_edges b
	WHERE a.subtree_hash = b.subtree_hash
	AND a.direct_dependency_subtree_hash = b.direct_dependency_subtree_hash
	AND a.ctid > b.ctid;`)
	if err != nil {
		return fmt.Errorf("could not remove duplicates from edges table: %w", err)
	}
	slog.Info("removed duplicates from edges table", "amount", results.RowsAffected())

	// now we continue with separating nodes from the edges table
	_, err = tx.Exec(ctx, `
		INSERT INTO public.sbom_merkle_nodes (node_hash, component_id) (
			SELECT DISTINCT subtree_hash, component_id
			FROM sbom_merkle_edges
		);`)
	if err != nil {
		return fmt.Errorf("could not transfer nodes from edges to nodes table: %w", err)
	}

	_, err = tx.Exec(ctx, `
	ALTER TABLE public.sbom_merkle_edges DROP COLUMN component_id;`)
	if err != nil {
		return fmt.Errorf("could not drop component_id column from edges table: %w", err)
	}

	// ensure referential integrity between edges and nodes
	_, err = tx.Exec(ctx, `
		ALTER TABLE public.sbom_merkle_edges 
			ADD FOREIGN KEY (subtree_hash) 
				REFERENCES public.sbom_merkle_nodes (node_hash),
			ADD FOREIGN KEY (direct_dependency_subtree_hash) 
				REFERENCES public.sbom_merkle_nodes (node_hash);`)
	if err != nil {
		return fmt.Errorf("could not check apply foreign key from edges to nodes: %w", err)
	}

	// ensure referential integrity between sboms and nodes
	_, err = tx.Exec(ctx, `
		ALTER TABLE public.sboms
		ADD FOREIGN KEY (root_subtree_hash) 
		REFERENCES public.sbom_merkle_nodes (node_hash);`)
	if err != nil {
		return fmt.Errorf("could not check apply foreign key from sboms to nodes: %w", err)
	}
	slog.Info("dropped component_id and applied all referential integrity checks")

	// delete all leaf edges
	results, err = tx.Exec(ctx, `
		DELETE FROM public.sbom_merkle_edges sme
		WHERE sme.direct_dependency_subtree_hash IS NULL;`)
	if err != nil {
		return fmt.Errorf("could not delete leaf edges: %w", err)
	}
	slog.Info("deleted all leaf edges", "amount", results.RowsAffected())

	_, err = tx.Exec(ctx, `
	ALTER TABLE public.sbom_merkle_edges 
	ADD PRIMARY KEY (subtree_hash, direct_dependency_subtree_hash);`)
	if err != nil {
		return fmt.Errorf("could not add primary key constraint to edges table: %w", err)
	}
	slog.Info("added primary key constraint to edges table", "time", time.Since(start))

	_, err = tx.Exec(ctx, `
		CREATE INDEX sbom_merkle_nodes_component_id 
		ON public.sbom_merkle_nodes (component_id);`)
	if err != nil {
		return fmt.Errorf("could not create component_id index for nodes table: %w", err)
	}
	slog.Info("added primary key constraint to edges table", "time", time.Since(start))

	err = tx.Commit(ctx)
	if err != nil {
		return fmt.Errorf("could not commit migration v8: %w", err)
	}
	slog.Info("successfully finished v8 migration", "time", time.Since(start))

	return nil
}

func runDependencyVulnSignatureMigration(pool *pgxpool.Pool) error {
	start := time.Now()
	defer func() {
		slog.Info("dependency_vuln signature migration completed", "duration", time.Since(start))
	}()
	db := database.NewGormDB(pool)
	depVulnRepo := repositories.NewDependencyVulnRepository(db)
	return db.Transaction(func(tx *gorm.DB) error {
		total := 0
		// fetch all in batches and update the signature
		for batch, err := range depVulnRepo.InBatches(context.Background(), tx, 5_000) {
			if err != nil {
				return fmt.Errorf("failed to fetch dependency_vulns in batches: %w", err)
			}

			total += len(batch)

			if total%100_000 == 0 {
				slog.Info("updating dependency_vuln signatures", "processed", total)
			}
			// just update the signature for each vuln and save it back to the database
			for i := range batch {
				batch[i].Signature = batch[i].CalculateSignature()
				batch[i].AssetSignature = utils.HashToInt64(batch[i].CalculateAssetVersionIndependentHash())
			}

			if err := depVulnRepo.SaveBatch(context.Background(), tx, batch); err != nil {
				return fmt.Errorf("failed to update dependency_vuln signatures in batch: %w", err)
			}
		}

		// The optimize_vex_rule_daemon schema migration intentionally skips adding this constraint
		// because existing installations have millions of vuln_events rows for license risks /
		// first-party vulns / compliance postures where dependency_vuln_id and asset_signature are
		// both legitimately NULL. Add it here, scoped to the columns that actually identify a vuln
		// event, now that we know the signature backfill above has run.
		// the old one_vuln_parent constraint required exactly one of
		// dependency_vuln_id/license_risk_id/first_party_vuln_id/compliance_posture_id
		// to be set, which rejects asset_signature-only group events outright -
		// superseded by the constraint added below.
		if err := tx.Exec(`
			ALTER TABLE public.vuln_events DROP CONSTRAINT IF EXISTS one_vuln_parent
		`).Error; err != nil {
			return fmt.Errorf("failed to drop vuln_events one_vuln_parent constraint: %w", err)
		}
		if err := tx.Exec(`
		ALTER TABLE public.vuln_events
			ADD CONSTRAINT vuln_events_dependency_vuln_id_or_asset_signature
			CHECK (
				dependency_vuln_id IS NOT NULL
				OR asset_signature IS NOT NULL
				OR license_risk_id IS NOT NULL
				OR first_party_vuln_id IS NOT NULL
				OR compliance_posture_id IS NOT NULL
				OR security_advisory_id IS NOT NULL
			) NOT VALID
	`).Error; err != nil {
			return fmt.Errorf("failed to add vuln_events dependency_vuln_id_or_asset_signature constraint: %w", err)
		}
		if err := tx.Exec(`
		ALTER TABLE public.vuln_events
			VALIDATE CONSTRAINT vuln_events_dependency_vuln_id_or_asset_signature
	`).Error; err != nil {
			return fmt.Errorf("failed to validate vuln_events dependency_vuln_id_or_asset_signature constraint: %w", err)
		}
		return nil
	})

}

func runVulnEventsSecurityAdvisoryConstraintFix(pool *pgxpool.Pool) error {
	start := time.Now()
	defer func() {
		slog.Info("vuln_events security_advisory_id constraint fix completed", "duration", time.Since(start))
	}()
	db := database.NewGormDB(pool)
	return db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec(`
			ALTER TABLE public.vuln_events DROP CONSTRAINT IF EXISTS vuln_events_dependency_vuln_id_or_asset_signature
		`).Error; err != nil {
			return fmt.Errorf("failed to drop vuln_events dependency_vuln_id_or_asset_signature constraint: %w", err)
		}
		if err := tx.Exec(`
			ALTER TABLE public.vuln_events
				ADD CONSTRAINT vuln_events_dependency_vuln_id_or_asset_signature
				CHECK (
					dependency_vuln_id IS NOT NULL
					OR asset_signature IS NOT NULL
					OR license_risk_id IS NOT NULL
					OR first_party_vuln_id IS NOT NULL
					OR compliance_posture_id IS NOT NULL
					OR security_advisory_id IS NOT NULL
				) NOT VALID
		`).Error; err != nil {
			return fmt.Errorf("failed to add vuln_events dependency_vuln_id_or_asset_signature constraint: %w", err)
		}
		if err := tx.Exec(`
			ALTER TABLE public.vuln_events
				VALIDATE CONSTRAINT vuln_events_dependency_vuln_id_or_asset_signature
		`).Error; err != nil {
			return fmt.Errorf("failed to validate vuln_events dependency_vuln_id_or_asset_signature constraint: %w", err)
		}
		return nil
	})
}

// runVEXRuleCVEScopeBackfill computes cve_scope for every existing vex_rules
// and upstream_vex_rules row from its cel_expression. cve_scope was added as a
// plain column with no backfill, and SetCELExpression/EnsureID only compute it
// going forward - existing rows are stuck at NULL until this runs.
func runVEXRuleCVEScopeBackfill(pool *pgxpool.Pool) error {
	start := time.Now()
	defer func() {
		slog.Info("VEX rule cve_scope backfill completed", "duration", time.Since(start))
	}()
	db := database.NewGormDB(pool)

	return db.Transaction(func(tx *gorm.DB) error {
		var upstreamRules []models.UpstreamVEXRule
		if err := tx.FindInBatches(&upstreamRules, 2_000, func(_ *gorm.DB, _ int) error {
			for i := range upstreamRules {
				upstreamRules[i].CVEScope = models.ExtractCVEScopeFromCELExpression(upstreamRules[i].CELExpression)
				if err := tx.Save(&upstreamRules[i]).Error; err != nil {
					return fmt.Errorf("failed to save upstream_vex_rules row %s: %w", upstreamRules[i].ID, err)
				}
			}
			return nil
		}).Error; err != nil {
			return fmt.Errorf("failed to backfill upstream_vex_rules cve_scope: %w", err)
		}

		var vexRules []models.VEXRule
		if err := tx.FindInBatches(&vexRules, 2_000, func(_ *gorm.DB, _ int) error {
			for i := range vexRules {
				vexRules[i].CVEScope = models.ExtractCVEScopeFromCELExpression(vexRules[i].CELExpression)
				if err := tx.Save(&vexRules[i]).Error; err != nil {
					return fmt.Errorf("failed to save vex_rules row %s: %w", vexRules[i].ID, err)
				}
			}
			return nil
		}).Error; err != nil {
			return fmt.Errorf("failed to backfill vex_rules cve_scope: %w", err)
		}

		return nil
	})
}

// this function handles the migration for importing new CVEs from the OSV.
// existing components may now have (multiple) different CVEs associated with them and we need to first determine affected dependency_vulns, then update the assigned CVE and lastly adjust the hash on the dependency_vuln itself and all references
func runCVEHashMigration(pool *pgxpool.Pool, daemonRunner shared.DaemonRunner) error {
	// Start health check server for kubernetes liveness/readiness probes during migration
	healthServer := &http.Server{
		Addr: ":8080",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("migration in progress")) //nolint:errcheck
		}),
	}

	go func() {
		slog.Info("Starting health check server on :8080 during migration")
		if err := healthServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("health check server error", "err", err)
		}
	}()

	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := healthServer.Shutdown(ctx); err != nil {
			slog.Error("failed to shutdown health check server", "err", err)
		}
	}()
	db := database.NewGormDB(pool)
	// Disable slow query logs for this migration
	db = db.Session(&gorm.Session{
		Logger: logger.New(
			slog.NewLogLogger(slog.Default().Handler(), slog.LevelError),
			logger.Config{
				SlowThreshold:             0, // Disable slow query logging
				LogLevel:                  logger.Error,
				IgnoreRecordNotFoundError: true,
				Colorful:                  false,
			},
		),
	})

	slog.Info("start running cve migration...")
	// Load all vulns with artifacts and events
	var allVulns []models.DependencyVuln
	err := db.Preload("Artifacts").Preload("Events").Find(&allVulns).Error
	if err != nil {
		panic(err)
	}

	pc := scan.NewPurlComparer(db, new(0)) // no cache should be fine
	totalVulns := len(allVulns)
	slog.Info("Starting CVE hash migration", "total", totalVulns)

	// Phase 1: Fetch all CVE data concurrently
	type vulnResult struct {
		oldVuln    models.DependencyVuln
		vulnsInPkg []models.VulnInPackage
		err        error
	}

	numWorkers := min(runtime.NumCPU()*4, 64)

	jobs := make(chan models.DependencyVuln, numWorkers*4)
	results := make(chan vulnResult, numWorkers*4)

	// Cache for the vuln lookups - same PURL will return same vulns
	type cacheEntry struct {
		vulns []models.VulnInPackage
		err   error
	}
	var cacheMu sync.RWMutex
	purlCache := make(map[string]cacheEntry)

	var fetchWg sync.WaitGroup
	for range numWorkers {
		fetchWg.Go(func() {
			for v := range jobs {
				purl := v.ComponentPurl

				// Check cache first
				cacheMu.RLock()
				cached, found := purlCache[purl]
				cacheMu.RUnlock()

				if found {
					results <- vulnResult{oldVuln: v, vulnsInPkg: cached.vulns, err: cached.err}
					continue
				}

				// Not in cache - fetch and store
				parsedPurl, err := packageurl.FromString(purl)
				if err != nil {
					cacheMu.Lock()
					purlCache[purl] = cacheEntry{err: err}
					cacheMu.Unlock()
					results <- vulnResult{oldVuln: v, err: err}
					continue
				}

				vulnsInPackage, err := pc.GetVulns(context.Background(), []packageurl.PackageURL{parsedPurl})

				cacheMu.Lock()
				purlCache[purl] = cacheEntry{vulns: vulnsInPackage, err: err}
				cacheMu.Unlock()

				results <- vulnResult{oldVuln: v, vulnsInPkg: vulnsInPackage, err: err}
			}
		})
	}

	go func() {
		fetchWg.Wait()
		close(results)
	}()

	go func() {
		for _, v := range allVulns {
			jobs <- v
		}
		close(jobs)
	}()

	// Collect all results first (fast - just memory operations)
	allResults := make([]vulnResult, 0, totalVulns)
	for result := range results {
		if result.err != nil {
			slog.Error("could not process purl", "purl", result.oldVuln.ComponentPurl, "err", result.err)
			return result.err
		}
		allResults = append(allResults, result)
	}

	// Group results by (AssetID, AssetVersionName, PURL) - this is critical to handle multiple old CVEs correctly
	// Vulns are scoped to specific asset versions, not just PURLs
	type groupKey struct {
		assetID          string
		assetVersionName string
		purl             string
	}
	type purlGroup struct {
		key      groupKey
		oldVulns []models.DependencyVuln
		newVulns []models.VulnInPackage
	}
	purlGroups := make(map[groupKey]*purlGroup)
	for _, result := range allResults {
		key := groupKey{
			assetID:          result.oldVuln.AssetID.String(),
			assetVersionName: result.oldVuln.AssetVersionName,
			purl:             result.oldVuln.ComponentPurl,
		}
		if purlGroups[key] == nil {
			purlGroups[key] = &purlGroup{
				key:      key,
				oldVulns: make([]models.DependencyVuln, 0),
				newVulns: result.vulnsInPkg, // All oldVulns for same key have same newVulns (cached)
			}
		}
		purlGroups[key].oldVulns = append(purlGroups[key].oldVulns, result.oldVuln)
	}

	slog.Info("Grouped vulnerabilities", "totalGroups", len(purlGroups), "totalOldVulns", len(allResults))

	// Phase 2: Prepare all data for bulk operations
	createdVulnIDs := make(map[uuid.UUID]bool)
	copiedTicketIDs := make(map[string]bool) // Track which ticket IDs have already been assigned
	var vulnsToCreate []models.DependencyVuln
	var eventsToCreate []models.VulnEvent

	// Process each asset version + PURL group
	for _, group := range purlGroups {
		// Resolve which old CVEs map to which new CVEs for this asset version + PURL
		resolved := resolveCVERelationsForPurl(group.oldVulns, group.newVulns)

		// Process all new CVEs for this PURL
		for _, create := range resolved.creates {
			newVuln := create.newVuln
			if create.copyStateFrom != nil {
				// Copy all state and risk assessment fields from the old vuln
				newVuln.State = create.copyStateFrom.State
				newVuln.RiskAssessment = create.copyStateFrom.RiskAssessment
				newVuln.RiskRecalculatedAt = create.copyStateFrom.RiskRecalculatedAt

				// Only copy ticket ID and URL once per ticket to avoid duplicate ticket associations
				if create.copyStateFrom.TicketID != nil && !copiedTicketIDs[*create.copyStateFrom.TicketID] {
					newVuln.TicketID = create.copyStateFrom.TicketID
					newVuln.TicketURL = create.copyStateFrom.TicketURL
					newVuln.ManualTicketCreation = create.copyStateFrom.ManualTicketCreation
					copiedTicketIDs[*create.copyStateFrom.TicketID] = true
				}

				// Copy artifacts
				newVuln.Artifacts = create.copyStateFrom.Artifacts
			}

			vulnHash := newVuln.CalculateHash()
			if createdVulnIDs[vulnHash] {
				continue
			}
			createdVulnIDs[vulnHash] = true
			newVuln.ID = vulnHash

			vulnsToCreate = append(vulnsToCreate, newVuln)

			// copyStateFrom is guaranteed to be non-nil now (we filter above)
			for _, event := range create.copyStateFrom.Events {
				event.ID = uuid.New() // Generate new ID to avoid duplicates
				event.DependencyVulnID = new(vulnHash)
				eventsToCreate = append(eventsToCreate, event)
			}
		}

	}

	slog.Info("Prepared bulk data", "vulnsToCreate", len(vulnsToCreate), "eventsToCreate", len(eventsToCreate))

	// Phase 3: Bulk database operations
	err = db.Transaction(func(tx *gorm.DB) error {
		batchSize := 1000

		// Step 1: Delete ALL dependency vuln related data (we're recreating everything)
		slog.Info("Deleting all dependency vuln events...")
		if err := tx.Exec("DELETE FROM vuln_events WHERE dependency_vuln_id IS NOT NULL").Error; err != nil {
			slog.Error("failed to delete all dependency vuln events", "err", err)
			return err
		}

		slog.Info("Deleting all artifact_dependency_vulns...")
		if err := tx.Exec("DELETE FROM artifact_dependency_vulns").Error; err != nil {
			slog.Error("failed to delete all artifact_dependency_vulns", "err", err)
			return err
		}

		slog.Info("Deleting all dependency_vulns...")
		if err := tx.Exec("DELETE FROM dependency_vulns").Error; err != nil {
			slog.Error("failed to delete all dependency_vulns", "err", err)
			return err
		}
		slog.Info("Deleted all old data")

		// Step 2: Create new vulns in batches
		for i := 0; i < len(vulnsToCreate); i += batchSize {
			end := min(i+batchSize, len(vulnsToCreate))
			batch := vulnsToCreate[i:end]

			if err := tx.Create(batch).Error; err != nil {
				slog.Error("failed to bulk create vulns", "err", err)
				return err
			}

			// Associate artifacts for this batch
			for j := range batch {
				if len(batch[j].Artifacts) > 0 {
					if err := tx.Model(&batch[j]).Association("Artifacts").Replace(batch[j].Artifacts); err != nil {
						slog.Error("failed to associate artifacts", "vulnID", batch[j].ID, "err", err)
						return err
					}
				}
			}
		}

		// Step 4: Create new events in batches
		for i := 0; i < len(eventsToCreate); i += batchSize {
			end := min(i+batchSize, len(eventsToCreate))
			if err := tx.Create(eventsToCreate[i:end]).Error; err != nil {
				slog.Error("failed to bulk create events", "err", err)
				return err
			}
		}

		// Update hash migration version
		config := models.Config{
			Key: HashMigrationVersionKey,
			Val: strconv.Itoa(2),
		}
		if err := tx.Save(&config).Error; err != nil {
			slog.Error("failed to update hash migration version", "err", err)
			return err
		}

		slog.Info("finished cve hash migration successfully")
		return nil
	})

	if err != nil {
		slog.Error("cve hash migration failed", "err", err)
		return err
	}

	// Clean up orphaned rows before recreating foreign key constraints.
	// The vulnDB import runs with DisableForeignKeyFix=true so orphaned references
	// may have accumulated and would cause constraint creation to fail.
	err = db.Exec(`
			DELETE FROM public.dependency_vulns
			WHERE NOT EXISTS (
				SELECT 1 FROM public.cves WHERE cves.cve = dependency_vulns.cve_id
			);

			DELETE FROM public.cve_affected_component
			WHERE NOT EXISTS (
				SELECT 1 FROM public.cves WHERE cves.id = cve_affected_component.cve_id
			);

			DELETE FROM public.cve_affected_component
			WHERE NOT EXISTS (
				SELECT 1 FROM public.affected_components WHERE affected_components.id = cve_affected_component.affected_component_id
			);

			DELETE FROM public.cve_relationships
			WHERE NOT EXISTS (
				SELECT 1 FROM public.cves WHERE cves.cve = cve_relationships.source_cve
			);
		`).Error
	if err != nil {
		return fmt.Errorf("failed to clean up orphaned rows before recreating FK constraints: %w", err)
	}

	// Recreate the foreign key constraints as cleanup
	err = db.Exec(`
			ALTER TABLE public.dependency_vulns
			ADD CONSTRAINT fk_dependency_vulns_cve
			FOREIGN KEY (cve_id) REFERENCES public.cves(cve)
			ON DELETE CASCADE ON UPDATE CASCADE;

			ALTER TABLE public.cve_affected_component
			ADD CONSTRAINT fk_cve_affected_component_cve
			FOREIGN KEY (cve_id) REFERENCES public.cves(id)
			ON DELETE CASCADE ON UPDATE CASCADE;

			ALTER TABLE ONLY public.cve_affected_component
			ADD CONSTRAINT fk_cve_affected_component_affected_component
			FOREIGN KEY (affected_component_id) REFERENCES public.affected_components(id)
			ON UPDATE CASCADE ON DELETE CASCADE;

			ALTER TABLE ONLY public.cve_relationships
    		ADD CONSTRAINT fk_cve_relationships_cve
			FOREIGN KEY (source_cve) REFERENCES public.cves(cve)
			ON UPDATE CASCADE ON DELETE CASCADE;
		`).Error

	if err != nil {
		return err
	}

	return nil
}

type vulnCreate struct {
	newVuln       models.DependencyVuln
	copyStateFrom *models.DependencyVuln // Copy state/artifacts/events from this vuln
}

type resolveResult struct {
	creates []vulnCreate
}

// resolveCVERelationsForPurl processes all old vulns for a PURL together to determine
// which new CVEs should be created and which old CVE should donate state to each new one
func resolveCVERelationsForPurl(oldVulns []models.DependencyVuln, foundVulns []models.VulnInPackage) resolveResult {
	creates := []vulnCreate{}

	// No new vulns found - just delete all old ones (CVEs no longer apply)
	if len(foundVulns) == 0 {
		return resolveResult{creates: creates}
	}

	// Use first old vuln for metadata (they all have same PURL, asset, etc.)
	firstOld := oldVulns[0]

	// For each new CVE, check which old CVEs have relationships to it
	for _, foundVuln := range foundVulns {
		// Create vuln directly - v3 migration will add proper paths later
		newVuln := models.DependencyVuln{
			Vulnerability: models.Vulnerability{
				AssetVersionName: firstOld.AssetVersionName,
				AssetID:          firstOld.AssetID,
			},
			CVEID:             foundVuln.CVEID,
			ComponentPurl:     firstOld.ComponentPurl,
			CVE:               &foundVuln.CVE,
			VulnerabilityPath: nil, // Will be populated by v3 migration
		}

		// Find which old CVE (if any) should donate state to this new CVE
		// Priority: 1) exact CVE ID match, 2) relationship match
		var copyStateFrom *models.DependencyVuln = nil
		// If no exact match, check relationships
		for i := range oldVulns {
			if isRelatedCVE(oldVulns[i].CVEID, foundVuln.CVE.Relationships) {
				copyStateFrom = &oldVulns[i]
				break // First match wins
			}
		}

		newVuln.ID = newVuln.CalculateHash()

		// Only create vulns that have state to copy from
		// New vulns without prior state will be discovered by regular scanning
		if copyStateFrom != nil {
			creates = append(creates, vulnCreate{
				newVuln:       newVuln,
				copyStateFrom: copyStateFrom,
			})
		}
	}

	return resolveResult{creates: creates}
}

func isRelatedCVE(cveID string, relationships []models.CVERelationship) bool {
	for _, rel := range relationships {
		if rel.TargetCVE == cveID {
			return true
		}
	}
	return false
}

// runVulnerabilityPathHashMigration handles the migration for adding vulnerability_path to the hash.
// This migration loads the SBOM graph for each asset version and calculates the paths to each
// vulnerable component. Vulns that have multiple paths will be split into multiple vulns.
//
// To avoid OOM, this processes one asset version at a time and flushes to the DB
// before moving on. The entire migration runs inside a single transaction so
// a failure at any point rolls back to the original state.
func runVulnerabilityPathHashMigration(pool *pgxpool.Pool) error {
	db := database.NewGormDB(pool)
	// Disable slow query logs for this migration
	db = db.Session(&gorm.Session{
		Logger: logger.New(
			slog.NewLogLogger(slog.Default().Handler(), slog.LevelError),
			logger.Config{
				SlowThreshold:             0,
				LogLevel:                  logger.Error,
				IgnoreRecordNotFoundError: true,
				Colorful:                  false,
			},
		),
	})

	slog.Info("Starting vulnerability path hash migration (v3)...")

	// Get distinct asset version keys (lightweight query, no preloading)
	type assetVersionKey struct {
		AssetID          uuid.UUID `gorm:"column:asset_id"`
		AssetVersionName string    `gorm:"column:asset_version_name"`
	}
	var assetVersionKeys []assetVersionKey
	if err := db.Raw("SELECT DISTINCT asset_id, asset_version_name FROM dependency_vulns").Scan(&assetVersionKeys).Error; err != nil {
		return fmt.Errorf("failed to load asset version keys: %w", err)
	}

	if len(assetVersionKeys) == 0 {
		slog.Info("No dependency vulns to migrate")
		config := models.Config{
			Key: HashMigrationVersionKey,
			Val: strconv.Itoa(CurrentHashVersion),
		}
		return db.Save(&config).Error
	}

	slog.Info("Found asset versions to migrate", "count", len(assetVersionKeys))

	// Run everything in a single transaction so failures roll back safely
	err := db.Transaction(func(tx *gorm.DB) error {
		batchSize := 1000

		// Delete all old dependency vuln related data
		slog.Info("Deleting all dependency vuln events...")
		if err := tx.Exec("DELETE FROM vuln_events WHERE dependency_vuln_id IS NOT NULL").Error; err != nil {
			return fmt.Errorf("failed to delete dependency vuln events: %w", err)
		}
		slog.Info("Deleting all artifact_dependency_vulns...")
		if err := tx.Exec("DELETE FROM artifact_dependency_vulns").Error; err != nil {
			return fmt.Errorf("failed to delete artifact_dependency_vulns: %w", err)
		}
		slog.Info("Deleting all dependency_vulns...")
		if err := tx.Exec("DELETE FROM dependency_vulns").Error; err != nil {
			return fmt.Errorf("failed to delete dependency_vulns: %w", err)
		}

		createdVulnIDs := make(map[uuid.UUID]bool)
		copiedTicketIDs := make(map[string]bool)

		// Process each asset version independently, flushing to DB each iteration
		for groupIdx, key := range assetVersionKeys {
			slog.Info("Processing asset version", "group", groupIdx+1, "total", len(assetVersionKeys),
				"assetID", key.AssetID, "assetVersionName", key.AssetVersionName)

			// Load vulns scoped to this asset version only
			var vulns []models.DependencyVuln
			if err := tx.Preload("Artifacts").Preload("Events").
				Where("asset_id = ? AND asset_version_name = ?", key.AssetID, key.AssetVersionName).
				Find(&vulns).Error; err != nil {
				return fmt.Errorf("failed to load vulns for asset version %s/%s: %w", key.AssetID, key.AssetVersionName, err)
			}

			if len(vulns) == 0 {
				continue
			}

			// Collect new vulns and events for this asset version only
			var vulnsToCreate []models.DependencyVuln
			var eventsToCreate []models.VulnEvent

			// Rebuild this asset version's SBOMs from the legacy edge table.
			// This migration predates the content-addressed storage, so any
			// instance still on it has its graph only in component_dependencies.
			var legacyEdges []legacyEdge
			err := tx.Raw(`
				SELECT asset_id, asset_version_name, component_id, dependency_id
				FROM component_dependencies
				WHERE asset_id = ? AND asset_version_name = ?
			`, key.AssetID, key.AssetVersionName).Scan(&legacyEdges).Error
			if err != nil {
				return fmt.Errorf("failed to load components for asset version %s/%s: %w", key.AssetID, key.AssetVersionName, err)
			} else {
				var sbom normalize.MerkleForest
				for _, reconstructed := range reconstructSBOMs(legacyEdges) {
					sbom = append(sbom, reconstructed.Tree)
				}

				for _, oldVuln := range vulns {
					paths := sbom.PathsToPURL(oldVuln.ComponentPurl, 0)

					if len(paths) == 0 {
						slog.Warn("No SBOM paths found for vulnerable component, using empty path",
							"assetID", key.AssetID,
							"assetVersionName", key.AssetVersionName,
							"componentPurl", oldVuln.ComponentPurl)

						newVuln := oldVuln
						newVuln.VulnerabilityPath = nil
						newVuln.ID = newVuln.CalculateHash()

						if !createdVulnIDs[newVuln.ID] {
							createdVulnIDs[newVuln.ID] = true
							if oldVuln.TicketID != nil && copiedTicketIDs[*oldVuln.TicketID] {
								newVuln.TicketID = nil
								newVuln.TicketURL = nil
							} else if oldVuln.TicketID != nil {
								copiedTicketIDs[*oldVuln.TicketID] = true
							}
							vulnsToCreate = append(vulnsToCreate, newVuln)
							for _, event := range oldVuln.Events {
								event.ID = uuid.New()
								event.DependencyVulnID = new(newVuln.ID)
								eventsToCreate = append(eventsToCreate, event)
							}
						}
					} else {
						for _, path := range paths {
							newVuln := oldVuln
							newVuln.VulnerabilityPath = path
							newVuln.ID = newVuln.CalculateHash()

							if !createdVulnIDs[newVuln.ID] {
								createdVulnIDs[newVuln.ID] = true
								if oldVuln.TicketID != nil && copiedTicketIDs[*oldVuln.TicketID] {
									newVuln.TicketID = nil
									newVuln.TicketURL = nil
								} else if oldVuln.TicketID != nil {
									copiedTicketIDs[*oldVuln.TicketID] = true
								}
								vulnsToCreate = append(vulnsToCreate, newVuln)
								for _, event := range oldVuln.Events {
									event.ID = uuid.New()
									event.DependencyVulnID = new(newVuln.ID)
									eventsToCreate = append(eventsToCreate, event)
								}
							}
						}
					}
				}
			}

			// Flush this asset version's data to DB immediately
			for i := 0; i < len(vulnsToCreate); i += batchSize {
				end := min(i+batchSize, len(vulnsToCreate))
				batch := vulnsToCreate[i:end]

				if err := tx.Create(batch).Error; err != nil {
					return fmt.Errorf("failed to create vulns batch: %w", err)
				}

				for j := range batch {
					if len(batch[j].Artifacts) > 0 {
						if err := tx.Model(&batch[j]).Association("Artifacts").Replace(batch[j].Artifacts); err != nil {
							return fmt.Errorf("failed to associate artifacts for vuln %s: %w", batch[j].ID, err)
						}
					}
				}
			}

			for i := 0; i < len(eventsToCreate); i += batchSize {
				end := min(i+batchSize, len(eventsToCreate))
				if err := tx.Create(eventsToCreate[i:end]).Error; err != nil {
					return fmt.Errorf("failed to create events batch: %w", err)
				}
			}

			slog.Info("Flushed asset version to DB",
				"group", groupIdx+1, "vulnsCreated", len(vulnsToCreate), "eventsCreated", len(eventsToCreate))
		}

		// Update hash migration version
		config := models.Config{
			Key: HashMigrationVersionKey,
			Val: strconv.Itoa(CurrentHashVersion),
		}
		if err := tx.Save(&config).Error; err != nil {
			return fmt.Errorf("failed to update hash migration version: %w", err)
		}

		return nil
	})

	if err != nil {
		slog.Error("vulnerability path hash migration failed", "err", err)
		return err
	}

	slog.Info("Vulnerability path hash migration (v3) completed successfully")
	return nil
}
