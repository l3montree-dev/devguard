package hashmigrations

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/l3montree-dev/devguard/database"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/database/repositories"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/l3montree-dev/devguard/services"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/l3montree-dev/devguard/vulndb"
	"github.com/l3montree-dev/devguard/vulndb/scan"
	"github.com/package-url/packageurl-go"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const (
	// Increment this when the hash calculation algorithm changes
	CurrentHashVersion = 3
	// Config key for tracking hash migration version
	HashMigrationVersionKey = "hash_migration_version"
)

func RunHashMigrationsIfNeeded(pool *pgxpool.Pool, daemonRunner shared.DaemonRunner) error {
	// Check current version from config table
	var config models.Config
	db := database.NewGormDB(pool)
	err := db.Where("key = ?", HashMigrationVersionKey).First(&config).Error

	if errors.Is(err, gorm.ErrRecordNotFound) {
		config = models.Config{
			Key: HashMigrationVersionKey,
			Val: "3",
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

		slog.Info("Hash migrations completed successfully", "version", CurrentHashVersion)
	}

	return nil
}

func manuallyLoadNewVulnDB(db shared.DB, pool *pgxpool.Pool) error {
	// Drop all foreign key constraints that reference cves table before deleting
	err := db.Exec(`
		ALTER TABLE public.dependency_vulns DROP CONSTRAINT IF EXISTS fk_dependency_vulns_cve;
		ALTER TABLE public.cve_affected_component DROP CONSTRAINT IF EXISTS fk_cve_affected_component_cve;
		ALTER TABLE public.cve_affected_component DROP CONSTRAINT IF EXISTS fk_cve_affected_component_affected_component;
	`).Error
	if err != nil {
		slog.Error("could not drop foreign key constraints", "err", err)
		return err
	}

	// import the new VulnDB state, containing the (new) CVEs from the OSV database
	cveRepository := repositories.NewCVERepository(db)
	cweRepository := repositories.NewCWERepository(db)
	exploitsRepository := repositories.NewExploitRepository(db)
	affectedComponentsRepository := repositories.NewAffectedComponentRepository(db)
	configService := services.NewConfigService(db)
	v := vulndb.NewImportService(cveRepository, cweRepository, exploitsRepository, affectedComponentsRepository, configService, pool)

	err = configService.RemoveConfig("vulndb.lastIncrementalImport")
	if err != nil {
		slog.Error("could not remove last incremental import config", "err", err)
		return err
	}
	// the import will create foreign keys we need to disable temporarily
	vulndb.DisableForeignKeyFix = true
	// slog.Info("Step 1: Importing new vulnDB state")
	err = v.ImportFromDiff(nil)
	vulndb.DisableForeignKeyFix = false
	return err
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

	slog.Info("Syncing vulndb")
	if err := manuallyLoadNewVulnDB(db, pool); err != nil {
		slog.Error("could not initialize database for migration", "err", err)
		panic(err)
	}

	slog.Info("start running cve migration...")
	// Load all vulns with artifacts and events
	var allVulns []models.DependencyVuln
	err := db.Preload("Artifacts").Preload("Events").Find(&allVulns).Error
	if err != nil {
		panic(err)
	}

	pc := scan.NewPurlComparer(db)
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

	// Cache for GetVulns results - same PURL will return same vulns
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

				vulnsInPackage, err := pc.GetVulns(parsedPurl)

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
	createdVulnIDs := make(map[string]bool)
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
				newVuln.RawRiskAssessment = create.copyStateFrom.RawRiskAssessment
				newVuln.RiskAssessment = create.copyStateFrom.RiskAssessment
				newVuln.Effort = create.copyStateFrom.Effort
				newVuln.Priority = create.copyStateFrom.Priority
				newVuln.RiskRecalculatedAt = create.copyStateFrom.RiskRecalculatedAt
				newVuln.Message = create.copyStateFrom.Message

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
				event.VulnID = vulnHash
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
		if err := tx.Exec("DELETE FROM vuln_events WHERE vuln_type = 'dependencyVuln'").Error; err != nil {
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
			Val: strconv.Itoa(CurrentHashVersion),
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

	// Recreate the foreign key constraints as cleanup
	err = db.Exec(`
			ALTER TABLE public.dependency_vulns
			ADD CONSTRAINT fk_dependency_vulns_cve
			FOREIGN KEY (cve_id) REFERENCES public.cves(cve)
			ON DELETE CASCADE ON UPDATE CASCADE;

			ALTER TABLE public.cve_affected_component
			ADD CONSTRAINT fk_cve_affected_component_cve
			FOREIGN KEY (cvecve) REFERENCES public.cves(cve)
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
			CVE:               foundVuln.CVE,
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
		componentRepository := repositories.NewComponentRepository(tx)
		batchSize := 1000

		// Delete all old dependency vuln related data
		slog.Info("Deleting all dependency vuln events...")
		if err := tx.Exec("DELETE FROM vuln_events WHERE vuln_type = 'dependencyVuln'").Error; err != nil {
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

		createdVulnIDs := make(map[string]bool)
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

			// Load SBOM components for this asset version
			componentDeps, err := componentRepository.LoadComponents(tx, key.AssetVersionName, key.AssetID, nil)
			if err != nil {
				return fmt.Errorf("failed to load components for asset version %s/%s: %w", key.AssetID, key.AssetVersionName, err)
			} else {
				sbom := normalize.SBOMGraphFromComponents(utils.MapType[normalize.GraphComponent](componentDeps), nil)

				for _, oldVuln := range vulns {
					paths := sbom.FindAllComponentOnlyPathsToPURL(oldVuln.ComponentPurl, 0)

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
								event.VulnID = newVuln.ID
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
									event.VulnID = newVuln.ID
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
