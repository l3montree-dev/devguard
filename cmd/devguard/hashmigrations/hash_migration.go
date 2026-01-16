package hashmigrations

import (
	"fmt"
	"log/slog"
	"runtime"
	"strconv"
	"sync"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/database/repositories"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/l3montree-dev/devguard/vulndb/scan"
	"github.com/package-url/packageurl-go"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	// Increment this when the hash calculation algorithm changes
	CurrentHashVersion = 2
	// Config key for tracking hash migration version
	HashMigrationVersionKey = "hash_migration_version"
)

func RunHashMigrationsIfNeeded(db *gorm.DB, daemonRunner shared.DaemonRunner) error {
	// Check current version from config table
	var config models.Config
	err := db.Where("key = ?", HashMigrationVersionKey).First(&config).Error

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

		if err := runCVEHashMigration(db, daemonRunner); err != nil {
			return fmt.Errorf("failed to run CVE hash migration: %w", err)
		}

		slog.Info("Hash migrations completed successfully", "version", CurrentHashVersion)
	}

	return nil
}

// this function handles the migration for importing new CVEs from the OSV.
// existing components may now have (multiple) different CVEs associated with them and we need to first determine affected dependency_vulns, then update the assigned CVE and lastly adjust the hash on the dependency_vuln itself and all references
func runCVEHashMigration(db *gorm.DB, daemonRunner shared.DaemonRunner) error {

	slog.Info("start running cve migration...")

	// Drop all foreign key constraints that reference cves table before deleting
	/*err := db.Exec(`
		ALTER TABLE public.dependency_vulns DROP CONSTRAINT IF EXISTS fk_dependency_vulns_cve;
		ALTER TABLE public.cve_affected_component DROP CONSTRAINT IF EXISTS fk_cve_affected_component_cve;
		ALTER TABLE public.cve_affected_component DROP CONSTRAINT IF EXISTS fk_cve_affected_component_affected_component;
	`).Error
	if err != nil {
		slog.Error("could not drop foreign key constraints", "err", err)
		return err
	}

	// Delete all CVEs (now that FK constraints are dropped)
	err = db.Exec(`DELETE FROM cves`).Error
	if err != nil {
		slog.Error("could not delete cves", "err", err)
		return err
	}
	slog.Info("successfully deleted cve entries")

	// import the new VulnDB state, containing the (new) CVEs from the OSV database
	// cveRepository := repositories.NewCVERepository(db)
	// cweRepository := repositories.NewCWERepository(db)
	// exploitsRepository := repositories.NewExploitRepository(db)
	// affectedComponentsRepository := repositories.NewAffectedComponentRepository(db)
	// configService := services.NewConfigService(db)
	// v := vulndb.NewImportService(cveRepository, cweRepository, exploitsRepository, affectedComponentsRepository, configService)

	// slog.Info("Step 1: Importing new vulnDB state")
	// err = v.ImportFromDiff(nil)
	// if err != nil {
	// 	slog.Error("error when trying to import with diff files", "err", err)
	// }
	cveRepository := repositories.NewCVERepository(db)
	affectedComponentsRepository := repositories.NewAffectedComponentRepository(db)

	v := vulndb.NewOSVService(affectedComponentsRepository, cveRepository, repositories.NewCveRelationshipRepository(db))

	slog.Info("Syncing vulndb")
	err = v.Mirror()
	if err != nil {
		return err
	}
	*/
	dependencyVulnRepository := repositories.NewDependencyVulnRepository(db)
	allVulns, err := dependencyVulnRepository.All()
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

	numWorkers := runtime.NumCPU() * 4
	if numWorkers > 64 {
		numWorkers = 64
	}

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
	for w := 0; w < numWorkers; w++ {
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
	processed := 0
	for result := range results {
		processed++
		if processed%1000 == 0 {
			slog.Info("Fetched CVE data", "progress", processed, "total", totalVulns)
		}
		if result.err != nil {
			slog.Error("could not process purl", "purl", result.oldVuln.ComponentPurl, "err", result.err)
			return result.err
		}
		allResults = append(allResults, result)
	}
	slog.Info("Finished fetching CVE data", "total", len(allResults))

	// Phase 2: Prepare all data for bulk operations
	createdVulnIDs := make(map[string]bool)
	var vulnsToCreate []models.DependencyVuln
	var eventsToCreate []models.VulnEvent
	var oldVulnIDs []string

	for _, result := range allResults {
		resolved := resolveCVERelations(result.oldVuln, result.vulnsInPkg)

		for _, create := range resolved.creates {
			newVuln := create.newVuln
			if create.copyStateFrom != nil {
				newVuln.State = create.copyStateFrom.State
			}

			vulnHash := newVuln.CalculateHash()
			if createdVulnIDs[vulnHash] {
				continue
			}
			createdVulnIDs[vulnHash] = true
			newVuln.ID = vulnHash

			vulnsToCreate = append(vulnsToCreate, newVuln)

			if create.copyStateFrom == nil {
				ev := models.NewDetectedEvent(vulnHash, dtos.VulnTypeDependencyVuln, "system", dtos.RiskCalculationReport{}, "", dtos.UpstreamStateInternal)
				eventsToCreate = append(eventsToCreate, ev)
			} else {
				for _, event := range create.copyStateFrom.Events {
					event.VulnID = vulnHash
					eventsToCreate = append(eventsToCreate, event)
				}
			}
		}

		if resolved.delete != nil {
			oldVulnIDs = append(oldVulnIDs, resolved.delete.ID)
		}
	}

	slog.Info("Prepared bulk data", "vulnsToCreate", len(vulnsToCreate), "eventsToCreate", len(eventsToCreate), "vulnsToDelete", len(oldVulnIDs))

	// Phase 3: Bulk database operations
	err = db.Transaction(func(tx *gorm.DB) error {
		// Bulk create vulns in batches
		batchSize := 1000
		for i := 0; i < len(vulnsToCreate); i += batchSize {
			end := min(i+batchSize, len(vulnsToCreate))
			if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(vulnsToCreate[i:end]).Error; err != nil {
				slog.Error("failed to bulk create vulns", "err", err)
				return err
			}
			slog.Info("Created vulns batch", "progress", end, "total", len(vulnsToCreate))
		}

		// Bulk create events in batches
		for i := 0; i < len(eventsToCreate); i += batchSize {
			end := min(i+batchSize, len(eventsToCreate))
			if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(eventsToCreate[i:end]).Error; err != nil {
				slog.Error("failed to bulk create events", "err", err)
				return err
			}
			slog.Info("Created events batch", "progress", end, "total", len(eventsToCreate))
		}

		// Bulk delete old events
		if len(oldVulnIDs) > 0 {
			for i := 0; i < len(oldVulnIDs); i += batchSize {
				end := min(i+batchSize, len(oldVulnIDs))
				if err := tx.Where("vuln_id IN ? AND vuln_type = ?", oldVulnIDs[i:end], "dependencyVuln").Delete(&models.VulnEvent{}).Error; err != nil {
					slog.Error("failed to bulk delete events", "err", err)
					return err
				}
			}
			slog.Info("Deleted old events")

			// Bulk delete old vulns
			for i := 0; i < len(oldVulnIDs); i += batchSize {
				end := min(i+batchSize, len(oldVulnIDs))
				if err := tx.Where("id IN ?", oldVulnIDs[i:end]).Delete(&models.DependencyVuln{}).Error; err != nil {
					slog.Error("failed to bulk delete vulns", "err", err)
					return err
				}
			}
			slog.Info("Deleted old vulns")
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

			ALTER TABLE public.cve_affected_component
			ADD CONSTRAINT fk_cve_affected_component_affected_component
			FOREIGN KEY (affected_component_purl) REFERENCES public.affected_components(purl)
			ON DELETE CASCADE ON UPDATE CASCADE;
		`).Error

	return err
}

type vulnCreate struct {
	newVuln       models.DependencyVuln
	copyStateFrom *models.DependencyVuln // Copy state/artifacts/events from this vuln
}

type resolveResult struct {
	creates []vulnCreate
	delete  *models.DependencyVuln
}

func resolveCVERelations(oldVuln models.DependencyVuln, foundVulns []models.VulnInPackage) resolveResult {
	creates := []vulnCreate{}

	// No new vulns found - just delete all old ones (CVEs no longer apply)
	if len(foundVulns) == 0 {
		return resolveResult{
			creates: creates,
			delete:  &oldVuln,
		}
	}

	// CVE split: one old vuln maps to multiple new vulns
	depthMap := map[string]int{
		oldVuln.ComponentPurl: utils.OrDefault(oldVuln.ComponentDepth, 1),
	}

	for _, foundVuln := range foundVulns {
		newVuln := transformer.VulnInPackageToDependencyVulnWithoutArtifact(
			foundVuln,
			depthMap,
			oldVuln.AssetID,
			oldVuln.AssetVersionName,
		)
		var copyStateFrom *models.DependencyVuln = nil
		if isRelatedCVE(oldVuln.CVEID, foundVuln.CVE.Relationships) {
			copyStateFrom = &oldVuln
		}

		newVuln.ID = newVuln.CalculateHash()

		creates = append(creates, vulnCreate{
			newVuln:       newVuln,
			copyStateFrom: copyStateFrom,
		})
	}

	return resolveResult{
		creates: creates,
		delete:  &oldVuln,
	}
}

func isRelatedCVE(cveID string, relationships []models.CVERelationship) bool {
	for _, rel := range relationships {
		if rel.TargetCVE == cveID && rel.RelationshipType == dtos.RelationshipTypeUpstream {
			return true
		}
	}
	return false
}
