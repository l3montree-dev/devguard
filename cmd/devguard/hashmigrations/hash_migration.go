package hashmigrations

import (
	"fmt"
	"log/slog"
	"strconv"

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

	// Wrap the entire migration in a single transaction
	err = db.Transaction(func(tx *gorm.DB) error {
		for i, v := range allVulns {
			purl := v.ComponentPurl
			// parse the purl
			parsedPurl, err := packageurl.FromString(purl)
			if err != nil {
				slog.Error("could not parse purl", "purl", purl, "err", err)
				return err
			}
			vulnsInPackage, err := pc.GetVulns(parsedPurl)
			if err != nil {
				slog.Error("could not get vulns for purl", "purl", purl, "err", err)
				return err
			}

			result := resolveCVERelations(v, vulnsInPackage)
			slog.Info("Processing CVE hash migration for purl", "purl", purl, "index", i, "after", len(vulnsInPackage))
			// 1. Create all new vulns with copied state/artifacts/events
			// Track already created vulns by their hash to avoid duplicates
			createdVulnIDs := make(map[string]bool)
			for _, create := range result.creates {
				// Create new vuln record (BeforeSave hook will set the ID)
				newVuln := create.newVuln
				// check if we should copy the state from an old vuln
				if create.copyStateFrom != nil {
					newVuln.State = create.copyStateFrom.State
				}

				// Calculate the hash to check for duplicates
				vulnHash := newVuln.CalculateHash()
				if createdVulnIDs[vulnHash] {
					// Skip duplicate - already created this vuln in this batch
					continue
				}
				createdVulnIDs[vulnHash] = true

				if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&newVuln).Error; err != nil {
					return err
				}

				if create.copyStateFrom == nil {
					// we need to create an initial event for this vuln creation
					ev := models.NewDetectedEvent(newVuln.CalculateHash(), dtos.VulnTypeDependencyVuln, "system", dtos.RiskCalculationReport{}, "", dtos.UpstreamStateInternal)

					if err := tx.Model(&newVuln).Association("Events").Append(&ev); err != nil {
						slog.Error("could not create initial detected event for new vuln", "vuln_id", newVuln.ID, "err", err)
						return err
					}
					continue
				}

				// Copy artifact associations
				if len(create.copyStateFrom.Artifacts) > 0 {
					if err := tx.Model(&newVuln).Association("Artifacts").Append(create.copyStateFrom.Artifacts); err != nil {
						slog.Error("could not associate artifacts", "vuln_id", newVuln.ID, "err", err)
						return err
					}
				}

				// Copy events
				for _, event := range create.copyStateFrom.Events {
					event.VulnID = newVuln.ID
					if err := tx.Create(&event).Error; err != nil {
						slog.Error("could not create event", "vuln_id", newVuln.ID, "err", err)
						return err
					}
				}
			}

			// 2. Delete all old vulns
			if result.delete != nil {
				oldVuln := *result.delete
				// Delete events (polymorphic, no FK)
				if err := tx.Where("vuln_id = ? AND vuln_type = ?", oldVuln.ID, "dependencyVuln").Delete(&models.VulnEvent{}).Error; err != nil {
					slog.Error("could not delete events for old vuln", "id", oldVuln.ID, "err", err)
					return err
				}

				// Delete the vuln (CASCADE will handle artifact join table via ON DELETE CASCADE)
				if err := tx.Delete(&oldVuln).Error; err != nil {
					slog.Error("could not delete old dependency vuln", "id", oldVuln.ID, "err", err)
					return err
				}
			}
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
			FOREIGN KEY (cve_cve) REFERENCES public.cves(cve)
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
