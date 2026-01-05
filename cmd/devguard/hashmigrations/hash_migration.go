package hashmigrations

import (
	"fmt"
	"log/slog"
	"strconv"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/database/repositories"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/services"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/l3montree-dev/devguard/vulndb"
	"gorm.io/gorm"
)

const (
	// Increment this when the hash calculation algorithm changes
	CurrentHashVersion = 1
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

	// If version is outdated, run migrations
	if currentVersion < CurrentHashVersion {
		slog.Info("Hash algorithm version changed, running hash migrations",
			"current_version", currentVersion,
			"target_version", CurrentHashVersion)

		// Run dependency vuln hash migration
		if err := runDependencyVulnHashMigration(db); err != nil {
			return err
		}

		// Run first party vuln hash migration
		if err := runFirstPartyVulnHashMigration(db); err != nil {
			return err
		}

		// if err := runCVEHashMigration(db, daemonRunner); err != nil {
		// 	return err
		// }

		// Update version record in config table
		versionConfig := models.Config{
			Key: HashMigrationVersionKey,
			Val: strconv.Itoa(CurrentHashVersion),
		}

		if err := db.Save(&versionConfig).Error; err != nil {
			return fmt.Errorf("failed to update hash migration version: %w", err)
		}

		slog.Info("Hash migrations completed successfully", "version", CurrentHashVersion)
	}

	return nil
}

func runDependencyVulnHashMigration(db *gorm.DB) error {
	var dependencyVulns []models.DependencyVuln
	err := db.Model(&models.DependencyVuln{}).Find(&dependencyVulns).Error
	if err != nil {
		return err
	}

	slog.Info("Migrating dependency vuln hashes", "count", len(dependencyVulns))

	for _, dependencyVuln := range dependencyVulns {
		oldHash := dependencyVuln.ID
		newHash := dependencyVuln.CalculateHash()

		if oldHash == newHash {
			continue
		}

		// Update the hash in the database
		err = db.Model(&models.DependencyVuln{}).Where("id = ?", oldHash).UpdateColumn("id", newHash).Error
		if err != nil {
			// Handle duplicate key error by merging
			var otherVuln models.DependencyVuln
			err = db.Model(&models.DependencyVuln{}).Where("id = ?", newHash).First(&otherVuln).Error
			if err != nil {
				slog.Error("could not fetch other dependencyVuln", "err", err)
				return err
			}

			if err = db.Model(&models.DependencyVuln{}).Where("id = ?", newHash).UpdateColumn("scanner_ids", utils.AddToWhitespaceSeparatedStringList(otherVuln.GetScannerIDsOrArtifactNames(), dependencyVuln.GetScannerIDsOrArtifactNames())).Error; err != nil {
				slog.Error("could not update dependencyVuln", "err", err)
				return err
			}
			db.Model(&models.DependencyVuln{}).Where("id = ?", oldHash).Delete(&dependencyVuln)
		}

		// Update all vuln events
		err = db.Model(&models.VulnEvent{}).Where("vuln_id = ?", oldHash).UpdateColumn("vuln_id", newHash).Error
		if err != nil {
			slog.Error("could not update vuln events", "err", err)
			return err
		}
	}

	return nil
}

func runFirstPartyVulnHashMigration(db *gorm.DB) error {
	var firstPartyVulns []models.FirstPartyVuln
	err := db.Model(&models.FirstPartyVuln{}).Find(&firstPartyVulns).Error
	if err != nil {
		return err
	}

	slog.Info("Migrating first party vuln hashes", "count", len(firstPartyVulns))

	type firstPartyWithOldHash struct {
		OldHash        string
		FirstPartyVuln models.FirstPartyVuln
	}

	firstPartyVulnMap := make(map[string][]firstPartyWithOldHash)

	for _, firstPartyVuln := range firstPartyVulns {
		oldHash := firstPartyVuln.ID
		newHash := firstPartyVuln.CalculateHash()

		if oldHash == newHash {
			continue
		}

		firstPartyVulnMap[newHash] = append(firstPartyVulnMap[newHash], firstPartyWithOldHash{
			OldHash:        oldHash,
			FirstPartyVuln: firstPartyVuln,
		})
	}

	for newHash, firstPartyVulnsWithOldHash := range firstPartyVulnMap {
		if len(firstPartyVulnsWithOldHash) == 1 {
			fp := firstPartyVulnsWithOldHash[0]
			err = db.Model(&models.FirstPartyVuln{}).Where("id = ?", fp.OldHash).UpdateColumn("id", newHash).Error
			if err != nil {
				slog.Error("could not update firstPartyVuln", "err", err)
				return err
			}
		} else {
			// Handle merging multiple vulns with same hash
			mergedFirstPartyVuln := firstPartyVulnsWithOldHash[0].FirstPartyVuln
			mergedSnippetContents := dtos.SnippetContents{
				Snippets: []dtos.SnippetContent{},
			}
			for _, fp := range firstPartyVulnsWithOldHash {
				snippetContents, err := transformer.FromJSONSnippetContents(fp.FirstPartyVuln)
				if err != nil {
					slog.Error("could not parse snippet contents", "error", err)
					return err
				}
				mergedSnippetContents.Snippets = append(mergedSnippetContents.Snippets, snippetContents.Snippets...)
			}
			mergedSnippetJSON, err := transformer.SnippetContentsToJSON(mergedSnippetContents)
			if err != nil {
				slog.Error("could not convert merged snippet contents to JSON", "error", err)
				return err
			}
			mergedFirstPartyVuln.SnippetContents = mergedSnippetJSON

			err = db.Model(&models.FirstPartyVuln{}).Save(&mergedFirstPartyVuln).Error
			if err != nil {
				slog.Error("could not create merged firstPartyVuln", "err", err)
				return err
			}

			for _, fp := range firstPartyVulnsWithOldHash {
				err = db.Model(&models.FirstPartyVuln{}).Where("id = ?", fp.OldHash).Delete(&models.FirstPartyVuln{}, "id = ?", fp.OldHash).Error
				if err != nil {
					slog.Error("could not delete old firstPartyVuln", "err", err)
					return err
				}

				err = db.Model(&models.VulnEvent{}).Where("vuln_id = ?", fp.OldHash).UpdateColumn("vuln_id", newHash).Error
				if err != nil {
					slog.Error("could not update vuln events", "err", err)
					return err
				}
			}
		}
	}

	return nil
}

// this function handles the migration for importing new CVEs from the OSV.
// existing components may now have (multiple) different CVEs associated with them and we need to first determine affected dependency_vulns, then update the assigned CVE and lastly adjust the hash on the dependency_vuln itself and all references
func runCVEHashMigration(db *gorm.DB, daemonRunner shared.DaemonRunner) error {
	slog.Info("start running cve migration...")

	// before importing the new CVEs we need to make sure that we do not get foreign key errors, for dependency_vulns which CVE does not exist anymore
	err := db.Exec(`ALTER TABLE public.dependency_vulns 
					DROP CONSTRAINT fk_dependency_vulns_cve`).Error
	if err != nil {
		slog.Error("could not drop foreign key constraint")
		return err
	}

	defer func() {
		// make sure to reenable the foreign key constraint as cleanup
		err := db.Exec(`ALTER TABLE ONLY public.dependency_vulns
    					ADD CONSTRAINT fk_dependency_vulns_cve FOREIGN KEY (cve_id) REFERENCES public.cves(cve);`).Error
		if err != nil {
			panic(fmt.Sprintf("fatal error: could not reenable foreign key constraint fk_dependency_vulns_cve on table dependency_vulns, with internal error: %s", err.Error()))
		}
	}()

	// import the new VulnDB state, containing the (new) CVEs from the OSV database
	cveRepository := repositories.NewCVERepository(db)
	cweRepository := repositories.NewCWERepository(db)
	exploitsRepository := repositories.NewExploitRepository(db)
	affectedComponentsRepository := repositories.NewAffectedComponentRepository(db)
	configService := services.NewConfigService(db)
	v := vulndb.NewImportService(cveRepository, cweRepository, exploitsRepository, affectedComponentsRepository, configService)

	slog.Info("Step 1: Importing new vulnDB state")
	err = v.ImportFromDiff(nil)
	if err != nil {
		slog.Error("error when trying to import with diff files", "err", err)
	}

	// now we need to scan everything once more to update the dependencyVulns on the way
	slog.Info("Step 2: Scanning all Assets")
	daemonRunner.RunAssetPipeline()

	return nil
}
