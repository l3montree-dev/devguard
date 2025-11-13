package models

import (
	"fmt"
	"log/slog"
	"strconv"

	"github.com/l3montree-dev/devguard/utils"
	"gorm.io/gorm"
)

const (
	// Increment this when the hash calculation algorithm changes
	CurrentHashVersion = 1
	// Config key for tracking hash migration version
	HashMigrationVersionKey = "hash_migration_version"
)

func RunHashMigrationsIfNeeded(db *gorm.DB) error {
	// Check current version from config table
	var config Config
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

		// Update version record in config table
		versionConfig := Config{
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
	var dependencyVulns []DependencyVuln
	err := db.Model(&DependencyVuln{}).Find(&dependencyVulns).Error
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
		err = db.Model(&DependencyVuln{}).Where("id = ?", oldHash).UpdateColumn("id", newHash).Error
		if err != nil {
			// Handle duplicate key error by merging
			var otherVuln DependencyVuln
			err = db.Model(&DependencyVuln{}).Where("id = ?", newHash).First(&otherVuln).Error
			if err != nil {
				slog.Error("could not fetch other dependencyVuln", "err", err)
				return err
			}

			if err = db.Model(&DependencyVuln{}).Where("id = ?", newHash).UpdateColumn("scanner_ids", utils.AddToWhitespaceSeparatedStringList(otherVuln.GetScannerIDsOrArtifactNames(), dependencyVuln.GetScannerIDsOrArtifactNames())).Error; err != nil {
				slog.Error("could not update dependencyVuln", "err", err)
				return err
			}
			db.Model(&DependencyVuln{}).Where("id = ?", oldHash).Delete(&dependencyVuln)
		}

		// Update all vuln events
		err = db.Model(&VulnEvent{}).Where("vuln_id = ?", oldHash).UpdateColumn("vuln_id", newHash).Error
		if err != nil {
			slog.Error("could not update vuln events", "err", err)
			return err
		}
	}

	return nil
}

func runFirstPartyVulnHashMigration(db *gorm.DB) error {
	var firstPartyVulns []FirstPartyVuln
	err := db.Model(&FirstPartyVuln{}).Find(&firstPartyVulns).Error
	if err != nil {
		return err
	}

	slog.Info("Migrating first party vuln hashes", "count", len(firstPartyVulns))

	type firstPartyWithOldHash struct {
		OldHash        string
		FirstPartyVuln FirstPartyVuln
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
			err = db.Model(&FirstPartyVuln{}).Where("id = ?", fp.OldHash).UpdateColumn("id", newHash).Error
			if err != nil {
				slog.Error("could not update firstPartyVuln", "err", err)
				return err
			}
		} else {
			// Handle merging multiple vulns with same hash
			mergedFirstPartyVuln := firstPartyVulnsWithOldHash[0].FirstPartyVuln
			mergedSnippetContents := SnippetContents{
				Snippets: []SnippetContent{},
			}
			for _, fp := range firstPartyVulnsWithOldHash {
				snippetContents, err := fp.FirstPartyVuln.FromJSONSnippetContents()
				if err != nil {
					slog.Error("could not parse snippet contents", "error", err)
					return err
				}
				mergedSnippetContents.Snippets = append(mergedSnippetContents.Snippets, snippetContents.Snippets...)
			}
			mergedSnippetJSON, err := mergedSnippetContents.ToJSON()
			if err != nil {
				slog.Error("could not convert merged snippet contents to JSON", "error", err)
				return err
			}
			mergedFirstPartyVuln.SnippetContents = mergedSnippetJSON

			err = db.Model(&FirstPartyVuln{}).Save(&mergedFirstPartyVuln).Error
			if err != nil {
				slog.Error("could not create merged firstPartyVuln", "err", err)
				return err
			}

			for _, fp := range firstPartyVulnsWithOldHash {
				err = db.Model(&FirstPartyVuln{}).Where("id = ?", fp.OldHash).Delete(&FirstPartyVuln{}, "id = ?", fp.OldHash).Error
				if err != nil {
					slog.Error("could not delete old firstPartyVuln", "err", err)
					return err
				}

				err = db.Model(&VulnEvent{}).Where("vuln_id = ?", fp.OldHash).UpdateColumn("vuln_id", newHash).Error
				if err != nil {
					slog.Error("could not update vuln events", "err", err)
					return err
				}
			}
		}
	}

	return nil
}
