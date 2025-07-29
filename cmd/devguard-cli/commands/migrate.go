package commands

import (
	"log/slog"

	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
)

func NewMigrateCommand() *cobra.Command {
	migrate := cobra.Command{
		Use:   "migrate",
		Short: "Migrate data",
	}
	migrate.AddCommand(newDependencyVulnHashMigration())
	migrate.AddCommand(newFirstPartyVulnHashMigration())
	return &migrate
}

func newDependencyVulnHashMigration() *cobra.Command {
	dependencyVulnHashMigration := cobra.Command{
		Use:   "dependency-vuln-hash",
		Short: "Will recalculate the dependencyVuln hashes for all dependencyVulns",
		Args:  cobra.ExactArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			core.LoadConfig() // nolint
			database, err := core.DatabaseFactory()
			if err != nil {
				slog.Error("could not connect to database", "err", err)
				return
			}

			dependencyVulnRepository := repositories.NewDependencyVulnRepository(database)

			var dependencyVulns []models.DependencyVuln
			err = dependencyVulnRepository.GetDB(nil).Model(&models.DependencyVuln{}).Find(&dependencyVulns).Error

			if err != nil {
				slog.Error("could not fetch dependencyVulns", "err", err)
				return
			}

			pb := progressbar.Default(int64(len(dependencyVulns)))

			for _, dependencyVuln := range dependencyVulns {
				pb.Add(1) //nolint:errcheck
				oldHash := dependencyVuln.ID
				newHash := dependencyVuln.CalculateHash()

				if oldHash == newHash {
					// no need to update
					continue
				}
				// update the hash in the database
				err = dependencyVulnRepository.GetDB(nil).Model(&models.DependencyVuln{}).Where("id = ?", oldHash).UpdateColumn("id", newHash).Error
				if err != nil {
					// duplicate key error - try to merge the two dependencyVulns
					var otherVuln models.DependencyVuln
					err = dependencyVulnRepository.GetDB(nil).Model(&models.DependencyVuln{}).Where("id = ?", newHash).First(&otherVuln).Error
					if err != nil {
						slog.Error("could not fetch other dependencyVuln", "err", err)
						continue
					}

					// save this vuln
					if err = dependencyVulnRepository.GetDB(nil).Model(&models.DependencyVuln{}).Where("id = ?", newHash).UpdateColumn("scanner_ids", utils.AddToWhitespaceSeparatedStringList(otherVuln.ScannerIDs, dependencyVuln.ScannerIDs)).Error; err != nil {
						slog.Error("could not update dependencyVuln", "err", err)
						continue
					}
					// delete the old dependencyVuln
					dependencyVulnRepository.GetDB(nil).Model(&models.DependencyVuln{}).Where("id = ?", oldHash).Delete(&dependencyVuln)
				}

				// update all vuln events
				err = dependencyVulnRepository.GetDB(nil).Model(&models.VulnEvent{}).Where("vuln_id = ?", oldHash).UpdateColumn("vuln_id", newHash).Error
				if err != nil {
					slog.Error("could not update vuln events", "err", err)
					continue
				}
			}
		},
	}

	return &dependencyVulnHashMigration
}

func newFirstPartyVulnHashMigration() *cobra.Command {
	firstPartyVulnHashMigration := cobra.Command{
		Use:   "first-party-vuln-hash",
		Short: "Will recalculate the firstPartyVuln hashes for all firstPartyVulns",
		Args:  cobra.ExactArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			core.LoadConfig() // nolint
			database, err := core.DatabaseFactory()
			if err != nil {
				slog.Error("could not connect to database", "err", err)
				return
			}

			firstPartyVulnRepository := repositories.NewFirstPartyVulnerabilityRepository(database)

			var firstPartyVulns []models.FirstPartyVuln
			err = firstPartyVulnRepository.GetDB(nil).Model(&models.FirstPartyVuln{}).Find(&firstPartyVulns).Error

			if err != nil {
				slog.Error("could not fetch firstPartyVulns", "err", err)
				return
			}

			pb := progressbar.Default(int64(len(firstPartyVulns)))

			type firstPartyWithOldHash struct {
				OldHash        string
				FirstPartyVuln models.FirstPartyVuln
			}

			firstPartyVulnMap := make(map[string][]firstPartyWithOldHash)

			for _, firstPartyVuln := range firstPartyVulns {
				pb.Add(1) //nolint:errcheck
				oldHash := firstPartyVuln.ID
				newHash := firstPartyVuln.CalculateHash()

				if oldHash == newHash {
					// no need to update
					continue
				}

				// store the firstPartyVuln in a map to handle duplicates later
				firstPartyVulnMap[newHash] = append(firstPartyVulnMap[newHash], firstPartyWithOldHash{
					OldHash:        oldHash,
					FirstPartyVuln: firstPartyVuln,
				})
			}
			for newHash, firstPartyVulnsWithOldHash := range firstPartyVulnMap {
				pb.Add(1) //nolint:errcheck
				if len(firstPartyVulnsWithOldHash) == 1 {
					// only one firstPartyVuln with this hash, we can update it directly
					fp := firstPartyVulnsWithOldHash[0]
					err = firstPartyVulnRepository.GetDB(nil).Model(&models.FirstPartyVuln{}).Where("id = ?", fp.OldHash).UpdateColumn("id", newHash).Error
					if err != nil {
						slog.Error("could not update firstPartyVuln", "err", err)
						continue
					}
				} else {
					// multiple firstPartyVulns with the same hash, we need to merge them

					// create a new firstPartyVuln with the merged snippet contents
					mergedFirstPartyVuln := firstPartyVulnsWithOldHash[0].FirstPartyVuln
					mergedSnippetContents := models.SnippetContents{
						Snippets: []models.SnippetContent{},
					}
					for _, fp := range firstPartyVulnsWithOldHash {
						snippetContents, err := fp.FirstPartyVuln.FromJSONSnippetContents()
						if err != nil {
							slog.Error("could not parse snippet contents", "error", err)
							continue
						}
						mergedSnippetContents.Snippets = append(mergedSnippetContents.Snippets, snippetContents.Snippets...)
					}
					mergedSnippetJSON, err := mergedSnippetContents.ToJSON()
					if err != nil {
						slog.Error("could not convert merged snippet contents to JSON", "error", err)
						continue
					}
					mergedFirstPartyVuln.SnippetContents = mergedSnippetJSON

					// save the merged firstPartyVuln
					err = firstPartyVulnRepository.GetDB(nil).Model(&models.FirstPartyVuln{}).Save(&mergedFirstPartyVuln).Error
					if err != nil {
						slog.Error("could not create merged firstPartyVuln", "err", err)
						continue
					}
					// delete the old firstPartyVulns
					for _, fp := range firstPartyVulnsWithOldHash {
						err = firstPartyVulnRepository.GetDB(nil).Model(&models.FirstPartyVuln{}).Where("id = ?", fp.OldHash).Delete(&models.FirstPartyVuln{}, "id = ?", fp.OldHash).Error
						if err != nil {
							slog.Error("could not delete old firstPartyVuln", "err", err)
							continue
						}

						// update all vuln events to point to the new firstPartyVuln
						err = firstPartyVulnRepository.GetDB(nil).Model(&models.VulnEvent{}).Where("vuln_id = ?", fp.OldHash).UpdateColumn("vuln_id", newHash).Error
						if err != nil {
							slog.Error("could not update vuln events", "err", err)
							continue
						}

					}
				}

			}
		},
	}

	return &firstPartyVulnHashMigration
}
