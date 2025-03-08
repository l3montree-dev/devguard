package commands

import (
	"log/slog"

	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
	"github.com/spf13/cobra"
)

func NewMigrateCommand() *cobra.Command {
	migrate := cobra.Command{
		Use:   "migrate",
		Short: "Migrate data",
	}

	migrate.AddCommand(newDependencyVulnHashMigration())
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

			for _, dependencyVuln := range dependencyVulns {
				oldHash := dependencyVuln.ID
				newHash := dependencyVuln.CalculateHash()

				// update the hash in the database
				err = dependencyVulnRepository.GetDB(nil).Model(&models.DependencyVuln{}).Where("id = ?", oldHash).UpdateColumn("id", newHash).Error
				if err != nil {
					slog.Error("could not update dependencyVuln hash", "err", err)
					return
				}
			}
		},
	}

	return &dependencyVulnHashMigration
}
