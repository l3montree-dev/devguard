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

	migrate.AddCommand(newFlawHashMigration())
	return &migrate
}

func newFlawHashMigration() *cobra.Command {
	flawHashMigration := cobra.Command{
		Use:   "flaw-hash",
		Short: "Will recalculate the flaw hashes for all flaws",
		Args:  cobra.ExactArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			core.LoadConfig() // nolint
			database, err := core.DatabaseFactory()
			if err != nil {
				slog.Error("could not connect to database", "err", err)
				return
			}

			flawRepository := repositories.NewFlawRepository(database)

			var flaws []models.Flaw
			err = flawRepository.GetDB(nil).Model(&models.Flaw{}).Find(&flaws).Error

			if err != nil {
				slog.Error("could not fetch flaws", "err", err)
				return
			}

			for _, flaw := range flaws {
				oldHash := flaw.ID
				newHash := flaw.CalculateHash()

				// update the hash in the database
				err = flawRepository.GetDB(nil).Model(&models.Flaw{}).Where("id = ?", oldHash).UpdateColumn("id", newHash).Error
				if err != nil {
					slog.Error("could not update flaw hash", "err", err)
					return
				}
			}
		},
	}

	return &flawHashMigration
}
