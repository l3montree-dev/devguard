package commands

import (
	"log/slog"

	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/component"
	"github.com/l3montree-dev/devguard/internal/core/vuln"
	"github.com/l3montree-dev/devguard/internal/core/vulndb"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
)

func NewComponentsCommand() *cobra.Command {
	vulndbCmd := cobra.Command{
		Use: "components",
	}

	vulndbCmd.AddCommand(newUpdateDepsDevInformation())
	return &vulndbCmd
}

func newUpdateDepsDevInformation() *cobra.Command {
	importCmd := &cobra.Command{
		Use:   "update-deps-dev-info",
		Short: "Will update the dev information for all existing components",
		Args:  cobra.ExactArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			core.LoadConfig() // nolint
			database, err := core.DatabaseFactory()
			if err != nil {
				slog.Error("could not connect to database", "err", err)
				return
			}

			depsDevService := vulndb.NewDepsDevService()
			componentProjectRepository := repositories.NewComponentProjectRepository(database)
			componentRepository := repositories.NewComponentRepository(database)
			licenseRiskService := vuln.NewLicenseRiskService(repositories.NewLicenseRiskRepository(database), repositories.NewVulnEventRepository(database))

			components, err := componentRepository.All()
			if err != nil {
				slog.Error("could not get components", "err", err)
				return
			}

			componentService := component.NewComponentService(
				&depsDevService,
				componentProjectRepository,
				componentRepository,
				licenseRiskService,
			)

			bar := progressbar.Default(int64(len(components)))

			batch := make([]models.Component, 0, 100)
			for _, component := range components {
				c, err := componentService.GetLicense(component)
				if err != nil {
					slog.Error("could not get license", "err", err)
					continue
				}

				batch = append(batch, c)
				if len(batch) > 100 {
					err := componentRepository.SaveBatch(nil, batch)
					if err != nil {
						slog.Error("could not save batch", "err", err)
						return
					}

					batch = make([]models.Component, 0, 100)
				}
				bar.Add(1) // nolint
			}

			slog.Info("updating project information")
			projects, err := componentProjectRepository.All()
			if err != nil {
				slog.Error("could not get projects", "err", err)
				return
			}

			bar.Reset()
			bar = progressbar.Default(int64(len(projects)))

			for _, project := range projects {
				componentService.RefreshComponentProjectInformation(project)
				bar.Add(1) // nolint
			}
		},
	}

	return importCmd
}
