package commands

import (
	"context"
	"os"
	"time"

	"github.com/l3montree-dev/devguard/database"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/services"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/spf13/cobra"
	"go.uber.org/fx"
)

func NewDataTransferCommand() *cobra.Command {
	dataTransferCmd := cobra.Command{
		Use:   "data-transfer",
		Short: "Manages data transfer between DevGuard instances",
		//Long:  "TBD", TODO
	}

	dataTransferCmd.AddCommand(newDTExportCommand())
	dataTransferCmd.AddCommand(newDTImportCommand())
	return &dataTransferCmd
}

func newDTExportCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "export",
		Short: "exports the data for a specified set of entities",
		RunE: func(cmd *cobra.Command, args []string) error {
			shared.LoadConfig() // nolint
			options := dtos.DataTransferExportOptions{
				AffectedEntities: dtos.AffectedEntities{
					Projects: []string{"d1c1ae53-6b95-4657-8275-b241d700c22e"},
				},
			}
			app := fx.New(
				fx.NopLogger,
				fx.Supply(database.GetPoolConfigFromEnv()),
				database.Module,
				services.ServiceModule,
				fx.Invoke(func(dataTransferService shared.DataTransferService) error {
					exportFile, err := os.Create("devguard-export.tar")
					if err != nil {
						return err
					}
					defer exportFile.Close()
					return dataTransferService.StartExport(context.Background(), options, exportFile)
				}),
			)

			ctx := context.Background()
			startCtx, cancel := context.WithTimeout(ctx, 30*time.Minute)
			defer cancel()
			if err := app.Start(startCtx); err != nil {
				return err
			}

			stopCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
			defer cancel()
			return app.Stop(stopCtx)
		},
	}
}

func newDTImportCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "import",
		Short: "imports the data for a specified set of entities",
		RunE: func(cmd *cobra.Command, args []string) error {
			shared.LoadConfig() // nolint

			app := fx.New(
				fx.NopLogger,
				fx.Supply(database.GetPoolConfigFromEnv()),
				database.Module,
				services.ServiceModule,
				fx.Invoke(func(dataTransferService shared.DataTransferService) error {
					exportFile, err := os.Open("devguard-export.tar")
					if err != nil {
						return err
					}
					defer exportFile.Close()
					return dataTransferService.ImportFile(context.Background(), exportFile)
				}),
			)

			ctx := context.Background()
			startCtx, cancel := context.WithTimeout(ctx, 30*time.Minute)
			defer cancel()
			if err := app.Start(startCtx); err != nil {
				return err
			}

			stopCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
			defer cancel()
			return app.Stop(stopCtx)
		},
	}
}
