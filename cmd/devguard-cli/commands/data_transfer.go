package commands

import (
	"context"
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
					Orgs: []string{"361813a7-1255-4764-a7b3-c64946215ef6"},
				},
			}
			app := fx.New(
				fx.NopLogger,
				fx.Supply(database.GetPoolConfigFromEnv()),
				database.Module,
				services.ServiceModule,
				fx.Invoke(func(dataTransferService shared.DataTransferService) error {
					return dataTransferService.StartExport(context.Background(), options)
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
