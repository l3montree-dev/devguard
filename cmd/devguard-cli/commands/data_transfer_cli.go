package commands

import (
	"context"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/accesscontrol"
	"github.com/l3montree-dev/devguard/controllers"
	"github.com/l3montree-dev/devguard/database"
	"github.com/l3montree-dev/devguard/database/repositories"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/events"
	"github.com/l3montree-dev/devguard/integrations"
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
				EntityType: dtos.DataTransferEntityProject,
				EntityID:   uuid.MustParse("d1c1ae53-6b95-4657-8275-b241d700c22e"),
			}
			app := fx.New(
				fx.NopLogger,
				fx.Supply(database.GetPoolConfigFromEnv()),
				database.Module,
				events.Module,
				repositories.Module,
				services.ServiceModule,
				accesscontrol.AccessControlModule,
				controllers.ControllerModule,
				integrations.Module,
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
		Use:   "import <owner-user-id>",
		Short: "imports the data for a specified set of entities",
		Long:  "imports the data for a specified set of entities, the given user becomes owner of all imported organizations",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			shared.LoadConfig() // nolint
			ownerID := args[0]

			app := fx.New(
				fx.NopLogger,
				fx.Supply(database.GetPoolConfigFromEnv()),
				database.Module,
				events.Module, // publishes the policy changes, so running instances reload the new rbac rules
				repositories.Module,
				services.ServiceModule,
				accesscontrol.AccessControlModule,
				controllers.ControllerModule,
				integrations.Module,
				fx.Invoke(func(dataTransferService shared.DataTransferService) error {
					exportFile, err := os.Open("devguard-export.tar")
					if err != nil {
						return err
					}
					defer exportFile.Close()
					return dataTransferService.ImportFile(context.Background(), exportFile, ownerID)
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
