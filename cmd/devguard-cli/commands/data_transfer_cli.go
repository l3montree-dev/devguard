package commands

import (
	"context"
	"fmt"
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
				EntityType: dtos.DataTransferEntityOrg,
				EntityID:   uuid.MustParse("abccd789-abe0-4b03-8b1f-c8e2aafcb0ed"),
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
	var targetOrg, targetProject string
	importCmd := &cobra.Command{
		Use:   "import <owner-user-id>",
		Short: "imports an exported org, project or asset",
		Long:  "imports an exported org, project or asset, the given user gets the highest role on the imported entity",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			shared.LoadConfig() // nolint
			options := dtos.DataTransferImportOptions{OwnerID: args[0]}
			if targetOrg != "" {
				orgID, err := uuid.Parse(targetOrg)
				if err != nil {
					return fmt.Errorf("invalid target org id: %w", err)
				}
				options.TargetOrgID = orgID
			}
			if targetProject != "" {
				projectID, err := uuid.Parse(targetProject)
				if err != nil {
					return fmt.Errorf("invalid target project id: %w", err)
				}
				options.TargetProjectID = &projectID
			}

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
					return dataTransferService.ImportFile(context.Background(), exportFile, options)
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
	importCmd.Flags().StringVar(&targetOrg, "target-org", "", "org a project or asset archive gets imported into")
	importCmd.Flags().StringVar(&targetProject, "target-project", "", "parent project of an imported project, required for an asset archive")
	return importCmd
}
