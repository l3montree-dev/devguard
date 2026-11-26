package commands

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/accesscontrol"
	"github.com/l3montree-dev/devguard/database"
	"github.com/l3montree-dev/devguard/database/repositories"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/events"
	"github.com/l3montree-dev/devguard/services"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/spf13/cobra"
	"go.uber.org/fx"
)

func NewDataTransferCommand() *cobra.Command {
	dataTransferCmd := cobra.Command{
		Use:   "data-transfer",
		Short: "Move an org, project or asset between DevGuard instances",
		Long: `Moves an org, project or asset including everything below it from one DevGuard instance to another, e.g. from the SaaS to a self-hosted instance.

Run "export" against the source database and "import" with the produced archive against the target database.
Both instances must run the same DevGuard version, the import is rejected if the database schema versions differ.`,
	}

	dataTransferCmd.AddCommand(newDataTransferExportCommand())
	dataTransferCmd.AddCommand(newDataTransferImportCommand())
	return &dataTransferCmd
}

func newDataTransferExportCommand() *cobra.Command {
	var orgID, projectID, assetID, outputPath string

	exportCmd := &cobra.Command{
		Use:   "export",
		Short: "Export an org, project or asset into an archive",
		Long: `Exports exactly one org, project or asset including all its sub projects, assets, vulnerabilities and history into a tar archive.
Entities above the exported one are never part of the archive.`,
		Example: `  devguard-cli data-transfer export --org 3f1c... --output my-org.tar
  devguard-cli data-transfer export --project 9a2b...`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			options, err := exportOptionsFromFlags(orgID, projectID, assetID)
			if err != nil {
				return err
			}
			cmd.SilenceUsage = true

			shared.LoadConfig() // nolint
			dataTransferService, err := newDataTransferService()
			if err != nil {
				return err
			}

			// never overwrite an existing archive, it holds all data of the entity so only the owner may read it
			exportFile, err := os.OpenFile(outputPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
			if err != nil {
				return fmt.Errorf("could not create output file: %w", err)
			}
			err = dataTransferService.StartExport(cmd.Context(), options, exportFile)
			exportFile.Close()
			if err != nil {
				// a partial archive must not be mistaken for a complete one
				os.Remove(outputPath) // nolint
				return err
			}

			slog.Info("wrote export archive", "path", outputPath)
			return nil
		},
	}

	exportCmd.Flags().StringVar(&orgID, "org", "", "ID of the org to export")
	exportCmd.Flags().StringVar(&projectID, "project", "", "ID of the project to export")
	exportCmd.Flags().StringVar(&assetID, "asset", "", "ID of the asset to export")
	exportCmd.Flags().StringVarP(&outputPath, "output", "o", "devguard-export.tar", "Path of the created archive, must not exist yet")
	exportCmd.MarkFlagsOneRequired("org", "project", "asset")
	exportCmd.MarkFlagsMutuallyExclusive("org", "project", "asset")

	return exportCmd
}

func exportOptionsFromFlags(orgID, projectID, assetID string) (dtos.DataTransferExportOptions, error) {
	entityType, entityID := dtos.DataTransferEntityOrg, orgID
	switch {
	case projectID != "":
		entityType, entityID = dtos.DataTransferEntityProject, projectID
	case assetID != "":
		entityType, entityID = dtos.DataTransferEntityAsset, assetID
	}

	parsedID, err := uuid.Parse(entityID)
	if err != nil {
		return dtos.DataTransferExportOptions{}, fmt.Errorf("invalid %s id: %w", entityType, err)
	}
	return dtos.DataTransferExportOptions{EntityType: entityType, EntityID: parsedID}, nil
}

func newDataTransferImportCommand() *cobra.Command {
	var entityType, ownerID, targetOrgID, targetProjectID string

	importCmd := &cobra.Command{
		Use:   "import <archive>",
		Short: "Import an archive created by the export command",
		Long: `Imports an archive created by "data-transfer export". All rows are imported in one transaction, a failed import leaves no imported rows behind.

What has to be passed depends on what the archive contains:
  org archive      imported as a new org, --owner becomes its owner
  project archive  needs --targetOrg to become a root project or --targetProject to become a sub project, --owner becomes admin of the project
  asset archive    needs --targetProject, --owner becomes admin of the asset

Slugs are kept as they are, the import fails if one is already taken in the target.`,
		Example: `  devguard-cli data-transfer import my-org.tar --type org --owner 5d4e...
  devguard-cli data-transfer import my-project.tar --type project --owner 5d4e... --targetOrg 3f1c...
  devguard-cli data-transfer import my-asset.tar --type asset --owner 5d4e... --targetProject 9a2b...`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			options, err := importOptionsFromFlags(entityType, ownerID, targetOrgID, targetProjectID)
			if err != nil {
				return err
			}
			cmd.SilenceUsage = true

			archive, err := os.Open(args[0])
			if err != nil {
				return fmt.Errorf("could not open archive: %w", err)
			}
			defer archive.Close()

			shared.LoadConfig() // nolint
			dataTransferService, err := newDataTransferService()
			if err != nil {
				return err
			}
			return dataTransferService.ImportFile(cmd.Context(), archive, options)
		},
	}

	importCmd.Flags().StringVar(&entityType, "type", "", "Type of the archive: org, project or asset, the import is rejected if the archive is of another type")
	importCmd.Flags().StringVar(&ownerID, "owner", "", "ID of the user who gets the highest role on the imported entity")
	importCmd.Flags().StringVar(&targetOrgID, "targetOrg", "", "ID of the org a project archive gets imported into as a root project")
	importCmd.Flags().StringVar(&targetProjectID, "targetProject", "", "ID of the parent project of an imported project, or the project of an imported asset, the org is taken from this project")
	importCmd.MarkFlagRequired("type")  // nolint
	importCmd.MarkFlagRequired("owner") // nolint
	importCmd.MarkFlagsMutuallyExclusive("targetOrg", "targetProject")

	return importCmd
}

func importOptionsFromFlags(entityType, ownerID, targetOrgID, targetProjectID string) (dtos.DataTransferImportOptions, error) {
	switch dtos.DataTransferEntityType(entityType) {
	case dtos.DataTransferEntityOrg, dtos.DataTransferEntityProject, dtos.DataTransferEntityAsset:
	default:
		return dtos.DataTransferImportOptions{}, fmt.Errorf("invalid type %q, expected org, project or asset", entityType)
	}
	if _, err := uuid.Parse(ownerID); err != nil {
		return dtos.DataTransferImportOptions{}, fmt.Errorf("invalid owner id: %w", err)
	}
	options := dtos.DataTransferImportOptions{EntityType: dtos.DataTransferEntityType(entityType), OwnerID: ownerID}

	if targetOrgID != "" {
		orgID, err := uuid.Parse(targetOrgID)
		if err != nil {
			return dtos.DataTransferImportOptions{}, fmt.Errorf("invalid target org id: %w", err)
		}
		options.TargetOrgID = orgID
	}
	if targetProjectID != "" {
		projectID, err := uuid.Parse(targetProjectID)
		if err != nil {
			return dtos.DataTransferImportOptions{}, fmt.Errorf("invalid target project id: %w", err)
		}
		options.TargetProjectID = &projectID
	}
	return options, nil
}

// only builds the dependency graph, nothing of it needs to be started for an export or import
func newDataTransferService() (shared.DataTransferService, error) {
	var dataTransferService shared.DataTransferService
	app := fx.New(
		fx.NopLogger,
		fx.Supply(database.GetPoolConfigFromEnv()),
		database.Module,
		events.Module, // publishes the policy changes, so running instances reload the new rbac rules
		repositories.Module,
		services.ServiceModule,
		accesscontrol.AccessControlModule,
		fx.Populate(&dataTransferService),
	)
	return dataTransferService, app.Err()
}
