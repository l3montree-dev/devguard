package commands

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/l3montree-dev/devguard/services"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/spf13/cobra"
)

func NewMigrationCommand() *cobra.Command {
	migrationCmd := &cobra.Command{
		Use:   "migration",
		Short: "Encrypts all existing plaintext secrets in the database with the provided key.",
		Long:  "One-off migration that wraps all currently unencrypted secrets in the database using the provided key and stores that key at the configured key file path (creating the file if it does not exist yet). Already encrypted values are left untouched, so it is safe to re-run. It only works while the application is offline.",
		Args:  cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			key, err := cmd.Flags().GetString("key")
			if err != nil {
				return fmt.Errorf("could not get the key, make sure its set and properly formatted: %w", err)
			}
			shared.LoadConfig() // nolint

			enc, err := services.NewDBEncryptionServiceFromKey([]byte(key))
			if err != nil {
				return fmt.Errorf("could not build encryption module from the provided key: %w", err)
			}

			err = os.WriteFile(os.Getenv(services.KeyFilePathENVName), []byte(key), 0o600)
			if err != nil {
				return fmt.Errorf("could not write the key to the key file under the path in the %s environment variable: %w", services.KeyFilePathENVName, err)
			}

			err = reEncryptAllSecrets(cmd.Context(), enc, enc)
			if err != nil {
				return fmt.Errorf("could not encrypt existing data: %w", err)
			}

			slog.Info("successfully encrypted all existing secrets")
			return nil
		},
	}
	migrationCmd.Flags().StringP("key", "k", "", "The hex encoded AES-256 key (64 hex characters) which will be used to encrypt the existing data")
	err := migrationCmd.MarkFlagRequired("key")
	if err != nil {
		slog.Error("a key needs to be provided")
		return nil
	}

	return migrationCmd
}
