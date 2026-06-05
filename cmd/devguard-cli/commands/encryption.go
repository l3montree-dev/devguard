package commands

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/l3montree-dev/devguard/database"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/services"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/spf13/cobra"
	"go.uber.org/fx"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func NewEncryptionCommand() *cobra.Command {
	encryptionCmd := &cobra.Command{
		Use:   "encryption",
		Short: "Manage app side encryption of the secrets stored in the database.",
		Long:  "Bundles the app side encryption maintenance modes. Use the 'migration' mode to encrypt currently plaintext secrets for the first time and the 'keyRotation' mode to switch all secrets to a new key. Both modes only work while the application is offline.",
	}

	encryptionCmd.AddCommand(newMigrationCommand())
	encryptionCmd.AddCommand(newKeyRotationCommand())

	return encryptionCmd
}

func newMigrationCommand() *cobra.Command {
	migrationCmd := &cobra.Command{
		Use:   "migration",
		Short: "Encrypts all existing plaintext secrets in the database with the provided key.",
		Long:  "One-off migration that wraps all currently unencrypted secrets in the database using the provided key and stores that key at the configured key file path (creating the file if it does not exist yet). It only works while the application is offline.",
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

			path := os.Getenv(services.KeyFilePathENVName)
			if path == "" {
				return fmt.Errorf("environment variable %s is not set.", services.KeyFilePathENVName)
			}

			err = os.WriteFile(path, []byte(key), 0o600)
			if err != nil {
				return fmt.Errorf("fatal: could not update the key in your key file (%s), to resolve this update the key manually under the specified filename in the %s environment variable in your .env", path, services.KeyFilePathENVName)
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

func newKeyRotationCommand() *cobra.Command {
	rotationCmd := &cobra.Command{
		Use:   "keyRotation",
		Short: "Rotates the current db encryption symmetric key to a new one.",
		Long:  "Read a new key, re-encrypts all the existing data and changes the key to the new one. The key needs to be a 256-Bit AES key. The command only works while the application is offline.",
		Args:  cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			newKey, err := cmd.Flags().GetString("key")
			if err != nil {
				return fmt.Errorf("could not get the newKey, make sure its set and properly formatted: %w", err)
			}
			shared.LoadConfig() // nolint
			currentKey := services.ReadCurrentKey()
			currentEnc, err := services.NewDBEncryptionServiceFromKey(currentKey)
			if err != nil {
				return fmt.Errorf("could not build current encryption module from key: %w", err)
			}

			newEnc, err := services.NewDBEncryptionServiceFromKey([]byte(newKey))
			if err != nil {
				return fmt.Errorf("could not build new encryption module from key: %w", err)
			}

			err = reEncryptAllSecrets(cmd.Context(), currentEnc, newEnc)
			if err != nil {
				return fmt.Errorf("could not rotate keys: %w", err)
			}

			path := os.Getenv(services.KeyFilePathENVName)
			if path == "" {
				return fmt.Errorf("environment variable %s is not set.", services.KeyFilePathENVName)
			}

			err = os.WriteFile(path, []byte(newKey), 0o600)
			if err != nil {
				return fmt.Errorf("fatal: could not update the key in your key file (%s), to resolve this update the key manually under the specified filename in the %s environment variable in your .env", path, services.KeyFilePathENVName)
			}
			return nil
		},
	}
	rotationCmd.Flags().StringP("key", "k", "", "The new hex encoded AES-256 key (64 hex characters) which will be used for encryption")
	err := rotationCmd.MarkFlagRequired("key")
	if err != nil {
		slog.Error("a new key needs to be provided")
		return nil
	}

	return rotationCmd
}

// function to fetch all secrets, decrypt them with the decryptEnc, then encrypting them with the encryptEnc and finally saving the update secrets to the database
func reEncryptAllSecrets(ctx context.Context, decryptEnc, encryptEnc *services.DBEncryptionService) error {
	var pipelineErr error

	app := fx.New(
		fx.NopLogger,
		fx.Supply(database.GetPoolConfigFromEnv()),
		database.Module,
		fx.Invoke(func(db *gorm.DB) error {
			secrets, err := fetchExistingSecrets(db)
			if err != nil {
				return fmt.Errorf("could not fetch existing secrets: %w", err)
			}

			decryptedSecrets, err := decryptSecrets(secrets, decryptEnc)
			if err != nil {
				return fmt.Errorf("could not decrypt existing secrets: %w", err)
			}

			reEncryptedSecrets, err := encryptSecrets(decryptedSecrets, encryptEnc)
			if err != nil {
				return fmt.Errorf("could not re-encrypt existing secrets: %w", err)
			}

			err = updateSecretsInDB(db, reEncryptedSecrets)
			if err != nil {
				return fmt.Errorf("could not save re-encrypted secrets to the database: %w", err)
			}

			return nil
		}),
	)

	if err := app.Start(ctx); err != nil {
		pipelineErr = err
	}

	if err := app.Stop(ctx); err != nil {
		if pipelineErr == nil {
			pipelineErr = err
		}
	}

	return pipelineErr
}

type secretsInDB struct {
	JiraIntegrations    []models.JiraIntegration
	GitlabIntegrations  []models.GitLabIntegration
	Oauth2Tokens        []models.GitLabOauth2Token
	WebhookIntegrations []models.WebhookIntegration
}

// fetch all known secrets from the database
func fetchExistingSecrets(db *gorm.DB) (secretsInDB, error) {
	allSecrets := secretsInDB{}

	err := db.Raw(`SELECT * FROM jira_integrations;`).Find(&allSecrets.JiraIntegrations).Error
	if err != nil {
		return secretsInDB{}, fmt.Errorf("could not fetch jira integrations: %w", err)
	}

	err = db.Raw(`SELECT * FROM gitlab_integrations;`).Find(&allSecrets.GitlabIntegrations).Error
	if err != nil {
		return secretsInDB{}, fmt.Errorf("could not fetch gitlab integrations: %w", err)
	}

	err = db.Raw(`SELECT * FROM webhook_integrations;`).Find(&allSecrets.WebhookIntegrations).Error
	if err != nil {
		return secretsInDB{}, fmt.Errorf("could not fetch webhook integrations: %w", err)
	}

	err = db.Raw(`SELECT * FROM gitlab_oauth2_tokens;`).Find(&allSecrets.Oauth2Tokens).Error
	if err != nil {
		return secretsInDB{}, fmt.Errorf("could not fetch oauth2 tokens: %w", err)
	}
	slog.Info("successfully fetched existing secrets from the database")
	return allSecrets, nil
}

// iterates over all secrets and calls maybe decrypt on all existing values
func decryptSecrets(secrets secretsInDB, decryptionService *services.DBEncryptionService) (secretsInDB, error) {
	for i := range secrets.GitlabIntegrations {
		decryptedAccessToken, err := decryptionService.MaybeDecryptData(secrets.GitlabIntegrations[i].AccessToken)
		if err != nil {
			return secretsInDB{}, fmt.Errorf("could not decrypt gitlab integration access token: %w", err)
		}
		secrets.GitlabIntegrations[i].AccessToken = decryptedAccessToken
	}

	for i := range secrets.WebhookIntegrations {
		if secrets.WebhookIntegrations[i].Secret == nil {
			continue
		}
		decryptedSecret, err := decryptionService.MaybeDecryptData(*secrets.WebhookIntegrations[i].Secret)
		if err != nil {
			return secretsInDB{}, fmt.Errorf("could not decrypt webhook integration secret: %w", err)
		}
		secrets.WebhookIntegrations[i].Secret = &decryptedSecret
	}

	for i := range secrets.Oauth2Tokens {
		decryptedAccessToken, err := decryptionService.MaybeDecryptData(secrets.Oauth2Tokens[i].AccessToken)
		if err != nil {
			return secretsInDB{}, fmt.Errorf("could not decrypt oauth2 access token: %w", err)
		}

		decryptedRefreshToken, err := decryptionService.MaybeDecryptData(secrets.Oauth2Tokens[i].RefreshToken)
		if err != nil {
			return secretsInDB{}, fmt.Errorf("could not decrypt oauth2 refresh token: %w", err)
		}

		secrets.Oauth2Tokens[i].AccessToken = decryptedAccessToken
		secrets.Oauth2Tokens[i].RefreshToken = decryptedRefreshToken
	}

	for i := range secrets.JiraIntegrations {
		decryptedAccessToken, err := decryptionService.MaybeDecryptData(secrets.JiraIntegrations[i].AccessToken)
		if err != nil {
			return secretsInDB{}, fmt.Errorf("could not decrypt jira integration access token: %w", err)
		}
		secrets.JiraIntegrations[i].AccessToken = decryptedAccessToken
	}
	slog.Info("successfully decrypted existing secrets")
	return secrets, nil
}

// iterate over all secrets and calls encrypt and wrap data on all existing values
func encryptSecrets(secrets secretsInDB, encryptionService *services.DBEncryptionService) (secretsInDB, error) {
	for i := range secrets.GitlabIntegrations {
		encryptedAccessToken, err := encryptionService.EncryptAndWrapData(secrets.GitlabIntegrations[i].AccessToken)
		if err != nil {
			return secretsInDB{}, fmt.Errorf("could not encrypt gitlab integration access token: %w", err)
		}
		secrets.GitlabIntegrations[i].AccessToken = encryptedAccessToken
	}

	for i := range secrets.WebhookIntegrations {
		if secrets.WebhookIntegrations[i].Secret == nil {
			continue
		}
		encryptedSecret, err := encryptionService.EncryptAndWrapData(*secrets.WebhookIntegrations[i].Secret)
		if err != nil {
			return secretsInDB{}, fmt.Errorf("could not encrypt webhook integration secret: %w", err)
		}
		secrets.WebhookIntegrations[i].Secret = &encryptedSecret
	}

	for i := range secrets.Oauth2Tokens {
		encryptedAccessToken, err := encryptionService.EncryptAndWrapData(secrets.Oauth2Tokens[i].AccessToken)
		if err != nil {
			return secretsInDB{}, fmt.Errorf("could not encrypt oauth2 access token: %w", err)
		}

		encryptedRefreshToken, err := encryptionService.EncryptAndWrapData(secrets.Oauth2Tokens[i].RefreshToken)
		if err != nil {
			return secretsInDB{}, fmt.Errorf("could not encrypt oauth2 refresh token: %w", err)
		}

		secrets.Oauth2Tokens[i].AccessToken = encryptedAccessToken
		secrets.Oauth2Tokens[i].RefreshToken = encryptedRefreshToken
	}

	for i := range secrets.JiraIntegrations {
		encryptedAccessToken, err := encryptionService.EncryptAndWrapData(secrets.JiraIntegrations[i].AccessToken)
		if err != nil {
			return secretsInDB{}, fmt.Errorf("could not encrypt jira integration access token: %w", err)
		}
		secrets.JiraIntegrations[i].AccessToken = encryptedAccessToken
	}
	slog.Info("successfully re-encrypted existing secrets")
	return secrets, nil
}

// save all the (updated) secrets to the database using on conflict update all
func updateSecretsInDB(db *gorm.DB, secrets secretsInDB) error {
	tx := db.Begin()
	defer tx.Rollback()
	if len(secrets.JiraIntegrations) > 0 {
		err := tx.Clauses(clause.OnConflict{UpdateAll: true}).Create(&secrets.JiraIntegrations).Error
		if err != nil {
			return fmt.Errorf("could not update jira integrations secrets: %w", err)
		}
	}

	if len(secrets.GitlabIntegrations) > 0 {
		err := tx.Clauses(clause.OnConflict{UpdateAll: true}).Create(&secrets.GitlabIntegrations).Error
		if err != nil {
			return fmt.Errorf("could not update gitlab integrations secrets: %w", err)
		}
	}

	if len(secrets.WebhookIntegrations) > 0 {
		err := tx.Clauses(clause.OnConflict{UpdateAll: true}).Create(&secrets.WebhookIntegrations).Error
		if err != nil {
			return fmt.Errorf("could not update webhook integrations secrets: %w", err)
		}
	}

	if len(secrets.Oauth2Tokens) > 0 {
		err := tx.Clauses(clause.OnConflict{UpdateAll: true}).Create(&secrets.Oauth2Tokens).Error
		if err != nil {
			return fmt.Errorf("could not update oauth2 tokens: %w", err)
		}
	}

	err := tx.Commit().Error
	if err != nil {
		return fmt.Errorf("could not commit updated secrets: %w, rolling back transaction", err)
	}
	slog.Info("successfully updated all secrets in the database")
	return nil
}
