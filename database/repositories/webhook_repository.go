// Copyright 2025 l3montree GmbH.
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package repositories

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"gorm.io/gorm"
)

type webhookRepository struct {
	db *gorm.DB
	utils.Repository[uuid.UUID, models.WebhookIntegration, *gorm.DB]
	encryptionService shared.DBEncryptionService
}

func NewWebhookRepository(db *gorm.DB, encryptionService shared.DBEncryptionService) *webhookRepository {
	return &webhookRepository{
		db:                db,
		Repository:        newGormRepository[uuid.UUID, models.WebhookIntegration](db),
		encryptionService: encryptionService,
	}
}

// encryptSecretInPlace returns a copy of the webhook with its secret encrypted
// nosemgrep: repo-method-missing-tx -- private helper; no DB access
func (r *webhookRepository) encryptSecretInPlace(ctx context.Context, webhook models.WebhookIntegration) (models.WebhookIntegration, error) {
	if webhook.Secret == nil {
		return webhook, nil
	}

	encryptedSecret, err := r.encryptionService.EncryptAndWrapData(*webhook.Secret)
	if err != nil {
		return webhook, fmt.Errorf("could not encrypt webhook secret before saving to db: %w", err)
	}
	webhook.Secret = &encryptedSecret

	return webhook, nil
}

// decryptSecretInPlace decrypts the secret of a fetched webhook in place
// nosemgrep: repo-method-missing-tx -- private helper; no DB access
func (r *webhookRepository) decryptSecretInPlace(ctx context.Context, webhook *models.WebhookIntegration) error {
	if webhook.Secret == nil {
		return nil
	}

	decryptedSecret, err := r.encryptionService.MaybeDecryptData(*webhook.Secret)
	if err != nil {
		return fmt.Errorf("could not decrypt fetched webhook secret: %w", err)
	}
	webhook.Secret = &decryptedSecret

	return nil
}

// Save encrypts the secret in place so GORM writes DB-generated fields back onto the caller's model, then restores the plaintext.
func (r *webhookRepository) Save(ctx context.Context, tx *gorm.DB, webhook *models.WebhookIntegration) error {
	encrypted, err := r.encryptSecretInPlace(ctx, *webhook)
	if err != nil {
		return err
	}

	originalSecret := webhook.Secret
	webhook.Secret = encrypted.Secret
	defer func() { webhook.Secret = originalSecret }()

	return r.Repository.Save(ctx, tx, webhook)
}

func (r *webhookRepository) Read(ctx context.Context, tx *gorm.DB, id uuid.UUID) (models.WebhookIntegration, error) {
	webhook, err := r.Repository.Read(ctx, tx, id)
	if err != nil {
		return webhook, err
	}

	if err := r.decryptSecretInPlace(ctx, &webhook); err != nil {
		return webhook, err
	}

	return webhook, nil
}

func (r *webhookRepository) FindByOrgIDAndProjectID(ctx context.Context, tx *gorm.DB, orgID uuid.UUID, projectID uuid.UUID) ([]models.WebhookIntegration, error) {
	var integrations []models.WebhookIntegration

	query := r.GetDB(ctx, tx).Where("org_id = ? AND project_id IS NULL", orgID).Or("org_id = ? AND project_id = ?", orgID, projectID)

	if err := query.Find(&integrations).Error; err != nil {
		return nil, err
	}

	for i := range integrations {
		if err := r.decryptSecretInPlace(ctx, &integrations[i]); err != nil {
			return nil, err
		}
	}

	return integrations, nil
}

func (r *webhookRepository) GetProjectWebhooks(ctx context.Context, tx *gorm.DB, orgID uuid.UUID, projectID uuid.UUID) ([]models.WebhookIntegration, error) {
	var integrations []models.WebhookIntegration

	query := r.GetDB(ctx, tx).Where("org_id = ? AND project_id = ?", orgID, projectID)

	if err := query.Find(&integrations).Error; err != nil {
		return nil, err
	}

	for i := range integrations {
		if err := r.decryptSecretInPlace(ctx, &integrations[i]); err != nil {
			return nil, err
		}
	}

	return integrations, nil
}

func (r *webhookRepository) GetClientByIntegrationID(ctx context.Context, tx *gorm.DB, integrationID uuid.UUID) (models.WebhookIntegration, error) {
	var integration models.WebhookIntegration
	if err := r.GetDB(ctx, tx).First(&integration, "id = ?", integrationID).Error; err != nil {
		return models.WebhookIntegration{}, err
	}

	if err := r.decryptSecretInPlace(ctx, &integration); err != nil {
		return models.WebhookIntegration{}, err
	}

	return integration, nil
}
