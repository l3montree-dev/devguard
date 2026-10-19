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

type redmineIntegrationRepository struct {
	db *gorm.DB
	utils.Repository[uuid.UUID, models.RedmineIntegration, *gorm.DB]
	encryptionService shared.DBEncryptionService
}

func NewRedmineIntegrationRepository(db *gorm.DB, encryptionService shared.DBEncryptionService) *redmineIntegrationRepository {
	return &redmineIntegrationRepository{
		db:                db,
		Repository:        newGormRepository[uuid.UUID, models.RedmineIntegration](db),
		encryptionService: encryptionService,
	}
}

// Save encrypts the token in place so GORM writes DB-generated fields back onto the caller's model, then restores the plaintext.
func (r *redmineIntegrationRepository) Save(ctx context.Context, tx *gorm.DB, integration *models.RedmineIntegration) error {
	originalAccessToken := integration.AccessToken
	encryptedAccessToken, err := r.encryptionService.EncryptAndWrapData(originalAccessToken)
	if err != nil {
		return fmt.Errorf("could not encrypt access token before saving to db: %w", err)
	}
	integration.AccessToken = encryptedAccessToken
	defer func() { integration.AccessToken = originalAccessToken }()

	return r.Repository.Save(ctx, tx, integration)
}

func (r *redmineIntegrationRepository) Read(ctx context.Context, tx *gorm.DB, id uuid.UUID) (models.RedmineIntegration, error) {
	integration, err := r.Repository.Read(ctx, tx, id)
	if err != nil {
		return integration, err
	}

	decryptedAccessToken, err := r.encryptionService.MaybeDecryptData(integration.AccessToken)
	if err != nil {
		return integration, fmt.Errorf("could not decrypt fetched access token: %w", err)
	}
	integration.AccessToken = decryptedAccessToken

	return integration, nil
}

func (r *redmineIntegrationRepository) FindByOrganizationID(ctx context.Context, tx *gorm.DB, orgID uuid.UUID) ([]models.RedmineIntegration, error) {
	var integrations []models.RedmineIntegration
	if err := r.GetDB(ctx, tx).Find(&integrations, "org_id = ?", orgID).Error; err != nil {
		return nil, err
	}

	for i := range integrations {
		decryptedAccessToken, err := r.encryptionService.MaybeDecryptData(integrations[i].AccessToken)
		if err != nil {
			return nil, fmt.Errorf("could not decrypt fetched access token: %w", err)
		}
		integrations[i].AccessToken = decryptedAccessToken
	}

	return integrations, nil
}

func (r *redmineIntegrationRepository) GetClientByIntegrationID(ctx context.Context, tx *gorm.DB, integrationID uuid.UUID) (models.RedmineIntegration, error) {
	var integration models.RedmineIntegration
	if err := withOwnershipScope(ctx, r.GetDB(ctx, tx).Where("id = ?", integrationID), integration).First(&integration).Error; err != nil {
		return models.RedmineIntegration{}, err
	}

	decryptedAccessToken, err := r.encryptionService.MaybeDecryptData(integration.AccessToken)
	if err != nil {
		return models.RedmineIntegration{}, fmt.Errorf("could not decrypt fetched access token: %w", err)
	}
	integration.AccessToken = decryptedAccessToken

	return integration, nil
}
