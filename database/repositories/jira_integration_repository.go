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

type jiraIntegrationRepository struct {
	db *gorm.DB
	utils.Repository[uuid.UUID, models.JiraIntegration, *gorm.DB]
	encryptionService shared.DBEncryptionService
}

func NewJiraIntegrationRepository(db *gorm.DB, encryptionService shared.DBEncryptionService) *jiraIntegrationRepository {
	return &jiraIntegrationRepository{
		db:                db,
		Repository:        newGormRepository[uuid.UUID, models.JiraIntegration](db),
		encryptionService: encryptionService,
	}
}

// Save encrypts the token in place so GORM writes DB-generated fields back onto the caller's model, then restores the plaintext.
func (r *jiraIntegrationRepository) Save(ctx context.Context, tx *gorm.DB, integration *models.JiraIntegration) error {
	originalAccessToken := integration.AccessToken
	encryptedAccessToken, err := r.encryptionService.EncryptAndWrapData(originalAccessToken)
	if err != nil {
		return fmt.Errorf("could not encrypt access token before saving to db: %w", err)
	}
	integration.AccessToken = encryptedAccessToken
	defer func() { integration.AccessToken = originalAccessToken }()

	return r.Repository.Save(ctx, tx, integration)
}

func (r *jiraIntegrationRepository) Read(ctx context.Context, tx *gorm.DB, id uuid.UUID) (models.JiraIntegration, error) {
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

func (r *jiraIntegrationRepository) FindByOrganizationID(ctx context.Context, tx *gorm.DB, orgID uuid.UUID) ([]models.JiraIntegration, error) {
	var integrations []models.JiraIntegration
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

func (r *jiraIntegrationRepository) GetClientByIntegrationID(ctx context.Context, tx *gorm.DB, integrationID uuid.UUID) (models.JiraIntegration, error) {
	var integration models.JiraIntegration
	if err := withOwnershipScope(ctx, r.GetDB(ctx, tx).Where("id = ?", integrationID), integration).First(&integration).Error; err != nil {
		return models.JiraIntegration{}, err
	}

	decryptedAccessToken, err := r.encryptionService.MaybeDecryptData(integration.AccessToken)
	if err != nil {
		return models.JiraIntegration{}, fmt.Errorf("could not decrypt fetched access token: %w", err)
	}
	integration.AccessToken = decryptedAccessToken

	return integration, nil
}
