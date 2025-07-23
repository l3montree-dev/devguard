// Copyright 2025 l3montree GmbH.
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package repositories

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
)

type webhookRepository struct {
	db core.DB
	common.Repository[uuid.UUID, models.WebhookIntegration, core.DB]
}

func NewWebhookRepository(db core.DB) *webhookRepository {
	if err := db.AutoMigrate(&models.WebhookIntegration{}); err != nil {
		panic(err)
	}
	return &webhookRepository{
		db:         db,
		Repository: newGormRepository[uuid.UUID, models.WebhookIntegration](db),
	}
}
func (r *webhookRepository) FindByOrgIDAndProjectID(orgID uuid.UUID, projectID uuid.UUID) ([]models.WebhookIntegration, error) {
	var integrations []models.WebhookIntegration

	query := r.db.Where("organization_id = ? AND project_id IS NULL", orgID).Or("organization_id = ? AND project_id = ?", orgID, projectID)

	if err := query.Find(&integrations).Error; err != nil {
		return nil, err
	}

	return integrations, nil
}

func (r *webhookRepository) GetClientByIntegrationID(integrationID uuid.UUID) (models.WebhookIntegration, error) {
	var integration models.WebhookIntegration
	if err := r.db.First(&integration, "id = ?", integrationID).Error; err != nil {
		return models.WebhookIntegration{}, err
	}
	return integration, nil
}
