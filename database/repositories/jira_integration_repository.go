// Copyright 2025 l3montree GmbH.
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package repositories

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"gorm.io/gorm"
)

type jiraIntegrationRepository struct {
	db *gorm.DB
	Repository[uuid.UUID, models.JiraIntegration, *gorm.DB]
}

func NewJiraIntegrationRepository(db *gorm.DB) *jiraIntegrationRepository {
	return &jiraIntegrationRepository{
		db:         db,
		Repository: newGormRepository[uuid.UUID, models.JiraIntegration](db),
	}
}

func (r *jiraIntegrationRepository) FindByOrganizationID(orgID uuid.UUID) ([]models.JiraIntegration, error) {
	var integrations []models.JiraIntegration
	if err := r.db.Find(&integrations, "org_id = ?", orgID).Error; err != nil {
		return nil, err
	}
	return integrations, nil
}

func (r *jiraIntegrationRepository) GetClientByIntegrationID(integrationID uuid.UUID) (models.JiraIntegration, error) {
	var integration models.JiraIntegration
	if err := r.db.First(&integration, "id = ?", integrationID).Error; err != nil {
		return models.JiraIntegration{}, err
	}
	return integration, nil
}
