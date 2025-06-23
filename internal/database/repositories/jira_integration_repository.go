// Copyright 2025 l3montree GmbH.
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package repositories

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
)

type jiraIntegrationRepository struct {
	db core.DB
	common.Repository[uuid.UUID, models.JiraIntegration, core.DB]
}

func NewJiraIntegrationRepository(db core.DB) *jiraIntegrationRepository {
	if err := db.AutoMigrate(&models.JiraIntegration{}); err != nil {
		panic(err)
	}
	return &jiraIntegrationRepository{
		db:         db,
		Repository: newGormRepository[uuid.UUID, models.JiraIntegration](db),
	}
}

func (r *jiraIntegrationRepository) FindByOrganizationId(orgId uuid.UUID) ([]models.JiraIntegration, error) {
	var integrations []models.JiraIntegration
	if err := r.db.Find(&integrations, "org_id = ?", orgId).Error; err != nil {
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
