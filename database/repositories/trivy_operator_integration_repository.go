// Copyright (C) 2026 l3montree GmbH
// SPDX-License-Identifier: AGPL-3.0-or-later

package repositories

import (
	"context"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/utils"
	"gorm.io/gorm"
)

type trivyOperatorIntegrationRepository struct {
	db *gorm.DB
	utils.Repository[uuid.UUID, models.TrivyOperatorIntegration, *gorm.DB]
}

func NewTrivyOperatorIntegrationRepository(db *gorm.DB) *trivyOperatorIntegrationRepository {
	return &trivyOperatorIntegrationRepository{
		db:         db,
		Repository: newGormRepository[uuid.UUID, models.TrivyOperatorIntegration](db),
	}
}

func (r *trivyOperatorIntegrationRepository) FindByOrganizationID(ctx context.Context, tx *gorm.DB, orgID uuid.UUID) ([]models.TrivyOperatorIntegration, error) {
	var integrations []models.TrivyOperatorIntegration
	if err := r.GetDB(ctx, tx).Find(&integrations, "org_id = ?", orgID).Error; err != nil {
		return nil, err
	}
	return integrations, nil
}

func (r *trivyOperatorIntegrationRepository) FindBySecret(ctx context.Context, tx *gorm.DB, secret string) (models.TrivyOperatorIntegration, error) {
	var integration models.TrivyOperatorIntegration
	if err := r.GetDB(ctx, tx).First(&integration, "secret = ?", secret).Error; err != nil {
		return models.TrivyOperatorIntegration{}, err
	}
	return integration, nil
}
