// Copyright 2026 l3montree GmbH.
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package repositories

import (
	"context"

	"fmt"

	"github.com/google/uuid"

	"github.com/l3montree-dev/devguard/database"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/shared"
	"gorm.io/gorm"
)

type externalReferenceRepository struct {
	db              *gorm.DB
	createBatchSize int
}

var _ shared.ExternalReferenceRepository = (*externalReferenceRepository)(nil)

func NewExternalReferenceRepository(db *gorm.DB) shared.ExternalReferenceRepository {
	batchSize, err := database.CalcBatchSize(db, &models.ExternalReference{})
	if err != nil {
		panic(fmt.Errorf("error calculating batch size: %w", err))
	}
	return &externalReferenceRepository{
		db:              db,
		createBatchSize: batchSize,
	}
}

func (r *externalReferenceRepository) GetDB(ctx context.Context, tx *gorm.DB) *gorm.DB {
	if tx != nil {
		return tx.Session(&gorm.Session{CreateBatchSize: r.createBatchSize})
	}
	return r.db.Session(&gorm.Session{Context: ctx, CreateBatchSize: r.createBatchSize})
}

func (r *externalReferenceRepository) Create(ctx context.Context, tx *gorm.DB, t *models.ExternalReference) error {
	return r.GetDB(ctx, tx).Create(t).Error
}

func (r *externalReferenceRepository) SaveBatch(ctx context.Context, tx *gorm.DB, ts []models.ExternalReference) error {
	if len(ts) == 0 {
		return nil
	}
	return r.GetDB(ctx, tx).Save(ts).Error
}

func (r *externalReferenceRepository) FindByAssetID(ctx context.Context, tx *gorm.DB, assetID uuid.UUID) ([]models.ExternalReference, error) {
	var refs []models.ExternalReference
	err := r.GetDB(ctx, tx).Where("asset_id = ?", assetID).Find(&refs).Error
	return refs, err
}

func (r *externalReferenceRepository) DeleteByURL(ctx context.Context, tx *gorm.DB, assetID uuid.UUID, url string) error {
	return r.GetDB(ctx, tx).Where("asset_id = ? AND url = ?", assetID, url).Delete(&models.ExternalReference{}).Error
}
