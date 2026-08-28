// Copyright 2026 l3montree GmbH.
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package repositories

import (
	"context"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"gorm.io/gorm"
)

type externalReferenceRepository struct {
	db *gorm.DB
}

var _ shared.ExternalReferenceRepository = (*externalReferenceRepository)(nil)

func NewExternalReferenceRepository(db *gorm.DB) shared.ExternalReferenceRepository {
	return &externalReferenceRepository{
		db: db,
	}
}

func (r *externalReferenceRepository) GetDB(ctx context.Context, tx *gorm.DB) *gorm.DB {
	if tx != nil {
		return tx
	}
	return r.db.WithContext(ctx)
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

func (r *externalReferenceRepository) FindByAssetIDWithVexRuleCountPaged(ctx context.Context, tx *gorm.DB, assetID uuid.UUID, pageInfo shared.PageInfo, search string, filterQuery []shared.FilterQuery, sortQuery []shared.SortQuery) (shared.Paged[dtos.ExternalReferenceDTO], error) {
	var refs []dtos.ExternalReferenceDTO
	var total int64

	query := r.GetDB(ctx, tx).Table("external_references").
		Joins("LEFT JOIN vex_rules ON vex_rules.vex_source = external_references.url AND vex_rules.asset_id = external_references.asset_id").
		Where("external_references.asset_id = ?", assetID).
		Where("external_references.type != ?", dtos.ExternalReferenceTypeUnknown)

	// Apply search filter
	if search != "" {
		searchPattern := "%" + search + "%"
		query = query.Where("external_references.url ILIKE ?", searchPattern)
	}

	// Apply filter queries
	for _, filter := range filterQuery {
		query = filter.Where(query)
	}

	query = query.Group("external_references.asset_id, external_references.url")

	// Count total before pagination
	if err := query.Session(&gorm.Session{}).Distinct("external_references.url").Count(&total).Error; err != nil {
		return shared.Paged[dtos.ExternalReferenceDTO]{}, err
	}

	query = query.Select("external_references.*, COUNT(vex_rules.id) AS vex_rule_count")

	// Apply sorting
	if len(sortQuery) > 0 {
		for _, sort := range sortQuery {
			query = sort.Order(query)
		}
	} else {
		query = query.Order("external_references.url ASC")
	}

	// Apply pagination
	query = pageInfo.ApplyOnDB(query)

	if err := query.Find(&refs).Error; err != nil {
		return shared.Paged[dtos.ExternalReferenceDTO]{}, err
	}

	return shared.NewPaged(pageInfo, total, refs), nil
}

func (r *externalReferenceRepository) DeleteByURL(ctx context.Context, tx *gorm.DB, assetID uuid.UUID, url string) error {
	return r.GetDB(ctx, tx).Where("asset_id = ? AND url = ?", assetID, url).Delete(&models.ExternalReference{}).Error
}
