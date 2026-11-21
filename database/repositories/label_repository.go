package repositories

import (
	"context"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/utils"
	"gorm.io/gorm"
)

type LabelRepository struct {
	db *gorm.DB
	utils.Repository[uuid.UUID, models.Label, *gorm.DB]
}

func NewLabelRepository(db *gorm.DB) *LabelRepository {
	return &LabelRepository{
		db:         db,
		Repository: newGormRepository[uuid.UUID, models.Label](db),
	}
}

func (l *LabelRepository) ListOnOrgLevel(ctx context.Context, tx *gorm.DB, orgID uuid.UUID) ([]models.Label, error) {
	var labels []models.Label
	err := l.GetDB(ctx, tx).Where("organization_id = ? AND project_id IS NULL AND asset_id IS NULL", orgID).Find(&labels).Error
	if err != nil {
		return nil, err
	}
	return labels, nil
}

func (l *LabelRepository) ListOnProjectLevel(ctx context.Context, tx *gorm.DB, orgID, projectID uuid.UUID) ([]models.Label, error) {
	var labels []models.Label
	err := l.GetDB(ctx, tx).Where("organization_id = ? AND project_id = ? AND asset_id IS NULL", orgID, projectID).Find(&labels).Error
	if err != nil {
		return nil, err
	}
	return labels, nil
}

func (l *LabelRepository) ListOnAssetLevel(ctx context.Context, tx *gorm.DB, orgID, projectID, assetID uuid.UUID) ([]models.Label, error) {
	var labels []models.Label
	err := l.GetDB(ctx, tx).Where("organization_id = ? AND project_id = ? AND asset_id = ?", orgID, projectID, assetID).Find(&labels).Error
	if err != nil {
		return nil, err
	}
	return labels, nil
}
