package repositories

import (
	"context"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"gorm.io/gorm"
)

type logRepository struct {
	utils.Repository[uuid.UUID, models.Log, *gorm.DB]
}

func NewLogRepository(db *gorm.DB) *logRepository {
	return &logRepository{
		Repository: newGormRepository[uuid.UUID, models.Log](db),
	}
}

func (r logRepository) Save(ctx context.Context, tx *gorm.DB, log *models.Log) error {
	return r.Repository.GetDB(ctx, tx).Save(log).Error
}

func (r logRepository) ListPaged(ctx context.Context, tx *gorm.DB, orgID uuid.UUID, projectID uuid.UUID, assetID uuid.UUID, pageInfo shared.PageInfo) (shared.Paged[models.Log], error) {
	var count int64
	logs := []models.Log{}
	q := r.Repository.GetDB(ctx, tx).Model(&models.Log{}).Where("org_id = ? AND project_id = ? AND asset_id = ?", orgID, projectID, assetID).Order("created_at DESC, id DESC")

	err := q.Session(&gorm.Session{}).Count(&count).Error
	if err != nil {
		return shared.Paged[models.Log]{}, err
	}

	if err := q.Limit(pageInfo.PageSize).Offset((pageInfo.Page - 1) * pageInfo.PageSize).Find(&logs).Error; err != nil {
		return shared.Paged[models.Log]{}, err
	}

	return shared.NewPaged(pageInfo, count, logs), nil
}
