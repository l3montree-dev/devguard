package repositories

import (
	"context"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"gorm.io/gorm"
)

type AdvisoryRepository struct {
	db *gorm.DB
	utils.Repository[uuid.UUID, models.Advisory, *gorm.DB]
}

func NewAdvisoryRepository(db *gorm.DB) *AdvisoryRepository {
	return &AdvisoryRepository{
		db:         db,
		Repository: newGormRepository[uuid.UUID, models.Advisory](db),
	}
}

var _ shared.AdvisoryRepository = (*AdvisoryRepository)(nil)

func (advisoryRepository *AdvisoryRepository) CreateName(ctx context.Context, tx *gorm.DB, name string) error {
	err := advisoryRepository.GetDB(ctx, tx).Create(&models.Advisory{AdvisoryName: name}).Error
	if err != nil {
		return err
	}
	return nil
}
