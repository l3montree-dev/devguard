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

func (advisoryRepository *AdvisoryRepository) ReadName(ctx context.Context, tx *gorm.DB) ([]models.Advisory, error) {
	advisory_names := []models.Advisory{}
	db := advisoryRepository.db.WithContext(ctx)
	if tx != nil {
		db = tx
	}
	err := db.Raw(`SELECT * FROM advisories;`).Find(&advisory_names).Error
	return advisory_names, err
}

func (advisoryRepository *AdvisoryRepository) UpdateName(ctx context.Context, tx *gorm.DB, id uuid.UUID, name string) error {
	err := advisoryRepository.GetDB(ctx, tx).
		Model(&models.Advisory{Model: models.Model{ID: id}}).
		Update("advisory_name", name).Error
	if err != nil {
		return err
	}
	return nil
}

func (advisoryRepository *AdvisoryRepository) DeleteName(ctx context.Context, tx *gorm.DB, id uuid.UUID) error {
	err := advisoryRepository.GetDB(ctx, tx).Delete(&models.Advisory{Model: models.Model{ID: id}}).Error
	if err != nil {
		return err
	}
	return nil
}
