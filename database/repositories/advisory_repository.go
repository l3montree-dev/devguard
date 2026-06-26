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

func (advisoryRepository *AdvisoryRepository) Create(ctx context.Context, tx *gorm.DB, advisory *models.Advisory) error {
	err := advisoryRepository.GetDB(ctx, tx).Create(advisory).Error
	if err != nil {
		return err
	}
	return nil
}

func (advisoryRepository *AdvisoryRepository) ReadAll(ctx context.Context, tx *gorm.DB, assetID uuid.UUID) ([]models.Advisory, error) {
	advisories := []models.Advisory{}
	db := advisoryRepository.db.WithContext(ctx)
	if tx != nil {
		db = tx
	}
	err := db.Preload("AffectedPackages").Where("asset_id = ?", assetID).Find(&advisories).Error
	return advisories, err
}

func (advisoryRepository *AdvisoryRepository) ReadAdvisory(ctx context.Context, tx *gorm.DB, id uuid.UUID) (models.Advisory, error) {
	advisory := models.Advisory{}
	db := advisoryRepository.db.WithContext(ctx)
	if tx != nil {
		db = tx
	}
	err := db.Preload("AffectedPackages").Where("id = ?", id).Find(&advisory).Error
	return advisory, err
}

func (advisoryRepository *AdvisoryRepository) Update(ctx context.Context, tx *gorm.DB, id uuid.UUID, advisory *models.Advisory) error {
	return advisoryRepository.GetDB(ctx, tx).Session(&gorm.Session{FullSaveAssociations: true}).Save(advisory).Error
}

func (advisoryRepository *AdvisoryRepository) Delete(ctx context.Context, tx *gorm.DB, id uuid.UUID) error {
	db := advisoryRepository.db.WithContext(ctx)
	if tx != nil {
		db = tx
	}
	err := db.Preload("AffectedPackages").Delete(&models.Advisory{Model: models.Model{ID: id}}).Error
	if err != nil {
		return err
	}
	return nil
}
