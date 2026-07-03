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
	utils.Repository[int64, models.Advisory, *gorm.DB]
}

func NewAdvisoryRepository(db *gorm.DB) *AdvisoryRepository {
	return &AdvisoryRepository{
		db:         db,
		Repository: newGormRepository[int64, models.Advisory](db),
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

func (advisoryRepository *AdvisoryRepository) ReadAll(ctx context.Context, tx *gorm.DB, assetID uuid.UUID, filter []shared.FilterQuery, pagination shared.PageInfo) (shared.Paged[models.Advisory], error) {
	advisories := []models.Advisory{}
	db := advisoryRepository.GetDB(ctx, tx)
	query := db.Model(&models.Advisory{}).Preload("AffectedPackages").Where("asset_id = ?", assetID)

	for _, f := range filter {
		query = query.Where(f.SQL(), f.Value())
	}

	var count int64
	if err := query.Count(&count).Error; err != nil {
		return shared.Paged[models.Advisory]{}, err
	}

	if err := pagination.ApplyOnDB(query).Find(&advisories).Error; err != nil {
		return shared.Paged[models.Advisory]{}, err
	}

	return shared.NewPaged(pagination, count, advisories), nil
}

func (advisoryRepository *AdvisoryRepository) ReadAdvisory(ctx context.Context, tx *gorm.DB, id int64) (models.Advisory, error) {
	advisory := models.Advisory{}
	db := advisoryRepository.GetDB(ctx, tx)
	err := db.Preload("AffectedPackages").Where("id = ?", id).First(&advisory).Error
	return advisory, err
}

func (advisoryRepository *AdvisoryRepository) Update(ctx context.Context, tx *gorm.DB, id int64, advisory *models.Advisory) error {
	return advisoryRepository.GetDB(ctx, tx).Session(&gorm.Session{FullSaveAssociations: true}).Save(advisory).Error
}

func (advisoryRepository *AdvisoryRepository) Delete(ctx context.Context, tx *gorm.DB, id int64) error {
	err := advisoryRepository.GetDB(ctx, tx).Delete(&models.Advisory{ID: id}).Error
	if err != nil {
		return err
	}
	return nil
}

func (advisoryRepository *AdvisoryRepository) GetAllAdvisoriesByAssetID(ctx context.Context, assetID uuid.UUID) ([]models.Advisory, error) {
	advisories := []models.Advisory{}
	err := advisoryRepository.GetDB(ctx, nil).
		Preload("AffectedPackages").
		Where("asset_id = ?", assetID).
		Find(&advisories).Error
	return advisories, err

}
