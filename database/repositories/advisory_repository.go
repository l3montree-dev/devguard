package repositories

import (
	"context"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/statemachine"
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

func (advisoryRepository *AdvisoryRepository) ReadAdvisory(ctx context.Context, tx *gorm.DB, id uuid.UUID) (models.Advisory, error) {
	advisory := models.Advisory{}
	db := withOwnershipScope(ctx, advisoryRepository.GetDB(ctx, tx).Where("id = ?", id), advisory)
	err := db.Preload("AffectedPackages").Preload("Events").First(&advisory).Error
	return advisory, err
}

func (advisoryRepository *AdvisoryRepository) Update(ctx context.Context, tx *gorm.DB, id uuid.UUID, advisory *models.Advisory) error {
	advisory.ID = id
	return advisoryRepository.GetDB(ctx, tx).Session(&gorm.Session{FullSaveAssociations: true}).Save(advisory).Error
}

func (advisoryRepository *AdvisoryRepository) Delete(ctx context.Context, tx *gorm.DB, id uuid.UUID) error {
	err := advisoryRepository.GetDB(ctx, tx).Delete(&models.Advisory{ID: id}).Error
	if err != nil {
		return err
	}
	return nil
}

func (advisoryRepository *AdvisoryRepository) GetAllAdvisoriesByAssetID(ctx context.Context, tx *gorm.DB, assetID uuid.UUID) ([]models.Advisory, error) {
	advisories := []models.Advisory{}
	// CSAF feed must contain published (public) AND withdrawn advisories - a
	// withdrawn advisory stays part of the public record. Only drafts are excluded.
	err := advisoryRepository.GetDB(ctx, tx).
		Preload("AffectedPackages").
		Where("asset_id = ?", assetID).
		Where("visibility IN ?", []string{statemachine.VisibilityPublic, statemachine.VisibilityWithdrawn}).
		Find(&advisories).Error
	return advisories, err

}
