package repositories

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"gorm.io/gorm"
)

type trustedEntityRepository struct {
	db *gorm.DB
	utils.Repository[uuid.UUID, models.TrustedEntity, *gorm.DB]
}

func NewTrustedEntityRepository(db *gorm.DB) *trustedEntityRepository {
	return &trustedEntityRepository{
		db:         db,
		Repository: newGormRepository[uuid.UUID, models.TrustedEntity](db),
	}
}

var _ shared.TrustedEntityRepository = (*trustedEntityRepository)(nil)

func (r *trustedEntityRepository) UpsertOrganizationTrust(ctx context.Context, tx *gorm.DB, organizationID uuid.UUID, trustScore float64) error {
	db := r.GetDB(ctx, tx)

	// Try to find existing entry
	var existing models.TrustedEntity
	err := db.Where("organization_id = ?", organizationID).First(&existing).Error

	if errors.Is(err, gorm.ErrRecordNotFound) {
		// Create new entry
		trustedEntity := models.TrustedEntity{
			OrganizationID: &organizationID,
			ProjectID:      nil,
			TrustScore:     trustScore,
		}
		return db.Create(&trustedEntity).Error
	} else if err != nil {
		return err
	}

	// Update existing entry
	return db.Model(&existing).Updates(map[string]interface{}{
		"trustscore": trustScore,
		"updated_at": gorm.Expr("NOW()"),
	}).Error
}

func (r *trustedEntityRepository) UpsertProjectTrust(ctx context.Context, tx *gorm.DB, projectID uuid.UUID, trustScore float64) error {
	db := r.GetDB(ctx, tx)

	// Try to find existing entry
	var existing models.TrustedEntity
	err := db.Where("project_id = ?", projectID).First(&existing).Error

	if err == gorm.ErrRecordNotFound {
		// Create new entry
		trustedEntity := models.TrustedEntity{
			OrganizationID: nil,
			ProjectID:      &projectID,
			TrustScore:     trustScore,
		}
		return db.Create(&trustedEntity).Error
	} else if err != nil {
		return err
	}

	// Update existing entry
	return db.Model(&existing).Updates(map[string]any{
		"trustscore": trustScore,
		"updated_at": gorm.Expr("NOW()"),
	}).Error
}

func (r *trustedEntityRepository) GetOrganizationTrust(ctx context.Context, tx *gorm.DB, organizationID uuid.UUID) (*models.TrustedEntity, error) {
	var entity models.TrustedEntity
	err := r.GetDB(ctx, tx).Where("organization_id = ?", organizationID).First(&entity).Error
	if err != nil {
		return nil, err
	}
	return &entity, nil
}

func (r *trustedEntityRepository) GetProjectTrust(ctx context.Context, tx *gorm.DB, projectID uuid.UUID) (*models.TrustedEntity, error) {
	var entity models.TrustedEntity
	err := r.GetDB(ctx, tx).Where("project_id = ?", projectID).First(&entity).Error
	if err != nil {
		return nil, err
	}
	return &entity, nil
}

func (r *trustedEntityRepository) DeleteOrganizationTrust(ctx context.Context, tx *gorm.DB, organizationID uuid.UUID) error {
	return r.GetDB(ctx, tx).Where("organization_id = ?", organizationID).Delete(&models.TrustedEntity{}).Error
}

func (r *trustedEntityRepository) DeleteProjectTrust(ctx context.Context, tx *gorm.DB, projectID uuid.UUID) error {
	return r.GetDB(ctx, tx).Where("project_id = ?", projectID).Delete(&models.TrustedEntity{}).Error
}

func (r *trustedEntityRepository) ListAllTrustedEntities(ctx context.Context, tx *gorm.DB) ([]models.TrustedEntity, error) {
	var entities []models.TrustedEntity
	err := r.GetDB(ctx, tx).Find(&entities).Error
	return entities, err
}

func (r *trustedEntityRepository) GetTrustedEntitiesByProjectIDs(ctx context.Context, tx *gorm.DB, projectIDs []uuid.UUID) ([]models.TrustedEntity, error) {
	var trustedEntities []models.TrustedEntity
	err := r.GetDB(ctx, tx).Model(&models.TrustedEntity{}).Where("project_id IN ?", projectIDs).Find(&trustedEntities).Error
	return trustedEntities, err
}

func (r *trustedEntityRepository) GetTrustedEntitiesByOrganizationIDs(ctx context.Context, tx *gorm.DB, organizationIDs []uuid.UUID) ([]models.TrustedEntity, error) {
	var trustedEntities []models.TrustedEntity
	err := r.GetDB(ctx, tx).Model(&models.TrustedEntity{}).Where("organization_id IN ?", organizationIDs).Find(&trustedEntities).Error
	return trustedEntities, err
}
