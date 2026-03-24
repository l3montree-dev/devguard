package repositories

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
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

func (r *trustedEntityRepository) UpsertOrganizationTrust(ctx context.Context, tx *gorm.DB, organizationID uuid.UUID, trustScore float64) error {
	db := r.GetDB(ctx, tx)

	// Try to find existing entry
	var existing models.TrustedEntity
	err := db.Where("organization_id = ?", organizationID, "organization").First(&existing).Error

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
	err := db.Where("project_id = ?", projectID, "project").First(&existing).Error

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
	return db.Model(&existing).Updates(map[string]interface{}{
		"trustscore": trustScore,
		"updated_at": gorm.Expr("NOW()"),
	}).Error
}

func (r *trustedEntityRepository) GetOrganizationTrust(organizationID uuid.UUID) (*models.TrustedEntity, error) {
	var entity models.TrustedEntity
	err := r.db.Where("organization_id = ?", organizationID, "organization").First(&entity).Error
	if err != nil {
		return nil, err
	}
	return &entity, nil
}

func (r *trustedEntityRepository) GetProjectTrust(projectID uuid.UUID) (*models.TrustedEntity, error) {
	var entity models.TrustedEntity
	err := r.db.Where("project_id = ?", projectID, "project").First(&entity).Error
	if err != nil {
		return nil, err
	}
	return &entity, nil
}

func (r *trustedEntityRepository) DeleteOrganizationTrust(ctx context.Context, tx *gorm.DB, organizationID uuid.UUID) error {
	return r.GetDB(ctx, tx).Where("organization_id = ?", organizationID, "organization").Delete(&models.TrustedEntity{}).Error
}

func (r *trustedEntityRepository) DeleteProjectTrust(ctx context.Context, tx *gorm.DB, projectID uuid.UUID) error {
	return r.GetDB(ctx, tx).Where("project_id = ?", projectID, "project").Delete(&models.TrustedEntity{}).Error
}

func (r *trustedEntityRepository) ListAllTrustedEntities() ([]models.TrustedEntity, error) {
	var entities []models.TrustedEntity
	err := r.db.Find(&entities).Error
	return entities, err
}
