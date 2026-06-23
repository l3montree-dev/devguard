package repositories

import (
	"context"

	"github.com/l3montree-dev/devguard/database/models"
	"gorm.io/gorm"
)

type AdminRepository struct {
	db *gorm.DB
}

func NewAdminRepository(db *gorm.DB) AdminRepository {
	return AdminRepository{
		db: db,
	}
}

func (repository AdminRepository) GetAllExternalEntityOrganizations(ctx context.Context, tx *gorm.DB) ([]models.Org, error) {
	orgs := []models.Org{}
	db := repository.db.WithContext(ctx)
	if tx != nil {
		db = tx
	}
	err := db.Raw(`SELECT * FROM organizations o WHERE o.external_entity_provider_id IS NOT NULL;`).Find(&orgs).Error
	return orgs, err
}
