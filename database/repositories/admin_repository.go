package repositories

import (
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

func (repository AdminRepository) GetAllExternalEntityOrganizations() ([]models.Org, error) {
	orgs := []models.Org{}
	err := repository.db.Raw(`SELECT * FROM organizations o WHERE o.external_entity_provider_id IS NOT NULL;`).Find(&orgs).Error
	return orgs, err
}
