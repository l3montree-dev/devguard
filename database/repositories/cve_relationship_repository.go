package repositories

import (
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/utils"
	"gorm.io/gorm"
)

type cveRelationshipRepository struct {
	db *gorm.DB
	utils.Repository[string, models.CVERelationShip, *gorm.DB]
}

func NewCveRelationshipRepository(db *gorm.DB) *cveRelationshipRepository {
	return &cveRelationshipRepository{
		db:         db,
		Repository: newGormRepository[string, models.CVERelationShip](db),
	}
}

// get all source CVEs which relate to this CVE
func (repository *cveRelationshipRepository) GetAllRelationsForCVE(tx *gorm.DB, targetCVEID string) ([]models.CVERelationShip, error) {
	var relations []models.CVERelationShip
	err := repository.GetDB(tx).Where("target_cve=?", targetCVEID).Find(&relations).Error
	return relations, err
}
