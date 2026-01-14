package repositories

import (
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/utils"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type cveRelationshipRepository struct {
	db *gorm.DB
	utils.Repository[string, models.CVERelationship, *gorm.DB]
}

func NewCveRelationshipRepository(db *gorm.DB) *cveRelationshipRepository {
	return &cveRelationshipRepository{
		db:         db,
		Repository: newGormRepository[string, models.CVERelationship](db),
	}
}

// get all source CVEs which relate to this CVE
func (repository *cveRelationshipRepository) GetAllRelationsForCVE(tx *gorm.DB, targetCVEID string) ([]models.CVERelationship, error) {
	var relations []models.CVERelationship
	err := repository.GetDB(tx).Where("target_cve=?", targetCVEID).Find(&relations).Error
	return relations, err
}

func (repository *cveRelationshipRepository) GetAllRelationshipsForCVEBatch(tx *gorm.DB, sourceCVEIDs []string) ([]models.CVERelationship, error) {
	var relations []models.CVERelationship
	err := repository.GetDB(tx).Raw("SELECT * FROM cve_relationships cr WHERE cr.source_cve IN ?", sourceCVEIDs).Find(&relations).Error
	if err != nil {
		return nil, err
	}
	return relations, nil
}

func (repository *cveRelationshipRepository) FilterOutRelationsWithInvalidTargetCVE(tx *gorm.DB) error {
	var relationships []models.CVERelationship
	err := repository.GetDB(tx).Raw(`SELECT * FROM cve_relationships a WHERE NOT EXISTS
	(SELECT * FROM cves b WHERE a.target_cve = b.cve);`).Find(&relationships).Error
	if err != nil {
		return err
	}

	batchsize := 1000
	counter := 0
	for counter < len(relationships) {
		var batch []models.CVERelationship
		if counter+batchsize < len(relationships) {
			batch = relationships[counter : counter+batchsize]
			counter += batchsize
		} else {
			batch = relationships[counter:]
			counter += batchsize
		}

		err = repository.GetDB(tx).Session(&gorm.Session{Logger: logger.Default.LogMode(logger.Silent)}).Delete(batch).Error
		if err != nil {
			return err
		}
	}
	return nil
}
