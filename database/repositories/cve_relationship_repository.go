package repositories

import (
	"context"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/utils"
	"gorm.io/gorm"
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

func (repository *cveRelationshipRepository) GetRelationshipsByTargetCVEBatch(ctx context.Context, tx *gorm.DB, targetCVEIDs []string) ([]models.CVERelationship, error) {
	var relations []models.CVERelationship
	err := repository.GetDB(ctx, tx).Where("target_cve IN ?", targetCVEIDs).Find(&relations).Error
	if err != nil {
		return nil, err
	}
	return relations, nil
}
