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
	err := repository.GetDB(ctx, tx).Where("LOWER(target_cve) IN ?", utils.ToLowerSlice(targetCVEIDs)).Find(&relations).Error
	if err != nil {
		return nil, err
	}
	return relations, nil
}

/*
Given a CVEID this function finds all Relationships regardless of the direction
Example: Given CVEID "CVE1"
CVE1 -> CVE2
CVE1 -> CVE3
CVE4 -> CVE1
*/
func (repository *cveRelationshipRepository) FindCrossRelationshipsBatch(
	ctx context.Context,
	tx *gorm.DB,
	associatedCVEIDs []string,
) ([]models.CVERelationship, error) {

	const chunkSize = 10000

	lowerIDs := utils.ToLowerSlice(associatedCVEIDs)

	var result []models.CVERelationship

	for start := 0; start < len(lowerIDs); start += chunkSize {
		end := start + chunkSize
		if end > len(lowerIDs) {
			end = len(lowerIDs)
		}

		chunk := lowerIDs[start:end]

		var relationships []models.CVERelationship

		err := repository.GetDB(ctx, tx).
			Where(
				"LOWER(target_cve) IN ? OR LOWER(source_cve) IN ?",
				chunk,
				chunk,
			).
			Find(&relationships).Error

		if err != nil {
			return nil, err
		}

		result = append(result, relationships...)
	}

	return result, nil
}
