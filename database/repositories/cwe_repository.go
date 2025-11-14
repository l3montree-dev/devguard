package repositories

import (
	"github.com/l3montree-dev/devguard/common"
	"github.com/l3montree-dev/devguard/database/models"
	"gorm.io/gorm"
)

type cweRepository struct {
	db *gorm.DB
	common.Repository[string, models.CWE, *gorm.DB]
}

func NewCWERepository(db *gorm.DB) *cweRepository {
	return &cweRepository{
		db:         db,
		Repository: newGormRepository[string, models.CWE](db),
	}
}

func (g *cweRepository) GetAllCWEsID() ([]string, error) {
	var cwesID []string
	batchSize := 10000
	offset := 0

	for {
		var batch []string
		err := g.db.Model(&models.CWE{}).
			Offset(offset).
			Limit(batchSize).
			Pluck("cwe", &batch).
			Error
		if err != nil {
			return nil, err
		}
		if len(batch) == 0 {
			break
		}
		cwesID = append(cwesID, batch...)
		offset += batchSize
	}
	return cwesID, nil
}
