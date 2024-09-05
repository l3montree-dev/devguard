package repositories

import (
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"gorm.io/gorm"
)

type cweRepository struct {
	db *gorm.DB
	Repository[string, models.CWE, core.DB]
}

func NewCWERepository(db core.DB) *cweRepository {
	if err := db.AutoMigrate(&models.CWE{}); err != nil {
		panic(err)
	}
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
