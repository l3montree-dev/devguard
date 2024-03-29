package repositories

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/l3montree-dev/flawfix/internal/database/models"
	"gorm.io/gorm"
)

type flawRepository struct {
	db core.DB
	Repository[uuid.UUID, models.Flaw, core.DB]
}

func NewFlawRepository(db core.DB) *flawRepository {
	if err := db.AutoMigrate(&models.Flaw{}); err != nil {
		panic(err)
	}
	return &flawRepository{
		db:         db,
		Repository: newGormRepository[uuid.UUID, models.Flaw](db),
	}
}

func (r *flawRepository) GetByAssetId(
	tx *gorm.DB,
	assetId uuid.UUID,
) ([]models.Flaw, error) {

	var flaws []models.Flaw = []models.Flaw{}
	// get all flaws of the asset
	if err := r.Repository.GetDB(tx).Where("asset_id = ?", assetId).Find(&flaws).Error; err != nil {
		return nil, err
	}
	return flaws, nil
}

func (r *flawRepository) GetByAssetIdPaged(tx core.DB, pageInfo core.PageInfo, filter []core.FilterQuery, sort []core.SortQuery, assetId uuid.UUID) (core.Paged[models.Flaw], error) {
	var count int64
	var flaws []models.Flaw = []models.Flaw{}

	q := r.Repository.GetDB(tx).Joins("CVE").Where("asset_id = ?", assetId)

	// apply filters
	for _, f := range filter {
		q = q.Where(f.SQL(), f.Value)
	}
	q.Model(&models.Flaw{}).Count(&count)

	// get all flaws of the asset
	q = pageInfo.ApplyOnDB(r.Repository.GetDB(tx)).Joins("CVE").Where("asset_id = ?", assetId)

	// apply filters
	for _, f := range filter {
		q = q.Where(f.SQL(), f.Value)
	}

	// apply sorting
	if len(sort) > 0 {
		for _, s := range sort {
			q = q.Order(s.SQL())
		}
	} else {
		q = q.Order("\"CVE\".\"cvss\" desc")
	}

	err := q.Find(&flaws).Error

	if err != nil {
		return core.Paged[models.Flaw]{}, err
	}

	return core.NewPaged(pageInfo, count, flaws), nil
}

func (g flawRepository) Read(id uuid.UUID) (models.Flaw, error) {
	var t models.Flaw
	err := g.db.Preload("CVE.CWEs").Preload("Events").Preload("CVE").First(&t, id).Error

	return t, err
}
