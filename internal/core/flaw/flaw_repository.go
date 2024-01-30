package flaw

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/l3montree-dev/flawfix/internal/database"
	"gorm.io/gorm"
)

type GormRepository struct {
	db core.DB
	database.Repository[uuid.UUID, Model, core.DB]
}

type Repository interface {
	database.Repository[uuid.UUID, Model, core.DB]

	GetByAssetId(tx core.DB, assetId uuid.UUID) ([]Model, error)
	GetByAssetIdPaged(tx core.DB, pageInfo core.PageInfo, filter []core.FilterQuery, sort []core.SortQuery, assetId uuid.UUID) (core.Paged[Model], error)
}

func NewGormRepository(db core.DB) Repository {
	return &GormRepository{
		db:         db,
		Repository: database.NewGormRepository[uuid.UUID, Model](db),
	}
}

func (r *GormRepository) GetByAssetId(
	tx *gorm.DB,
	assetId uuid.UUID,
) ([]Model, error) {

	var flaws []Model = []Model{}
	// get all flaws of the asset
	if err := r.Repository.GetDB(tx).Where("asset_id = ?", assetId).Find(&flaws).Error; err != nil {
		return nil, err
	}
	return flaws, nil
}

func (r *GormRepository) GetByAssetIdPaged(tx core.DB, pageInfo core.PageInfo, filter []core.FilterQuery, sort []core.SortQuery, assetId uuid.UUID) (core.Paged[Model], error) {
	var count int64
	var flaws []Model = []Model{}

	q := r.Repository.GetDB(tx).Joins("CVE").Where("asset_id = ?", assetId)

	// apply filters
	for _, f := range filter {
		q = q.Where(f.SQL(), f.Value)
	}
	q.Model(&Model{}).Count(&count)

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
		return core.Paged[Model]{}, err
	}

	return core.NewPaged(pageInfo, count, flaws), nil
}

func (g GormRepository) Read(id uuid.UUID) (Model, error) {
	var t Model
	err := g.db.Preload("CVE.CWEs").Preload("Events").Preload("CVE").First(&t, id).Error

	return t, err
}
