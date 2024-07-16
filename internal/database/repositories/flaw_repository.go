package repositories

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"gorm.io/gorm"
)

type flawRepository struct {
	db core.DB
	Repository[string, models.Flaw, core.DB]
}

func NewFlawRepository(db core.DB) *flawRepository {
	if err := db.AutoMigrate(&models.Flaw{}); err != nil {
		panic(err)
	}
	return &flawRepository{
		db:         db,
		Repository: newGormRepository[string, models.Flaw](db),
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

func (r *flawRepository) ListByScanner(assetID uuid.UUID, scannerID string) ([]models.Flaw, error) {
	var flaws []models.Flaw = []models.Flaw{}
	if err := r.Repository.GetDB(r.db).Preload("CVE").Where("asset_id = ? AND scanner_id = ?", assetID, scannerID).Find(&flaws).Error; err != nil {
		return nil, err
	}
	return flaws, nil
}

func (r *flawRepository) GetByAssetIdPaged(tx core.DB, pageInfo core.PageInfo, filter []core.FilterQuery, sort []core.SortQuery, assetId uuid.UUID) (core.Paged[models.Flaw], error) {
	var count int64
	var flaws []models.Flaw = []models.Flaw{}

	q := r.Repository.GetDB(tx).Joins("CVE").Joins("Component").Where("asset_id = ?", assetId)

	// apply filters
	for _, f := range filter {
		q = q.Where(f.SQL(), f.Value())
	}
	q.Model(&models.Flaw{}).Count(&count)

	// get all flaws of the asset
	q = pageInfo.ApplyOnDB(r.Repository.GetDB(tx)).Joins("CVE").Joins("Component").Where("asset_id = ?", assetId)

	// apply filters
	for _, f := range filter {
		q = q.Where(f.SQL(), f.Value())
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

func (r *flawRepository) GetAllFlawsByAssetID(tx core.DB, assetID uuid.UUID) ([]models.Flaw, error) {
	var flaws []models.Flaw = []models.Flaw{}
	if err := r.Repository.GetDB(tx).Where("asset_id = ?", assetID).Find(&flaws).Error; err != nil {
		return nil, err
	}
	return flaws, nil
}

func (g flawRepository) Read(id string) (models.Flaw, error) {
	var t models.Flaw
	err := g.db.Preload("CVE.Weaknesses").Preload("Events").Preload("CVE").Preload("CVE.Exploits").First(&t, "id = ?", id).Error

	return t, err
}

func (r *flawRepository) GetFlawsByPurlOrCpe(tx core.DB, purlOrCpe []string) ([]models.Flaw, error) {

	var flaws []models.Flaw = []models.Flaw{}
	if len(purlOrCpe) == 0 {
		return flaws, nil
	}

	if err := r.Repository.GetDB(tx).Where("component_purl_or_cpe IN (?)", purlOrCpe).Find(&flaws).Error; err != nil {
		return nil, err
	}
	return flaws, nil
}
