package repositories

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"

	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
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

type riskStats struct {
	TotalRisk   float64 `json:"total_risk"`
	AvgRisk     float64 `json:"avg_risk"`
	MaxRisk     float64 `json:"max_risk"`
	FlawCount   int64   `json:"flaw_count"`
	PackageName string  `json:"package_name"`
}

func (r *flawRepository) GetByAssetIdPaged(tx core.DB, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery, assetId uuid.UUID) (core.Paged[models.Flaw], map[string]int, error) {
	var count int64
	var flaws []models.Flaw = []models.Flaw{}

	q := r.Repository.GetDB(tx).Model(&models.Flaw{}).Joins("CVE").Joins("Component").Where("flaws.asset_id = ?", assetId)

	// apply filters
	for _, f := range filter {
		q = q.Where(f.SQL(), f.Value())
	}
	if search != "" && len(search) > 2 {
		q = q.Where("(\"CVE\".description ILIKE ?  OR flaws.cve_id ILIKE ? OR component_purl ILIKE ?)", "%"+search+"%", "%"+search+"%", "%"+search+"%")
	}

	err := q.Distinct("flaws.component_purl").Count(&count).Error
	if err != nil {
		return core.Paged[models.Flaw]{}, map[string]int{}, err
	}

	// get all flaws of the asset
	q = r.Repository.GetDB(tx).Model(&models.Flaw{}).Joins("CVE").Joins("Component").Where("flaws.asset_id = ?", assetId)

	// apply filters
	for _, f := range filter {
		q = q.Where(f.SQL(), f.Value())
	}

	if search != "" && len(search) > 2 {
		q = q.Where("(\"CVE\".description ILIKE ?  OR flaws.cve_id ILIKE ? OR component_purl ILIKE ?)", "%"+search+"%", "%"+search+"%", "%"+search+"%")
	}

	packageNameQuery := r.GetDB(tx).Table("components").
		Select("SUM(f.raw_risk_assessment) as total_risk, AVG(f.raw_risk_assessment) as avg_risk, MAX(f.raw_risk_assessment) as max_risk, COUNT(f.id) as flaw_count, components.purl as package_name").
		Joins("INNER JOIN flaws f ON components.purl = f.component_purl").
		Where("components.asset_id = ?", "22e14d6a-edfe-4b30-aa30-18ddf3cd15af").
		Group("components.purl")

	// apply sorting
	if len(sort) > 0 {
		for _, s := range sort {
			packageNameQuery = packageNameQuery.Order(s.SQL())
		}
	} else {
		packageNameQuery = packageNameQuery.Order("max_risk DESC")
	}

	res := []riskStats{}
	if err := packageNameQuery.Scan(&res).Error; err != nil {
		return core.Paged[models.Flaw]{}, map[string]int{}, err
	}

	packageNames := utils.Map(res, func(r riskStats) string {
		return r.PackageName
	})

	err = q.Where("flaws.component_purl IN (?)", packageNames).Order("raw_risk_assessment DESC").Find(&flaws).Error

	if err != nil {
		return core.Paged[models.Flaw]{}, map[string]int{}, err
	}
	// order the flaws based on the package name ordering
	packageNameIndexMap := make(map[string]int)
	for i, name := range packageNames {
		packageNameIndexMap[name] = i
	}

	return core.NewPaged(pageInfo, count, flaws), packageNameIndexMap, nil
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
	err := g.db.Preload("CVE.Weaknesses").Preload("Events", func(db core.DB) core.DB {
		return db.Order("created_at ASC")
	}).Preload("CVE").Preload("CVE.Exploits").First(&t, "id = ?", id).Error

	return t, err
}

func (r *flawRepository) GetFlawsByPurl(tx core.DB, purl []string) ([]models.Flaw, error) {

	var flaws []models.Flaw = []models.Flaw{}
	if len(purl) == 0 {
		return flaws, nil
	}

	if err := r.Repository.GetDB(tx).Where("component_purl IN ?", purl).Find(&flaws).Error; err != nil {
		return nil, err
	}

	return flaws, nil
}

func (r *flawRepository) FindByTicketID(tx core.DB, ticketID string) (models.Flaw, error) {
	var flaw models.Flaw
	if err := r.Repository.GetDB(tx).Where("ticket_id = ?", ticketID).First(&flaw).Error; err != nil {
		return models.Flaw{}, err
	}
	return flaw, nil
}

func (r *flawRepository) GetOrgFromFlawID(tx core.DB, flawID string) (models.Org, error) {
	var org models.Org
	if err := r.GetDB(tx).Raw("SELECT organizations.* from organizations left join projects p on organizations.id = p.organization_id left join assets a on p.id = a.project_id left join flaws f on a.id = f.asset_id where f.id = ?", flawID).First(&org).Error; err != nil {
		return models.Org{}, err
	}
	return org, nil
}
