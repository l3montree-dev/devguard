package repositories

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/utils"

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

func (r *flawRepository) GetFlawsByAssetID(tx core.DB, assetID uuid.UUID) ([]models.Flaw, error) {
	var flaws []models.Flaw = []models.Flaw{}

	var assetVersionIds []uuid.UUID = []uuid.UUID{}

	if err := r.Repository.GetDB(tx).Model(&models.AssetVersion{}).Where("asset_id = ?", assetID).Pluck("id", &assetVersionIds).Error; err != nil {
		return nil, err
	}

	if len(assetVersionIds) == 0 {
		return flaws, nil
	}

	for _, assetVersionId := range assetVersionIds {
		var assetFlaws []models.Flaw = []models.Flaw{}
		if err := r.Repository.GetDB(tx).Where("asset_version_id = ?", assetVersionId).Find(&assetFlaws).Error; err != nil {
			return nil, err
		}
		flaws = append(flaws, assetFlaws...)
	}

	return flaws, nil

}

func (r *flawRepository) GetFlawsByAssetVersionId(tx *gorm.DB, assetVersionId uuid.UUID) ([]models.Flaw, error) {

	var flaws []models.Flaw = []models.Flaw{}
	if err := r.Repository.GetDB(tx).Where("asset_version_id = ?", assetVersionId).Find(&flaws).Error; err != nil {
		return nil, err
	}
	return flaws, nil
}

func (r *flawRepository) ListByScanner(assetVersionID uuid.UUID, scannerID string) ([]models.Flaw, error) {
	var flaws []models.Flaw = []models.Flaw{}
	if err := r.Repository.GetDB(r.db).Preload("CVE").Where("asset_version_id = ? AND scanner_id = ?", assetVersionID, scannerID).Find(&flaws).Error; err != nil {
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

func (r *flawRepository) GetByAssetVersionIdPaged(tx core.DB, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery, assetVersionId uuid.UUID) (core.Paged[models.Flaw], map[string]int, error) {
	var count int64
	var flaws []models.Flaw = []models.Flaw{}

	q := r.Repository.GetDB(tx).Model(&models.Flaw{}).Joins("CVE").Where("flaws.asset_version_id = ?", assetVersionId)

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
	q = r.Repository.GetDB(tx).Model(&models.Flaw{}).Joins("CVE").Where("flaws.asset_version_id = ?", assetVersionId)

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
		Where("f.asset_version_id = ?", assetVersionId.String()).
		Group("components.purl").Limit(pageInfo.PageSize).Offset((pageInfo.Page - 1) * pageInfo.PageSize)

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

func (r *flawRepository) GetFlawsByAssetVersionIdPagedAndFlat(tx core.DB, assetVersionId uuid.UUID, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery) (core.Paged[models.Flaw], error) {
	return r.GetFlawsPaged(tx, []string{assetVersionId.String()}, pageInfo, search, filter, sort)
}

func (r *flawRepository) GetAllOpenFlawsByAssetVersionID(tx core.DB, assetVersionID uuid.UUID) ([]models.Flaw, error) {
	var flaws []models.Flaw = []models.Flaw{}
	if err := r.Repository.GetDB(tx).Where("asset_version_id = ? AND state = ?", assetVersionID, models.FlawStateOpen).Find(&flaws).Error; err != nil {
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

func (g flawRepository) ReadFlawWithAssetEvents(id string) (models.Flaw, error) {
	var t models.Flaw
	err := g.db.Preload("CVE.Weaknesses").Preload("CVE").Preload("CVE.Exploits").First(&t, "id = ?", id).Error

	if err != nil {
		return models.Flaw{}, err
	}

	flawEvents, err := g.GetFlawEventsByFlawAssetID(g.db, t.FlawAssetID)
	if err != nil {
		return models.Flaw{}, err
	}

	t.Events = flawEvents

	return t, err
}

func (g flawRepository) GetFlawEventsByFlawAssetID(tx core.DB, flawAssetID string) ([]models.FlawEvent, error) {
	var flawEvents []models.FlawEvent = []models.FlawEvent{}
	if err := g.Repository.GetDB(tx).Where("flaw_asset_id = ?", flawAssetID).Find(&flawEvents).Order("created_at ASC").Error; err != nil {
		return nil, err
	}
	return flawEvents, nil
}

func (r *flawRepository) GetFlawsByPurl(tx core.DB, purl []string) ([]models.Flaw, error) {

	var flaws []models.Flaw = []models.Flaw{}
	if len(purl) == 0 {
		return flaws, nil
	}

	if err := r.Repository.GetDB(tx).Preload("Events").Joins("CVE").Where("component_purl IN ?", purl).Find(&flaws).Error; err != nil {
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
	if err := r.GetDB(tx).Raw("SELECT organizations.* from organizations left join projects p on organizations.id = p.organization_id left join assets a on p.id = a.project_id left join asset_version av on a.id = av.asset_id left join flaws f on av.id = f.asset_version_id where f.id = ?", flawID).First(&org).Error; err != nil {
		return models.Org{}, err
	}
	return org, nil
}
func (r *flawRepository) GetFlawsPaged(tx core.DB, assetVersionIdInSubQuery any, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery) (core.Paged[models.Flaw], error) {
	var flaws []models.Flaw = []models.Flaw{}

	q := r.Repository.GetDB(tx).Model(&models.Flaw{}).Preload("Events").Joins("CVE").Where("flaws.asset_version_id IN (?)", assetVersionIdInSubQuery)

	// apply filters
	for _, f := range filter {
		q = q.Where(f.SQL(), f.Value())
	}
	if search != "" && len(search) > 2 {
		q = q.Where("(\"CVE\".description ILIKE ?  OR flaws.cve_id ILIKE ? OR component_purl ILIKE ?)", "%"+search+"%", "%"+search+"%", "%"+search+"%")
	}

	// apply sorting
	if len(sort) > 0 {
		for _, s := range sort {
			q = q.Order(s.SQL())
		}
	} else {
		q = q.Order("flaws.cve_id DESC")
	}

	var count int64

	err := q.Count(&count).Error
	if err != nil {
		return core.Paged[models.Flaw]{}, err
	}

	err = q.Limit(pageInfo.PageSize).Offset((pageInfo.Page - 1) * pageInfo.PageSize).Find(&flaws).Error

	if err != nil {
		return core.Paged[models.Flaw]{}, err
	}

	return core.NewPaged(pageInfo, count, flaws), nil
}

func (r *flawRepository) GetDefaultFlawsByProjectIdPaged(tx core.DB, projectID uuid.UUID, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery) (core.Paged[models.Flaw], error) {

	subQueryAssetIDs := r.Repository.GetDB(tx).Model(&models.AssetNew{}).Select("id").Where("project_id = ?", projectID)

	subQuery := r.Repository.GetDB(tx).Model(&models.AssetVersion{}).Select("asset_id").Where("asset_id IN (?)", subQueryAssetIDs, "default_branch", true)

	return r.GetFlawsPaged(tx, subQuery, pageInfo, search, filter, sort)
}

func (r *flawRepository) GetDefaultFlawsByOrgIdPaged(tx core.DB, userAllowedProjectIds []string, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery) (core.Paged[models.Flaw], error) {

	subQueryAssetIDs := r.Repository.GetDB(tx).Model(&models.AssetNew{}).Select("assets.id").Where("assets.project_id IN (?)", userAllowedProjectIds)

	subQuery := r.Repository.GetDB(tx).Model(&models.AssetVersion{}).Select("asset_id").Where("asset_id IN (?)", subQueryAssetIDs, "default_branch", true)

	return r.GetFlawsPaged(tx, subQuery, pageInfo, search, filter, sort)
}

func (r *flawRepository) GetFlawAssetIDByFlawID(tx core.DB, flawID string) (string, error) {
	var flawAssetID string
	if err := r.Repository.GetDB(tx).Model(&models.Flaw{}).Select("flaw_asset_id").Where("id = ?", flawID).Row().Scan(&flawAssetID); err != nil {
		return "", err
	}
	return flawAssetID, nil
}
