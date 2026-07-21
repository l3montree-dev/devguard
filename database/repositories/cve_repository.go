package repositories

import (
	"context"
	"log/slog"
	"time"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"
)

type cveRepository struct {
	db *gorm.DB
	utils.Repository[string, models.CVE, *gorm.DB]
}

func NewCVERepository(db *gorm.DB) *cveRepository {
	return &cveRepository{
		db:         db,
		Repository: newGormRepository[string, models.CVE](db),
	}
}

func (g *cveRepository) GetLastModDate(ctx context.Context, tx *gorm.DB) (time.Time, error) {
	var cve models.CVE
	err := g.GetDB(ctx, tx).Order("date_last_modified desc").First(&cve).Error

	return cve.DateLastModified, err
}

func (g *cveRepository) FindByID(ctx context.Context, tx *gorm.DB, id string) (models.CVE, error) {
	var t models.CVE
	err := g.GetDB(ctx, tx).First(&t, "LOWER(cve) = LOWER(?)", id).Error

	return t, err
}

func (g *cveRepository) GetAllCVEsID(ctx context.Context, tx *gorm.DB) ([]string, error) {
	var cvesID []string
	err := g.GetDB(ctx, tx).Model(&models.CVE{}).
		Pluck("cve", &cvesID).
		Error
	return cvesID, err
}

func (g *cveRepository) FindAll(ctx context.Context, tx *gorm.DB, cveIDs []string) ([]models.CVE, error) {
	var cves []models.CVE
	err := g.GetDB(ctx, tx).Find(&cves, "LOWER(cve) IN ?", utils.ToLowerSlice(cveIDs)).Error
	return cves, err
}

func (g *cveRepository) SaveCveAffectedComponents(ctx context.Context, tx *gorm.DB, cveID string, affectedComponentHashes []int64) error {

	affectedComponents := utils.Map(utils.UniqBy(affectedComponentHashes, func(c int64) int64 {
		return c
	}), func(c int64) models.AffectedComponent {
		return models.AffectedComponent{
			ID: c,
		}
	})

	// add cpeCveMatches to the cve
	m := g.GetDB(ctx, tx).Session(&gorm.Session{
		// disable logging
		// it might log slow queries or a missing cve.
		Logger:               logger.Default.LogMode(logger.Silent),
		FullSaveAssociations: false,
	}).Model(&models.CVE{
		CVE: cveID,
	})
	assoc := m.Association("AffectedComponents")
	return assoc.Append(&affectedComponents)
}

func (g *cveRepository) createInBatches(ctx context.Context, tx *gorm.DB, cves []models.CVE, batchSize int) error {
	err := g.GetDB(ctx, tx).Session(
		&gorm.Session{
			Logger:               logger.Default.LogMode(logger.Silent),
			FullSaveAssociations: true,
		}).Clauses(
		clause.OnConflict{
			UpdateAll: true,
		},
	).CreateInBatches(&cves, batchSize).Error
	// check if we got a protocol error since we are inserting more than 65535 parameters
	if err != nil && err.Error() == "extended protocol limited to 65535 parameters; extended protocol limited to 65535 parameters" {
		newBatchSize := batchSize / 2
		if newBatchSize < 1 {
			// we can't reduce the batch size anymore
			// lets try to save the CVEs one by one
			// this will be slow but it will work
			for _, cve := range cves {
				tmpCVE := cve
				if err := g.GetDB(ctx, tx).Session(
					&gorm.Session{
						Logger:               logger.Default.LogMode(logger.Silent),
						FullSaveAssociations: true,
					}).Clauses(
					clause.OnConflict{
						UpdateAll: true,
					},
				).Create(&tmpCVE).Error; err != nil {
					// log, that we werent able to save the CVE
					slog.Error("unable to save CVE", "cve", cve.CVE, "err", err)
				}
			}
			return nil
		}
		slog.Warn("protocol error, trying to reduce batch size", "newBatchSize", newBatchSize, "oldBatchSize", batchSize, "err", err)
		return g.createInBatches(ctx, tx, cves, newBatchSize)
	}
	return err
}

func (g *cveRepository) SaveBatch(ctx context.Context, tx *gorm.DB, cves []models.CVE) error {
	return g.createInBatches(ctx, tx, cves, 1000)
}

func (g *cveRepository) Save(ctx context.Context, tx *gorm.DB, cve *models.CVE) error {
	return g.GetDB(ctx, tx).Clauses(
		clause.OnConflict{
			UpdateAll: true,
		},
	).Save(cve).Error
}

func applyFilters(q *gorm.DB, filter []shared.FilterQuery) (*gorm.DB, bool) {
	hasEcosystemJoin := false
	for _, f := range filter {
		if f.Field == "ecosystem" {
			if !hasEcosystemJoin {
				q = q.Joins("JOIN cve_affected_component ON cve_affected_component.cve_id = cves.id").
					Joins("JOIN affected_components ON affected_components.id = cve_affected_component.affected_component_id").
					Distinct()
				hasEcosystemJoin = true
			}
			q = q.Where("affected_components.ecosystem ILIKE ?", f.FieldValue)
		} else {
			q = q.Where(f.SQL(), f.Value())
		}
	}
	return q, hasEcosystemJoin
}

func (g *cveRepository) FindAllListPaged(ctx context.Context, tx *gorm.DB, pageInfo shared.PageInfo, filter []shared.FilterQuery, sort []shared.SortQuery) (shared.Paged[models.CVE], error) {
	var count int64
	var cves = []models.CVE{}

	q := g.GetDB(ctx, tx).Model(&models.CVE{})
	q, _ = applyFilters(q, filter)
	q.Count(&count)

	// get all cves
	q = pageInfo.ApplyOnDB(g.GetDB(ctx, tx))
	q, _ = applyFilters(q, filter)

	// apply sorting
	if len(sort) > 0 {
		for _, s := range sort {
			q = q.Order(s.SQL())
		}
	} else {
		q = q.Order("date_last_modified desc")
	}

	err := q.Preload("AffectedComponents").Preload("Exploits").Find(&cves).Error
	if err != nil {
		return shared.Paged[models.CVE]{}, err
	}

	return shared.NewPaged(pageInfo, count, cves), nil
}

func (g *cveRepository) FindCVE(ctx context.Context, tx *gorm.DB, cveID string) (models.CVE, error) {

	var cve models.CVE

	q := g.GetDB(ctx, tx).Model(&models.CVE{})

	q = q.Where("LOWER(cve) = LOWER(?)", cveID)

	err := q.Preload("AffectedComponents").Preload("Exploits").Preload("Relationships.TargetCVEData").First(&cve).Error
	if err != nil {
		return models.CVE{}, err
	}

	return cve, nil
}

// this method is used inside the risk_daemon to get all cves.
// we need this to run FAST. Do not add any preloading here (except exploits). We do not need it in the risk_daemons.
// create your own method if you need preloading.
func (g *cveRepository) FindCVEs(ctx context.Context, tx *gorm.DB, cveIds []string) ([]models.CVE, error) {
	var cves []models.CVE
	err := g.GetDB(ctx, tx).Where("LOWER(cve) IN ?", utils.ToLowerSlice(cveIds)).Preload("Exploits").Find(&cves).Error
	return cves, err
}

func (g *cveRepository) CreateCVEWithConflictHandling(ctx context.Context, tx *gorm.DB, cve *models.CVE) error {
	return g.GetDB(ctx, tx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "cve"}},
		UpdateAll: true,
	}).Create(cve).Error
}

func (g *cveRepository) CreateCVEAffectedComponentsEntries(ctx context.Context, tx *gorm.DB, cve *models.CVE, components []models.AffectedComponent) error {
	cves := make([]string, len(components))
	affectedComponents := make([]int64, len(components))

	for i := range components {
		cves[i] = cve.CVE
		affectedComponents[i] = components[i].CalculateHash()
	}

	query := `INSERT INTO cve_affected_component (affected_component_id,cve_id) 
	SELECT 
	unnest($1::text[]),
	unnest($2::text[])
	ON CONFLICT DO NOTHING`

	return g.GetDB(ctx, tx).Session(&gorm.Session{Logger: logger.Default.LogMode(logger.Silent)}).Exec(query, affectedComponents, cves).Error
}

// this function is used by the epss mirror function to update the epss information for all cves
func (g *cveRepository) UpdateEpssBatch(ctx context.Context, tx *gorm.DB, batch []models.CVE) error {
	ids := make([]string, len(batch))
	epss := make([]float64, len(batch))
	percentiles := make([]float32, len(batch))

	for i := range batch {
		ids[i] = batch[i].CVE
		epssValue := batch[i].EPSS
		if epssValue != nil {
			epss[i] = *epssValue
		}
		percentileValue := batch[i].Percentile
		if percentileValue != nil {
			percentiles[i] = *percentileValue
		}
	}

	// reset the epss and percentile values for all cves that are in the batch but have no epss or percentile value. This is necessary because the FIRST might remove the epss or percentile value for a cve and we need to reflect this in our database.
	if err := g.GetDB(ctx, tx).Exec("UPDATE cves SET epss = NULL, percentile = NULL").Error; err != nil {
		return err
	}

	sql := `UPDATE cves SET epss = new.epss, percentile = new.percentile
	FROM (SELECT
	unnest($1::text[]) as cve,
	unnest($2::numeric(6,5)[]) as epss,
	unnest($3::numeric(6,5)[]) as percentile
	) as new
	WHERE cves.cve = new.cve;`
	// avoid slow sql log
	return g.GetDB(ctx, tx).Exec(sql, ids, epss, percentiles).Error
}

func (g *cveRepository) FindAdvisoriesForCVE(ctx context.Context, tx *gorm.DB, cveID string) ([]models.CVE, error) {
	var advisories []models.CVE
	// find advisories either through direct relations or 1 layer deeper (e.g. for downstream cves)
	err := g.GetDB(ctx, tx).Raw(`
	SELECT DISTINCT
		cves.*
	FROM
		cve_relationships advisory
	JOIN cves
		ON advisory.source_cve = cves.cve
	WHERE
		advisory.relationship_type = ?
	AND advisory.source_cve != ?
	AND (
		advisory.target_cve = ?
		OR advisory.target_cve IN (
			SELECT downstream.target_cve
			FROM cve_relationships downstream
			WHERE downstream.source_cve = ?
		)
	)
	ORDER BY cves.cve DESC -- bsi advisories (wid...) appear before other advisories ;`, dtos.RelationshipTypeAdvisory, cveID, cveID, cveID).Find(&advisories).Error
	return advisories, err
}

// fetches all related cves recursively via their relationships
// and return them grouped by their relationship type
// fetched cves do not have any affected components or relationships
func (g *cveRepository) GetAllRelatedCVEsForCVE(ctx context.Context, tx *gorm.DB, cveID string) (map[dtos.RelationshipType][]models.CVE, error) {
	type cveWithRelationType struct {
		models.CVE
		TargetCVE        string                `gorm:"column:target_cve"`
		RelationshipType dtos.RelationshipType `gorm:"column:relationship_type"`
	}
	results := make([]cveWithRelationType, 0, 64)

	err := g.GetDB(ctx, tx).Raw(`
	SELECT 
		sub.*, cves.* 
	FROM(
		WITH RECURSIVE related_cves
	AS(
		SELECT 
			cr.target_cve, 0 as depth, cr.relationship_type 
		FROM 
			cve_relationships cr 
		WHERE 
			cr.source_cve = ?
		UNION 
		SELECT 
			cr2.target_cve, rc.depth + 1, cr2.relationship_type 
		FROM 
			cve_relationships cr2 
		INNER JOIN 
			related_cves rc ON rc.target_cve = cr2.source_cve
		WHERE 
			rc.depth + 1 < 5
	)
	SELECT 
		DISTINCT target_cve, relationship_type 
	FROM 
		related_cves) as sub 
	LEFT JOIN 
		cves ON cves.cve = sub.target_cve;`, cveID).Find(&results).Error
	if err != nil {
		return nil, err
	}

	// map each cve to its relationship
	relationshipTypeToCVEs := make(map[dtos.RelationshipType][]models.CVE, 5)
	for i := range results {
		relationshipTypeToCVEs[results[i].RelationshipType] = append(relationshipTypeToCVEs[results[i].RelationshipType], results[i].CVE)
	}

	return relationshipTypeToCVEs, err
}
