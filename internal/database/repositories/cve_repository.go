package repositories

import (
	"log/slog"
	"os"
	"time"

	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"
)

type cveRepository struct {
	db *gorm.DB
	common.Repository[string, models.CVE, core.DB]
}

func NewCVERepository(db core.DB) *cveRepository {
	if os.Getenv("DISABLE_AUTOMIGRATE") != "true" {
		if err := db.AutoMigrate(&models.CVE{}, &models.Weakness{}); err != nil {
			panic(err)
		}
	}

	return &cveRepository{
		db:         db,
		Repository: newGormRepository[string, models.CVE](db),
	}
}

func (g *cveRepository) GetLastModDate() (time.Time, error) {
	var cve models.CVE
	err := g.db.Order("date_last_modified desc").First(&cve).Error

	return cve.DateLastModified, err
}

func (g *cveRepository) FindByID(id string) (models.CVE, error) {
	var t models.CVE
	err := g.db.First(&t, "cve = ?", id).Error

	return t, err
}

func (g *cveRepository) GetAllCVEsID() ([]string, error) {
	var cvesID []string
	err := g.db.Model(&models.CVE{}).
		Pluck("cve", &cvesID).
		Error
	return cvesID, err
}

func (g *cveRepository) GetAllCPEMatchesID() ([]string, error) {
	var cpeMatchesID []string

	err := g.db.Model(&models.CPEMatch{}).
		Pluck("match_criteria_id", &cpeMatchesID).
		Error

	return cpeMatchesID, err
}

func (g *cveRepository) FindAll(cveIDs []string) ([]models.CVE, error) {
	var cves []models.CVE
	err := g.db.Find(&cves, "cve IN ?", cveIDs).Error
	return cves, err
}

func (g *cveRepository) SaveCveAffectedComponents(tx core.DB, cveId string, affectedComponentHashes []string) error {

	affectedComponents := utils.Map(utils.UniqBy(affectedComponentHashes, func(c string) string {
		return c
	}), func(c string) models.AffectedComponent {
		return models.AffectedComponent{
			ID: c,
		}
	})

	// add cpeCveMatches to the cve
	m := g.GetDB(tx).Session(&gorm.Session{
		// disable logging
		// it might log slow queries or a missing cve.
		Logger:               logger.Default.LogMode(logger.Silent),
		FullSaveAssociations: false,
	}).Model(&models.CVE{
		CVE: cveId,
	})
	assoc := m.Association("AffectedComponents")
	return assoc.Append(&affectedComponents)
}

func (g *cveRepository) createInBatches(tx core.DB, cves []models.CVE, batchSize int) error {
	err := g.GetDB(tx).Session(
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
				if err := g.GetDB(tx).Session(
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
		return g.createInBatches(tx, cves, newBatchSize)
	}
	return err
}

func (g *cveRepository) SaveBatch(tx core.DB, cves []models.CVE) error {
	return g.createInBatches(tx, cves, 1000)
}

func (g *cveRepository) Save(tx core.DB, cve *models.CVE) error {
	return g.GetDB(tx).Clauses(
		clause.OnConflict{
			UpdateAll: true,
		},
	).Save(cve).Error
}

func (g *cveRepository) saveBatchCPEMatch(tx core.DB, matches []models.CPEMatch, batchSize int) error {
	err := g.GetDB(tx).Session(
		&gorm.Session{
			Logger:               logger.Default.LogMode(logger.Silent),
			FullSaveAssociations: true,
		}).Clauses(
		clause.OnConflict{
			UpdateAll: true,
		},
	).CreateInBatches(&matches, batchSize).Error
	// check if we got a protocol error since we are inserting more than 65535 parameters
	if err != nil && err.Error() == "extended protocol limited to 65535 parameters; extended protocol limited to 65535 parameters" {
		newBatchSize := batchSize / 2
		if newBatchSize < 1 {
			// we can't reduce the batch size anymore
			// lets try to save the CVEs one by one
			// this will be slow but it will work
			for _, match := range matches {
				tmpCVE := match
				if err := g.GetDB(tx).Session(
					&gorm.Session{
						Logger:               logger.Default.LogMode(logger.Silent),
						FullSaveAssociations: true,
					}).Clauses(
					clause.OnConflict{
						UpdateAll: true,
					},
				).Create(&tmpCVE).Error; err != nil {
					// log, that we werent able to save the CVE
					slog.Error("unable to save cpe", "cpe", match.Criteria, "err", err)
				}
			}
			return nil
		}
		slog.Warn("protocol error, trying to reduce batch size", "newBatchSize", newBatchSize, "oldBatchSize", batchSize, "err", err)
		return g.saveBatchCPEMatch(tx, matches, newBatchSize)
	}
	return err
}

func (g *cveRepository) SaveBatchCPEMatch(tx core.DB, matches []models.CPEMatch) error {
	return g.saveBatchCPEMatch(tx, matches, 1000)
}

func (g *cveRepository) FindAllListPaged(tx core.DB, pageInfo core.PageInfo, filter []core.FilterQuery, sort []core.SortQuery) (core.Paged[models.CVE], error) {
	var count int64
	var cves []models.CVE = []models.CVE{}

	q := g.GetDB(tx).Model(&models.CVE{})

	// apply filters
	for _, f := range filter {
		q = q.Where(f.SQL(), f.Value())
	}
	q = q.Where("cvss > 0")
	q.Count(&count)

	// get all cves
	q = pageInfo.ApplyOnDB(g.GetDB(tx))

	// apply filters
	for _, f := range filter {
		q = q.Where(f.SQL(), f.Value())
	}
	q = q.Where("cvss > 0")

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
		return core.Paged[models.CVE]{}, err
	}

	return core.NewPaged(pageInfo, count, cves), nil
}

func (g *cveRepository) FindCVE(tx core.DB, cveId string) (models.CVE, error) {

	var cves models.CVE

	q := g.GetDB(tx).Model(&models.CVE{})

	q = q.Where("cve = ?", cveId)

	err := q.Preload("AffectedComponents").Preload("Exploits").First(&cves).Error
	if err != nil {
		return models.CVE{}, err
	}

	return cves, nil
}

// this method is used inside the risk_daemon to get all cves.
// we need this to run FAST. Do not add any preloading here (except exploits). We do not need it in the risk_daemon.
// create your own method if you need preloading.
func (g *cveRepository) FindCVEs(tx core.DB, cveIds []string) ([]models.CVE, error) {
	var cves []models.CVE

	err := g.GetDB(tx).Where("cve IN ?", cveIds).Preload("Exploits").Find(&cves).Error
	return cves, err
}
