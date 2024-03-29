package repositories

import (
	"log/slog"
	"time"

	"github.com/l3montree-dev/flawfix/internal/database"
	"github.com/l3montree-dev/flawfix/internal/database/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"
)

type cveRepository struct {
	Repository[string, models.CVE, database.DB]
	db *gorm.DB
}

func NewCVERepository(db database.DB) *cveRepository {
	if err := db.AutoMigrate(&models.CVE{}, &models.Weakness{}); err != nil {
		panic(err)
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

func (g *cveRepository) FindAll(cveIDs []string) ([]models.CVE, error) {
	var cves []models.CVE
	err := g.db.Find(&cves, "cve IN ?", cveIDs).Error
	return cves, err
}

func (g *cveRepository) createInBatches(tx database.DB, cves []models.CVE, batchSize int) error {
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

func (g *cveRepository) SaveBatch(tx database.DB, cves []models.CVE) error {
	return g.createInBatches(tx, cves, 1000)
}

func (g *cveRepository) Save(tx database.DB, cve *models.CVE) error {
	return g.GetDB(tx).Session(
		&gorm.Session{
			FullSaveAssociations: true,
		}).Clauses(
		clause.OnConflict{
			UpdateAll: true,
		},
	).Save(cve).Error
}
