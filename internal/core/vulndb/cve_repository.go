package vulndb

import (
	"log/slog"
	"time"

	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/l3montree-dev/flawfix/internal/database"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"
)

type Repository interface {
	database.Repository[string, CVE, core.DB]
	FindByID(id string) (CVE, error)
	GetLastModDate() (time.Time, error)
}

type GormRepository struct {
	database.Repository[string, CVE, core.DB]
	db *gorm.DB
}

func NewGormRepository(db core.DB) Repository {
	if err := db.AutoMigrate(&CVE{}, &Weakness{}); err != nil {
		panic(err)
	}

	return &GormRepository{
		db:         db,
		Repository: database.NewGormRepository[string, CVE](db),
	}
}

func (g *GormRepository) GetLastModDate() (time.Time, error) {
	var cve CVE
	err := g.db.Order("date_last_modified desc").First(&cve).Error

	return cve.DateLastModified, err
}

func (g *GormRepository) FindByID(id string) (CVE, error) {
	var t CVE
	err := g.db.First(&t, "cve = ?", id).Error

	return t, err
}

func (g *GormRepository) createInBatches(tx core.DB, cves []CVE, batchSize int) error {
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

func (g *GormRepository) SaveBatch(tx core.DB, cves []CVE) error {
	return g.createInBatches(tx, cves, 1000)
}

func (g *GormRepository) Save(tx core.DB, cve *CVE) error {
	return g.GetDB(tx).Session(
		&gorm.Session{
			FullSaveAssociations: true,
		}).Clauses(
		clause.OnConflict{
			UpdateAll: true,
		},
	).Save(cve).Error
}
