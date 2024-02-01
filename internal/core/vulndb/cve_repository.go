package vulndb

import (
	"time"

	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/l3montree-dev/flawfix/internal/database"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
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

func (g *GormRepository) SaveBatch(tx core.DB, cves []CVE) error {
	return g.GetDB(tx).Session(
		&gorm.Session{
			FullSaveAssociations: true,
		}).Clauses(
		clause.OnConflict{
			UpdateAll: true,
		},
	).CreateInBatches(&cves, 50).Error
}
