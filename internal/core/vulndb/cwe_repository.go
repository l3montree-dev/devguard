package vulndb

import (
	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/l3montree-dev/flawfix/internal/database"
)

type gormCWERepository struct {
	database.Repository[string, CWE, core.DB]
}

func newGormCWERepository(db core.DB) *gormCWERepository {
	if err := db.AutoMigrate(&CWE{}); err != nil {
		panic(err)
	}
	return &gormCWERepository{
		Repository: database.NewGormRepository[string, CWE](db),
	}
}
