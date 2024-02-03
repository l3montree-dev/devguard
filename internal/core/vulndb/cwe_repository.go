package vulndb

import (
	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/l3montree-dev/flawfix/internal/database"
)

type CWERepository interface {
	database.Repository[string, CWE, core.DB]
}

type GormCWERepository struct {
	database.Repository[string, CWE, core.DB]
}

func NewGormCWERepository(db core.DB) CWERepository {
	if err := db.AutoMigrate(&CWE{}); err != nil {
		panic(err)
	}
	return &GormCWERepository{
		Repository: database.NewGormRepository[string, CWE](db),
	}
}
