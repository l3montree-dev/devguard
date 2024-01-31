package config

import (
	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/l3montree-dev/flawfix/internal/database"
)

type gormRepository struct {
	database.Repository[string, Config, core.DB]
	db core.DB
}

func NewGormRepository(db core.DB) database.Repository[string, Config, core.DB] {
	if err := db.AutoMigrate(&Config{}); err != nil {
		panic(err)
	}
	return &gormRepository{
		db:         db,
		Repository: database.NewGormRepository[string, Config](db),
	}
}
