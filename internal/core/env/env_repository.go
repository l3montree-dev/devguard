package env

import (
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/l3montree-dev/flawfix/internal/database"
)

type GormRepository struct {
	db core.DB
	database.Repository[uuid.UUID, Model, core.DB]
}

type Repository interface {
	database.Repository[uuid.UUID, Model, core.DB]
	ReadBySlug(assetID uuid.UUID, slug string) (Model, error)
	UpdateLastReportTime(tx core.DB, envId uuid.UUID) error
}

func NewGormRepository(db core.DB) *GormRepository {
	return &GormRepository{
		db:         db,
		Repository: database.NewGormRepository[uuid.UUID, Model](db),
	}
}

func (g *GormRepository) ReadBySlug(assetID uuid.UUID, slug string) (Model, error) {
	var env Model
	err := g.db.Where("slug = ? AND asset_id = ?", slug, assetID).First(&env).Error
	return env, err
}

func (g *GormRepository) UpdateLastReportTime(tx core.DB, envId uuid.UUID) error {
	err := tx.Model(&Model{}).Where("id = ?", envId).Update("last_report_time", time.Now()).Error
	return err
}
