package flaw

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/l3montree-dev/flawfix/internal/database"
	"gorm.io/gorm"
)

type GormRepository struct {
	db core.DB
	database.Repository[uuid.UUID, Model, core.DB]
}

type Repository interface {
	database.Repository[uuid.UUID, Model, core.DB]

	GetByEnvId(tx core.DB, envId uuid.UUID) ([]Model, error)
	GetByEnvIdPaged(tx core.DB, pageInfo core.PageInfo, envId uuid.UUID) (core.Paged[Model], error)
}

func NewGormRepository(db core.DB) Repository {
	return &GormRepository{
		db:         db,
		Repository: database.NewGormRepository[uuid.UUID, Model](db),
	}
}

func (r *GormRepository) GetByEnvId(
	tx *gorm.DB,
	envId uuid.UUID,
) ([]Model, error) {

	var flaws []Model = []Model{}
	// get all flaws of the environment
	if err := r.Repository.GetDB(tx).Where("env_id = ?", envId).Find(&flaws).Error; err != nil {
		return nil, err
	}
	return flaws, nil
}

func (r *GormRepository) GetByEnvIdPaged(tx core.DB, pageInfo core.PageInfo, envId uuid.UUID) (core.Paged[Model], error) {
	var count int64
	var flaws []Model = []Model{}

	// get all flaws of the environment
	if err := pageInfo.ApplyOnDB(r.Repository.GetDB(tx)).Preload("CVE").Where("env_id = ?", envId).Find(&flaws).Error; err != nil {
		return core.Paged[Model]{}, err
	}

	return core.NewPaged(pageInfo, count, flaws), nil
}
