package flaw

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/l3montree-dev/flawfix/internal/core/flawevent"
	"github.com/l3montree-dev/flawfix/internal/database"
	"gorm.io/gorm"
)

type GormRepository struct {
	db core.DB
	database.Repository[uuid.UUID, Model, core.DB]
}

type Repository interface {
	database.Repository[uuid.UUID, Model, core.DB]
	GetWithLastEvent(tx core.DB, envId uuid.UUID) ([]ModelWithLastEvent, error)
	GetWithLastEventPaged(tx core.DB, pageInfo core.PageInfo, envId uuid.UUID) (core.Paged[ModelWithLastEvent], error)
}

func NewGormRepository(db core.DB) Repository {
	return &GormRepository{
		db:         db,
		Repository: database.NewGormRepository[uuid.UUID, Model](db),
	}
}

func (r *GormRepository) GetLastEvents(flaws []Model) ([]ModelWithLastEvent, error) {
	var events []flawevent.Model = []flawevent.Model{}
	var flawsWithLastEvent []ModelWithLastEvent = []ModelWithLastEvent{}

	ids := []uuid.UUID{}
	for _, flaw := range flaws {
		ids = append(ids, flaw.ID)
	}

	// get last event of each flaw
	err := r.db.Raw(
		"SELECT DISTINCT ON(flaw_events.flaw_id) flaw_events.* FROM flaw_events WHERE flaw_id IN (?) ORDER BY flaw_events.flaw_id, flaw_events.created_at DESC", ids,
	).Find(&events).Error

	if err != nil {
		return nil, err
	}

	// map flaw with last event
	for _, flaw := range flaws {
		for _, event := range events {
			if flaw.ID == event.FlawID {
				flawsWithLastEvent = append(flawsWithLastEvent, ModelWithLastEvent{
					Model:     flaw,
					LastEvent: event,
				})
			}
		}
	}

	return flawsWithLastEvent, nil
}

func (r *GormRepository) GetWithLastEvent(
	tx *gorm.DB,
	envId uuid.UUID,
) ([]ModelWithLastEvent, error) {

	var flaws []Model = []Model{}
	// get all flaws of the environment
	if err := r.Repository.GetDB(tx).Where("env_id = ?", envId).Find(&flaws).Error; err != nil {
		return nil, err
	}

	res, err := r.GetLastEvents(flaws)

	if err != nil {
		return nil, err
	}

	return res, nil
}

func (r *GormRepository) GetWithLastEventPaged(tx core.DB, pageInfo core.PageInfo, envId uuid.UUID) (core.Paged[ModelWithLastEvent], error) {
	var count int64
	var flaws []Model = []Model{}
	// get all flaws of the environment
	if err := pageInfo.ApplyOnDB(r.Repository.GetDB(tx)).Where("env_id = ?", envId).Find(&flaws).Count(&count).Error; err != nil {
		return core.Paged[ModelWithLastEvent]{}, err
	}

	res, err := r.GetLastEvents(flaws)

	if err != nil {
		return core.Paged[ModelWithLastEvent]{}, err
	}

	return core.NewPaged(pageInfo, count, res), nil
}
