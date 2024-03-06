package flaw

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/l3montree-dev/flawfix/internal/database"
)

type eventGormRepository struct {
	db core.DB
	database.Repository[uuid.UUID, EventModel, core.DB]
}

type eventRepository interface {
	database.Repository[uuid.UUID, EventModel, core.DB]
}

func NewEventGormRepository(db core.DB) *eventGormRepository {
	return &eventGormRepository{
		db:         db,
		Repository: database.NewGormRepository[uuid.UUID, EventModel](db),
	}
}
