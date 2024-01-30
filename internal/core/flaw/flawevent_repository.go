package flaw

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/l3montree-dev/flawfix/internal/database"
)

type EventGormRepository struct {
	db core.DB
	database.Repository[uuid.UUID, EventModel, core.DB]
}

type EventRepository interface {
	database.Repository[uuid.UUID, EventModel, core.DB]
}

func NewEventGormRepository(db core.DB) EventRepository {
	return &EventGormRepository{
		db:         db,
		Repository: database.NewGormRepository[uuid.UUID, EventModel](db),
	}
}
