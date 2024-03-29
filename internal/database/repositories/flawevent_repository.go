package repositories

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/l3montree-dev/flawfix/internal/database/models"
)

type eventGormRepository struct {
	db core.DB
	Repository[uuid.UUID, models.FlawEvent, core.DB]
}

type eventRepository interface {
	Repository[uuid.UUID, models.FlawEvent, core.DB]
}

func NewEventGormRepository(db core.DB) *eventGormRepository {
	return &eventGormRepository{
		db:         db,
		Repository: newGormRepository[uuid.UUID, models.FlawEvent](db),
	}
}
