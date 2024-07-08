package repositories

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
)

type eventRepository struct {
	db core.DB
	Repository[uuid.UUID, models.FlawEvent, core.DB]
}

func NewFlawEventRepository(db core.DB) *eventRepository {
	if err := db.AutoMigrate(&models.FlawEvent{}); err != nil {
		panic(err)
	}
	return &eventRepository{
		db:         db,
		Repository: newGormRepository[uuid.UUID, models.FlawEvent](db),
	}
}
