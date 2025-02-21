package repositories

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
)

type eventRepository struct {
	db core.DB
	Repository[uuid.UUID, models.VulnEvent, core.DB]
}

func NewVulnEventRepository(db core.DB) *eventRepository {
	if err := db.AutoMigrate(&models.VulnEvent{}); err != nil {
		panic(err)
	}
	return &eventRepository{
		db:         db,
		Repository: newGormRepository[uuid.UUID, models.VulnEvent](db),
	}
}
