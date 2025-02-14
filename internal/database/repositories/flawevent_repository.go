package repositories

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
)

type eventRepository struct {
	db core.DB
	Repository[uuid.UUID, models.DependencyVulnEvent, core.DB]
}

func NewDependencyVulnEventRepository(db core.DB) *eventRepository {
	if err := db.AutoMigrate(&models.DependencyVulnEvent{}); err != nil {
		panic(err)
	}
	return &eventRepository{
		db:         db,
		Repository: newGormRepository[uuid.UUID, models.DependencyVulnEvent](db),
	}
}
