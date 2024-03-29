package repositories

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/l3montree-dev/flawfix/internal/database/models"
)

type projectRepository struct {
	db core.DB
	Repository[uuid.UUID, models.Project, core.DB]
}

func NewProjectRepository(db core.DB) *projectRepository {
	if err := db.AutoMigrate(&models.Project{}); err != nil {
		panic(err)
	}
	return &projectRepository{
		db:         db,
		Repository: newGormRepository[uuid.UUID, models.Project](db),
	}
}

func (g *projectRepository) ReadBySlug(organizationID uuid.UUID, slug string) (models.Project, error) {
	var t models.Project
	err := g.db.Where("slug = ? AND organization_id = ?", slug, organizationID).First(&t).Error
	return t, err
}
