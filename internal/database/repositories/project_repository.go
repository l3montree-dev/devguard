package repositories

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
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

func (g *projectRepository) GetByOrgID(organizationID uuid.UUID) ([]models.Project, error) {
	var projects []models.Project
	err := g.db.Where("organization_id = ?", organizationID).Find(&projects).Error
	return projects, err
}

func (g *projectRepository) GetProjectByAssetID(assetID uuid.UUID) (models.Project, error) {
	var project models.Project
	err := g.db.Model(&models.Asset{}).Select("projects.*").Joins("JOIN projects ON projects.id = assets.project_id").Where("assets.id = ?", assetID).First(&project).Error
	return project, err
}

func (g *projectRepository) GetProjectIdByAssetID(assetID uuid.UUID) (uuid.UUID, error) {
	var projectID uuid.UUID
	err := g.db.Model(&models.Asset{}).Select("project_id").Where("id = ?", assetID).Row().Scan(&projectID)
	return projectID, err
}
func (g *projectRepository) ReadBySlug(organizationID uuid.UUID, slug string) (models.Project, error) {
	var t models.Project
	err := g.db.Where("slug = ? AND organization_id = ?", slug, organizationID).First(&t).Error
	return t, err
}
func (g *projectRepository) Update(tx core.DB, project *models.Project) error {
	return g.db.Save(project).Error
}

func (g *projectRepository) List(projectIDs []uuid.UUID, orgID uuid.UUID) ([]models.Project, error) {
	var projects []models.Project
	err := g.db.Where("id IN ?", projectIDs).Or("organization_id = ? AND is_public = true", orgID).Find(&projects).Error
	return projects, err
}
