package repositories

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
	"gorm.io/gorm"
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

func (g *projectRepository) ReadBySlug(orgID uuid.UUID, slug string) (models.Project, error) {
	var flatProjects []models.Project
	err := g.db.Raw(`
        WITH RECURSIVE parents AS (
            SELECT *
            FROM projects
            WHERE organization_id = ? AND slug = ? AND deleted_at IS NULL
            UNION ALL
            SELECT p.*
            FROM projects p
            INNER JOIN parents c ON p.id = c.parent_id
        )
        SELECT * FROM parents
    `, orgID, slug).Scan(&flatProjects).Error
	if err != nil {
		return models.Project{}, err
	}

	// if empty slice, return an error
	if len(flatProjects) == 0 {
		return models.Project{}, gorm.ErrRecordNotFound
	}

	// flatProjects is a slice of all matching + ancestor records.
	nested := nestProjects(slug, flatProjects)
	return nested, nil
}

func (g *projectRepository) ReadBySlugUnscoped(orgID uuid.UUID, slug string) (models.Project, error) {
	var project models.Project
	err := g.db.Unscoped().Where("slug = ? AND organization_id = ?", slug, orgID).First(&project).Error
	return project, err
}

// nestProjects transforms a flat list of projects into a single chain
// from child up to the root parent.
func nestProjects(slug string, projects []models.Project) models.Project {
	root, _ := utils.Find(
		projects,
		func(m models.Project) bool { return m.Slug == slug },
	)

	// Index by ID for quick lookup.
	byID := make(map[uuid.UUID]*models.Project)
	for i := range projects {
		// copy pointer
		p := &projects[i]
		byID[p.ID] = p
	}

	current := &root
	// start at the root and set parent until we reach the top.
	for current.ParentID != nil {
		// set the parent
		current.Parent = byID[*current.ParentID]
		// move to the parent
		current = current.Parent
	}

	return root
}

func (g *projectRepository) Update(tx core.DB, project *models.Project) error {
	return g.db.Save(project).Error
}

func (g *projectRepository) List(projectIDs []uuid.UUID, parentId *uuid.UUID, orgID uuid.UUID) ([]models.Project, error) {
	var projects []models.Project
	if parentId != nil {
		err := g.db.Where("id IN ? AND parent_id = ?", projectIDs, parentId).Or("organization_id = ? AND is_public = true AND parent_id = ?", orgID, parentId).Find(&projects).Error
		return projects, err
	}
	err := g.db.Where("id IN ? AND parent_id IS NULL", projectIDs).Or("organization_id = ? AND is_public = true AND parent_id IS NULL", orgID).Find(&projects).Error
	return projects, err
}

func (g *projectRepository) RecursivelyGetChildProjects(projectID uuid.UUID) ([]models.Project, error) {
	var projects []models.Project
	err := g.db.Raw(`
		WITH RECURSIVE children AS (
			SELECT *
			FROM projects
			WHERE parent_id = ? AND deleted_at IS NULL
			UNION ALL
			SELECT p.*
			FROM projects p
			INNER JOIN children c ON p.parent_id = c.id
		)
		SELECT * FROM children
	`, projectID).Scan(&projects).Error
	return projects, err
}

func (g *projectRepository) GetDirectChildProjects(projectID uuid.UUID) ([]models.Project, error) {
	var projects []models.Project
	err := g.db.Where("parent_id = ?", projectID).Find(&projects).Error
	return projects, err
}
