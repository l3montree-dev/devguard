package repositories

import (
	"fmt"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/lib/pq"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type projectRepository struct {
	db *gorm.DB
	utils.Repository[uuid.UUID, models.Project, *gorm.DB]
}

func NewProjectRepository(db *gorm.DB) *projectRepository {
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

func (g *projectRepository) GetProjectByAssetVersionID(assetVersionName string, assetID uuid.UUID) (models.Project, error) {
	var project models.Project
	err := g.db.Model(&models.AssetVersion{}).Select("assets.*").Joins("JOIN assets ON assets.id = asset_versions.asset_id").Joins("JOIN projects ON projects.id = assets.project_id").Where("asset_versions.name = ? AND asset_versions.asset_id = ?", assetVersionName, assetID).First(&project).Error
	return project, err
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
            WHERE organization_id = ? AND slug = ? 
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

func (g *projectRepository) Update(tx *gorm.DB, project *models.Project) error {
	return g.db.Save(project).Error
}

func (g *projectRepository) ListSubProjectsAndAssets(
	allowedAssetIDs []string,
	allowedProjectIDs []uuid.UUID,
	parentID *uuid.UUID,
	orgID uuid.UUID,
	pageInfo shared.PageInfo,
	search string,
	filter []shared.FilterQuery,
	sort []shared.SortQuery,
) (shared.Paged[dtos.ProjectAssetDTO], error) {

	var results []dtos.ProjectAssetDTO
	var q *gorm.DB

	assetQuery := g.db.Model(&models.Asset{}).
		Select("'asset' AS type, id, name, description, project_id, NULL::uuid AS parent_id, NULL::uuid AS organization_id, is_public, state, created_at, updated_at").
		Where("project_id = ?", parentID).
		Where("id IN ? OR is_public = true", allowedAssetIDs)

	projectQuery := g.db.Model(&models.Project{}).
		Select("'project' AS type, id, name, description, NULL::uuid AS project_id, parent_id, organization_id, is_public, state, created_at, updated_at").
		Where("parent_id = ?", parentID).
		Where("id IN ? OR (organization_id = ? AND is_public = true)", allowedProjectIDs, orgID)

	q = g.db.Table("(?) AS combined", g.db.Raw("? UNION ALL ?", assetQuery, projectQuery))

	// apply search
	if search != "" {
		q = q.Where("name ILIKE ?", "%"+search+"%")
	}

	// apply filters
	for _, f := range filter {
		q = q.Where(f.SQL(), f.Value())
	}

	// Sorting
	for _, s := range sort {
		q = q.Order(s.SQL())
	}

	// Count
	var count int64
	if err := q.Count(&count).Error; err != nil {
		return shared.Paged[dtos.ProjectAssetDTO]{}, err
	}

	// Pagination
	err := q.
		Limit(pageInfo.PageSize).
		Offset((pageInfo.Page - 1) * pageInfo.PageSize).Debug().
		Scan(&results).Error

	if err != nil {
		return shared.Paged[dtos.ProjectAssetDTO]{}, err
	}

	return shared.NewPaged(pageInfo, count, results), nil
}

func (g *projectRepository) ListPaged(projectIDs []uuid.UUID, parentID *uuid.UUID, orgID uuid.UUID, pageInfo shared.PageInfo, search string, filter []shared.FilterQuery, sort []shared.SortQuery) (shared.Paged[models.Project], error) {
	var projects []models.Project

	var q *gorm.DB
	if parentID != nil {
		q = g.db.Model(&models.Project{}).Where(
			g.db.Where("id IN ? AND parent_id = ?", projectIDs, parentID).
				Or("organization_id = ? AND is_public = true AND parent_id = ?", orgID, parentID),
		)
	} else {
		q = g.db.Model(&models.Project{}).Where(
			g.db.Where("id IN ? AND parent_id IS NULL", projectIDs).
				Or("organization_id = ? AND is_public = true AND parent_id IS NULL", orgID),
		)
	}

	// apply search
	if search != "" {
		q = q.Where("name LIKE ?", "%"+search+"%")
	}

	// apply filters
	for _, f := range filter {
		q = q.Where(f.SQL(), f.Value())
	}

	// apply sorting
	if len(sort) > 0 {
		for _, s := range sort {
			q = q.Order(s.SQL())
		}
	}

	var count int64
	err := q.Count(&count).Error
	if err != nil {
		return shared.Paged[models.Project]{}, err
	}
	err = q.Limit(pageInfo.PageSize).Offset((pageInfo.Page - 1) * pageInfo.PageSize).Find(&projects).Error
	if err != nil {
		return shared.Paged[models.Project]{}, err
	}
	return shared.NewPaged(pageInfo, count, projects), nil
}

func (g *projectRepository) List(projectIDs []uuid.UUID, parentID *uuid.UUID, orgID uuid.UUID) ([]models.Project, error) {
	var projects []models.Project
	if parentID != nil {
		err := g.db.Where("id IN ? AND parent_id = ?", projectIDs, parentID).Or("organization_id = ? AND is_public = true AND parent_id = ?", orgID, parentID).Find(&projects).Error
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
			WHERE parent_id = ? 
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

func (g *projectRepository) EnablePolicyForProject(tx *gorm.DB, projectID uuid.UUID, policyID uuid.UUID) error {
	return g.db.Model(&models.Project{
		Model: models.Model{
			ID: projectID,
		},
	}).Association("EnabledPolicies").Append(&models.Policy{ID: policyID})
}
func (g *projectRepository) DisablePolicyForProject(tx *gorm.DB, projectID uuid.UUID, policyID uuid.UUID) error {
	return g.db.Model(&models.Project{
		Model: models.Model{
			ID: projectID,
		},
	}).Association("EnabledPolicies").Delete(&models.Policy{ID: policyID})
}

func (g *projectRepository) EnableCommunityManagedPolicies(tx *gorm.DB, projectID uuid.UUID) error {
	// community policies can be identified by their "organization_id" being nil
	return g.GetDB(tx).Exec(`
		INSERT INTO project_enabled_policies (project_id, policy_id)
		SELECT ?, id
		FROM policies
		WHERE organization_id IS NULL
	`, projectID).Error
}

func (g *projectRepository) Create(tx *gorm.DB, project *models.Project) error {
	// set the slug if not set
	slug, err := g.firstFreeSlug(project.OrganizationID, project.Slug)
	if err != nil {
		return err
	}
	project.Slug = slug

	return g.GetDB(tx).Create(project).Error
}

func (g *projectRepository) UpsertSplit(tx *gorm.DB, externalProviderID string, projects []*models.Project) ([]*models.Project, []*models.Project, error) {
	// check which projects are already in the database - they can be identified by their external_entity_id and external_entity_provider_id
	var existingProjects []models.Project
	err := g.db.Where("external_entity_id IN (?) AND external_entity_provider_id = ?", utils.Map(projects, func(p *models.Project) *string { return p.ExternalEntityID }), externalProviderID).Find(&existingProjects).Error
	if err != nil {
		return nil, nil, err
	}

	existingMap := make(map[string]bool)
	for _, p := range existingProjects {
		existingMap[*p.ExternalEntityID] = true
	}

	err = g.Upsert(&projects, []clause.Column{
		{Name: "external_entity_provider_id"},
		{Name: "external_entity_id"},
	}, []string{"name", "description", "organization_id", "external_entity_parent_id", "avatar"})
	if err != nil {
		return nil, nil, err
	}
	// return the splitted results
	newProjects := make([]*models.Project, 0)
	updatedProjects := make([]*models.Project, 0)
	for _, p := range projects {
		if !existingMap[*p.ExternalEntityID] {
			newProjects = append(newProjects, p)
		} else {
			updatedProjects = append(updatedProjects, p)
		}
	}

	// make sure to set the correct parent ids for the projects. Maybe there is an externalEntityProviderParentID set
	err = g.GetDB(tx).Exec(`
	UPDATE projects p
	SET parent_id = parent.id
	FROM projects parent
	WHERE p.external_entity_parent_id = parent.external_entity_id
  	AND p.id != parent.id;`).Error

	if err != nil {
		return nil, nil, fmt.Errorf("failed to set parent ids: %w", err)
	}
	// return the new and updated projects
	return newProjects, updatedProjects, nil
}

func (g *projectRepository) firstFreeSlug(orgID uuid.UUID, projectSlug string) (string, error) {
	var slugs []string
	err := g.db.Model(&models.Project{}).
		Where("organization_id = ? AND slug LIKE ?", orgID, projectSlug+"%").
		Pluck("slug", &slugs).Error
	if err != nil {
		return "", err
	}

	baseTaken := false
	existing := make(map[string]bool)
	for _, s := range slugs {
		existing[s] = true
		if s == projectSlug {
			baseTaken = true
		}
	}

	if !baseTaken {
		return projectSlug, nil
	}

	for i := 1; ; i++ {
		candidate := fmt.Sprintf("%s-%d", projectSlug, i)
		if !existing[candidate] {
			return candidate, nil
		}
	}
}

func (g *projectRepository) prepareUniqueSlugs(orgID uuid.UUID, projects []*models.Project) error {
	if len(projects) == 0 {
		return nil
	}

	// Collect slug base patterns for LIKE search
	patterns := make([]string, 0, len(projects))

	for _, p := range projects {
		patterns = append(patterns, p.Slug+"%")
	}

	// Fetch existing slugs safely using ANY()
	var existing []*models.Project
	err := g.db.Model(&models.Project{}).
		Where("organization_id = ? AND slug LIKE ANY(?)", orgID, pq.Array(patterns)).Find(&existing).Error
	if err != nil {
		return err
	}

	// Inject unique slugs into the projects
	if err := injectUniqueSlugs(existing, projects); err != nil {
		return fmt.Errorf("failed to inject unique slugs: %w", err)
	}
	return nil
}

func (g *projectRepository) Upsert(t *[]*models.Project, conflictingColumns []clause.Column, updateOnly []string) error {
	if len(*t) == 0 {
		return nil
	}

	err := g.prepareUniqueSlugs((*t)[0].OrganizationID, *t)
	if err != nil {
		return fmt.Errorf("failed to prepare unique slugs: %w", err)
	}

	if len(conflictingColumns) == 0 {
		if len(updateOnly) > 0 {
			return g.db.Clauses(clause.OnConflict{DoUpdates: clause.AssignmentColumns(updateOnly)}).Create(t).Error
		}
		return g.db.Clauses(clause.OnConflict{UpdateAll: true}).Create(t).Error
	}

	if len(updateOnly) > 0 {
		return g.db.Clauses(clause.OnConflict{
			DoUpdates: clause.AssignmentColumns(updateOnly),
			Columns:   conflictingColumns,
		}).Create(t).Error
	}

	return g.db.Clauses(clause.OnConflict{UpdateAll: true, Columns: conflictingColumns}).Create(t).Error
}
