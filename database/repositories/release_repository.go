package repositories

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"gorm.io/gorm"
)

type releaseRepository struct {
	utils.Repository[uuid.UUID, models.Release, *gorm.DB]
	db *gorm.DB
}

func NewReleaseRepository(db *gorm.DB) *releaseRepository {
	return &releaseRepository{
		db:         db,
		Repository: newGormRepository[uuid.UUID, models.Release](db),
	}
}

func (r *releaseRepository) GetByProjectID(ctx context.Context, tx *gorm.DB, projectID uuid.UUID) ([]models.Release, error) {
	var rels []models.Release
	err := r.GetDB(ctx, tx).Where("project_id = ?", projectID).Find(&rels).Error
	if err != nil {
		return nil, err
	}

	return rels, nil
}

// ReadWithItems reads a release and preloads its direct items and related artifact/child pointers.
func (r *releaseRepository) ReadWithItems(ctx context.Context, tx *gorm.DB, id uuid.UUID) (models.Release, error) {
	var rel models.Release
	db := withOwnershipScope(ctx, r.GetDB(ctx, tx).Where("id = ?", id), rel)
	err := db.Preload("Items").Preload("Items.Artifact").Preload("Items.ChildRelease").First(&rel).Error
	return rel, err
}

// ReadRecursive loads the given release and all nested child releases using a recursive CTE on the DB
// and assembles the tree in memory.
func (r *releaseRepository) ReadRecursive(ctx context.Context, tx *gorm.DB, id uuid.UUID) (models.Release, error) {
	// Scope the CTE anchor to the caller's project when tenant IDs are present,
	// preventing cross-project traversal (BOLA via child-release UUID pivot).
	var cteRows *sql.Rows
	var err error
	if ids, ok := shared.OwnershipScopeFromCtx(ctx); ok {
		cteRows, err = r.GetDB(ctx, tx).Raw(`WITH RECURSIVE tree AS (
			SELECT id FROM releases WHERE id = ? AND project_id = ?
			UNION ALL
			SELECT ri.child_release_id FROM release_items ri JOIN tree t ON ri.release_id = t.id WHERE ri.child_release_id IS NOT NULL
		) SELECT id FROM tree`, id, ids.ProjectID).Rows()
	} else {
		cteRows, err = r.GetDB(ctx, tx).Raw(`WITH RECURSIVE tree AS (
			SELECT id FROM releases WHERE id = ?
			UNION ALL
			SELECT ri.child_release_id FROM release_items ri JOIN tree t ON ri.release_id = t.id WHERE ri.child_release_id IS NOT NULL
		) SELECT id FROM tree`, id).Rows()
	}
	if err != nil {
		return models.Release{}, err
	}
	defer cteRows.Close()

	var releaseIDs []uuid.UUID
	for cteRows.Next() {
		var rid uuid.UUID
		if err := cteRows.Scan(&rid); err != nil {
			return models.Release{}, err
		}
		releaseIDs = append(releaseIDs, rid)
	}

	if len(releaseIDs) == 0 {
		var rel models.Release
		db := withOwnershipScope(ctx, r.GetDB(ctx, tx).Where("id = ?", id), rel)
		return rel, db.First(&rel).Error
	}

	// fetch all releases (preload Project so Project.Avatar is available)
	var releases []models.Release
	if err := r.GetDB(ctx, tx).Where("id IN ?", releaseIDs).Find(&releases).Error; err != nil {
		return models.Release{}, err
	}

	// fetch all items belonging to these releases
	var items []models.ReleaseItem
	if err := r.GetDB(ctx, tx).Where("release_id IN ?", releaseIDs).Find(&items).Error; err != nil {
		return models.Release{}, err
	}

	// assemble releases by id
	relMap := map[uuid.UUID]*models.Release{}
	for i := range releases {
		rel := releases[i]
		rel.Items = []models.ReleaseItem{}
		relMap[rel.ID] = &rel
	}

	// attach items to their parent release and resolve child pointers from relMap
	for _, it := range items {
		parent, ok := relMap[it.ReleaseID]
		if !ok {
			continue
		}
		item := it
		if item.ChildReleaseID != nil {
			if child, ok := relMap[*item.ChildReleaseID]; ok {
				item.ChildRelease = child
			}
		}
		parent.Items = append(parent.Items, item)
	}

	root, ok := relMap[id]
	if !ok {
		var rel models.Release
		db := withOwnershipScope(ctx, r.GetDB(ctx, tx).Where("id = ?", id), rel)
		return rel, db.First(&rel).Error
	}

	return *root, nil
}

// CreateReleaseItem inserts a new ReleaseItem row.
func (r *releaseRepository) CreateReleaseItem(ctx context.Context, tx *gorm.DB, item *models.ReleaseItem) error {
	db := r.GetDB(ctx, tx)
	if tx != nil {
		db = tx
	}
	return db.Create(item).Error
}

// DeleteReleaseItem deletes a release item by id.
func (r *releaseRepository) DeleteReleaseItem(ctx context.Context, tx *gorm.DB, id uuid.UUID) error {
	db := r.GetDB(ctx, tx)
	if tx != nil {
		db = tx
	}
	db = db.Where("id = ?", id)
	// ReleaseItem has no project_id/organization_id column of its own, so scope through
	// the parent release's project instead - prevents deleting another tenant's item by UUID.
	if ids, ok := shared.OwnershipScopeFromCtx(ctx); ok {
		db = db.Where("release_id IN (SELECT id FROM releases WHERE project_id = ?)", ids.ProjectID)
	}
	res := db.Delete(&models.ReleaseItem{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

// GetByProjectIDPaged returns a paged list of releases for a project with optional search, filter and sort
func (r *releaseRepository) GetByProjectIDPaged(ctx context.Context, tx *gorm.DB, projectID uuid.UUID, pageInfo shared.PageInfo, search string, filter []shared.FilterQuery, sort []shared.SortQuery) (shared.Paged[models.Release], error) {
	db := r.GetDB(ctx, tx)
	if tx != nil {
		db = tx
	}

	// preload Project so DTO mapping can read Project.Avatar
	q := db.Model(&models.Release{}).Preload("Items").Preload("Items.ChildRelease").Where("project_id = ?", projectID)

	// apply search
	if search != "" {
		q = q.Where("id::text ILIKE ? OR CAST(project_id AS text) ILIKE ?", "%"+search+"%", "%"+search+"%")
	}

	// apply filter queries
	for _, f := range filter {
		q = q.Where(f.SQL(), f.Value())
	}

	// apply sort
	if len(sort) > 0 {
		for _, s := range sort {
			q = q.Order(s.SQL())
		}
	} else {
		q = q.Order("created_at desc")
	}

	type rowWithCount struct {
		models.Release
		TotalCount int64
	}
	var rows []rowWithCount

	// use a new gorm session to force a new statement for both queries
	if err := q.Session(&gorm.Session{}).Select("*, COUNT(*) OVER() AS total_count").
		Limit(pageInfo.PageSize).Offset((pageInfo.Page - 1) * pageInfo.PageSize).
		Find(&rows).Error; err != nil { // find must be used here so that the preloads of the release model work correctly
		return shared.Paged[models.Release]{}, err
	}

	var count int64
	releases := make([]models.Release, len(rows))
	for i, r := range rows {
		releases[i] = r.Release
		count = r.TotalCount
	}
	// the window count rides on each row, so an out-of-range (empty) page carries no count.
	if len(rows) == 0 {
		if err := q.Session(&gorm.Session{}).Count(&count).Error; err != nil {
			return shared.Paged[models.Release]{}, err
		}
	}

	return shared.NewPaged(pageInfo, count, releases), nil
}

func (r *releaseRepository) GetCandidateItemsForRelease(ctx context.Context, tx *gorm.DB, projectID uuid.UUID, releaseID *uuid.UUID) ([]models.Artifact, []models.Release, error) {
	// gather artifacts for default asset versions of the project and its child projects in a single joined query
	// first collect project ids (project + children) using a recursive CTE
	rows, err := r.GetDB(ctx, tx).Raw(`WITH RECURSIVE proj_tree AS (
		SELECT id FROM projects WHERE id = ?
		UNION ALL
		SELECT p.id FROM projects p JOIN proj_tree pt ON p.parent_id = pt.id
	) SELECT id FROM proj_tree`, projectID).Rows()
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	var projectIDs []uuid.UUID
	for rows.Next() {
		var pid uuid.UUID
		if err := rows.Scan(&pid); err != nil {
			return nil, nil, err
		}
		projectIDs = append(projectIDs, pid)
	}

	if len(projectIDs) == 0 {
		projectIDs = []uuid.UUID{projectID}
	}

	// preload AssetVersion.Asset so callers can access the asset name without additional queries
	var artifacts []models.Artifact
	if err := r.GetDB(ctx, tx).
		Model(&models.Artifact{}).
		Joins("JOIN asset_versions av ON av.asset_id = artifacts.asset_id AND av.name = artifacts.asset_version_name").
		Joins("JOIN assets ON assets.id = artifacts.asset_id").
		Joins("JOIN projects ON projects.id = assets.project_id").
		Where("projects.id IN ?", projectIDs).
		Find(&artifacts).Error; err != nil {
		return nil, nil, err
	}

	excluded := map[uuid.UUID]struct{}{}

	if releaseID != nil {
		rows, err := r.GetDB(ctx, tx).Raw(`WITH RECURSIVE tree AS (
		SELECT id FROM releases WHERE id = ?
		UNION ALL
		SELECT ri.child_release_id FROM release_items ri JOIN tree t ON ri.release_id = t.id WHERE ri.child_release_id IS NOT NULL
	) SELECT id FROM tree`, releaseID).Rows()
		if err != nil {
			return artifacts, nil, err
		}
		defer rows.Close()

		for rows.Next() {
			var rid uuid.UUID
			if err := rows.Scan(&rid); err != nil {
				return artifacts, nil, err
			}
			excluded[rid] = struct{}{}
		}
	}

	var rels []models.Release
	// convert excluded map to slice for SQL query
	var excludedIDs []uuid.UUID
	if len(excluded) > 0 {
		excludedIDs = make([]uuid.UUID, 0, len(excluded))
		for id := range excluded {
			excludedIDs = append(excludedIDs, id)
		}
	}

	q := r.GetDB(ctx, tx).Where("project_id IN ?", projectIDs)
	if len(excludedIDs) > 0 {
		q = q.Where("id NOT IN ?", excludedIDs)
	}
	if err := q.Find(&rels).Error; err != nil {
		return artifacts, nil, err
	}

	return artifacts, rels, nil
}

func (r *releaseRepository) FindOrCreate(ctx context.Context, tx *gorm.DB, projectID uuid.UUID, name string) (models.Release, error) {
	var rel models.Release
	err := r.GetDB(ctx, tx).Where("project_id = ? AND name = ?", projectID, name).First(&rel).Error
	if err == nil {
		return rel, nil
	}
	if err != nil && err != gorm.ErrRecordNotFound {
		return models.Release{}, err
	}

	rel = models.Release{
		Name:      name,
		ProjectID: projectID,
	}

	err = r.GetDB(ctx, tx).Create(&rel).Error
	return rel, err
}
