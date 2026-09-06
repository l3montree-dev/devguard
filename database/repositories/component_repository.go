// Copyright (C) 2024 Tim Bastin, l3montree GmbH
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package repositories

import (
	"context"
	"log/slog"
	"strings"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/lib/pq"
	"gorm.io/gorm"
)

type componentRepository struct {
	utils.Repository[string, models.Component, *gorm.DB]
	db *gorm.DB
}

var _ shared.ComponentRepository = (*componentRepository)(nil)

func NewComponentRepository(db *gorm.DB) *componentRepository {
	return &componentRepository{
		Repository: newGormRepository[string, models.Component](db),
		db:         db,
	}
}

func (c *componentRepository) FindAllWithoutLicense(ctx context.Context, tx *gorm.DB) ([]models.Component, error) {
	var components []models.Component
	err := c.GetDB(ctx, tx).Where("license IS NULL OR license = ''").Find(&components).Error
	return components, err
}

func (c *componentRepository) LoadComponentsWithProject(ctx context.Context, tx *gorm.DB, overwrittenLicenses []models.LicenseRisk, assetVersionName string, assetID uuid.UUID, pageInfo shared.PageInfo, search string, filter []shared.FilterQuery, sort []shared.SortQuery) (shared.Paged[models.ComponentDependency], error) {
	db := c.GetDB(ctx, tx)

	// Edges come from a walk over this asset version's SBOMs. The subquery keeps
	// the `component_dependencies` alias because callers pass filters and sorts
	// already qualified with that name.
	edges := db.Raw(`
		WITH RECURSIVE walk AS (
			SELECT s.asset_id, s.asset_version_name, e.component_id, e.direct_dependency_subtree_hash
			FROM sboms s
			JOIN sbom_merkle_edges e ON e.subtree_hash = s.root_subtree_hash
			WHERE s.asset_id = ? AND s.asset_version_name = ?
		UNION
			SELECT w.asset_id, w.asset_version_name, e.component_id, e.direct_dependency_subtree_hash
			FROM walk w
			JOIN sbom_merkle_edges e ON e.subtree_hash = w.direct_dependency_subtree_hash
		)
		SELECT DISTINCT w.asset_id, w.asset_version_name,
		       w.component_id AS component_id,
		       child.component_id AS dependency_id
		FROM walk w
		JOIN sbom_merkle_edges child ON child.subtree_hash = w.direct_dependency_subtree_hash
		WHERE w.direct_dependency_subtree_hash IS NOT NULL`, assetID, assetVersionName)

	query := db.Table("(?) AS component_dependencies", edges).
		Joins("LEFT JOIN components as dependency ON dependency.id = component_dependencies.dependency_id").
		Joins("LEFT JOIN component_projects as dependency_project ON dependency.project_key = dependency_project.project_key")

	for _, f := range filter {
		query = f.Where(query)
	}
	for _, s := range sort {
		query = s.Order(query)
	}
	if search != "" {
		query = query.Where("component_dependencies.dependency_id ILIKE ?", "pkg:%"+search+"%")
	}

	var total int64
	if err := query.Session(&gorm.Session{}).Distinct("component_dependencies.dependency_id").Count(&total).Error; err != nil {
		return shared.Paged[models.ComponentDependency]{}, err
	}

	distinctFields := []string{"component_dependencies.dependency_id"}
	for _, f := range sort {
		distinctFields = append(distinctFields, f.GetField())
	}
	selectClause := "DISTINCT ON (" + strings.Join(distinctFields, ",") + ") component_dependencies.component_id, component_dependencies.dependency_id"

	if pageInfo.PageSize == -1 {
		slog.Warn("unlimited page size requested - returning all results...", "assetVersionName", assetVersionName, "assetID", assetID)
	} else {
		query = query.Limit(pageInfo.PageSize).Offset((pageInfo.Page - 1) * pageInfo.PageSize)
	}

	var rows []struct {
		ComponentID  string
		DependencyID string
	}
	if err := query.Select(selectClause).Scan(&rows).Error; err != nil {
		return shared.Paged[models.ComponentDependency]{}, err
	}

	// component metadata lives in the components table, keyed by purl
	ids := make([]string, 0, len(rows)*2)
	for _, row := range rows {
		ids = append(ids, row.ComponentID, row.DependencyID)
	}
	components, err := c.FindByIDs(ctx, tx, ids)
	if err != nil {
		return shared.Paged[models.ComponentDependency]{}, err
	}
	byID := make(map[string]models.Component, len(components))
	for _, component := range components {
		byID[component.ID] = component
	}

	overwritten := make(map[string]string, len(overwrittenLicenses))
	for i := range overwrittenLicenses {
		if overwrittenLicenses[i].FinalLicenseDecision != nil {
			overwritten[overwrittenLicenses[i].ComponentPurl] = *overwrittenLicenses[i].FinalLicenseDecision
		}
	}
	resolve := func(id string) models.Component {
		component := byID[id]
		component.ID = id
		if license, ok := overwritten[id]; ok {
			component.License = &license
			component.IsLicenseOverwritten = true
		}
		return component
	}

	componentDependencies := make([]models.ComponentDependency, 0, len(rows))
	for _, row := range rows {
		componentDependencies = append(componentDependencies, models.ComponentDependency{
			AssetID:          assetID,
			AssetVersionName: assetVersionName,
			ComponentID:      row.ComponentID,
			DependencyID:     row.DependencyID,
			Component:        resolve(row.ComponentID),
			Dependency:       resolve(row.DependencyID),
		})
	}

	return shared.NewPaged(pageInfo, total, componentDependencies), nil
}

// FindByIDs loads component metadata for the given purls. The merkle tree
// stores only component ids, so anything richer - licenses, types, published
// dates - is looked up here when a document has to be rendered.
func (c *componentRepository) FindByIDs(ctx context.Context, tx *gorm.DB, ids []string) ([]models.Component, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	var components []models.Component
	err := c.GetDB(ctx, tx).Preload("ComponentProject").Where("id = ANY (?)", pq.Array(ids)).Find(&components).Error
	return components, err
}

func (c *componentRepository) FindByPurl(ctx context.Context, tx *gorm.DB, purl string) (models.Component, error) {
	var component models.Component
	err := c.GetDB(ctx, tx).Where("purl = ?", purl).First(&component).Error
	return component, err
}

func (c *componentRepository) GetDependencyCountPerScannerID(ctx context.Context, tx *gorm.DB, assetVersionName string, assetID uuid.UUID) (map[string]int, error) {
	var results []struct {
		ScannerID string `gorm:"column:scanner_ids"`
		Count     int    `gorm:"column:count"`
	}
	err := c.GetDB(ctx, tx).Model(&models.Component{}).
		Select("scanner_ids , COUNT(*) as count").
		Group("scanner_ids").
		Where("asset_version_name = ?", assetVersionName).
		Where("asset_id = ?", assetID).
		Find(&results).Error

	if err != nil {
		return nil, err
	}

	counts := make(map[string]int)
	for _, r := range results {
		counts[r.ScannerID] = r.Count
	}

	return counts, nil
}

func (c *componentRepository) SearchComponentOccurrencesByProject(ctx context.Context, tx *gorm.DB, projectIDs []uuid.UUID, pageInfo shared.PageInfo, search string) (shared.Paged[models.ComponentOccurrence], error) {
	occurrences := []models.ComponentOccurrence{}
	search = strings.TrimSpace(search)

	db := c.GetDB(ctx, tx)

	// walk every SBOM of the projects in scope. component_id carries the purl of
	// each reachable component, so no second join is needed to resolve children.
	const walk = `
		WITH RECURSIVE walk AS (
			SELECT s.asset_id, s.asset_version_name, s.artifact_name,
			       e.component_id, e.direct_dependency_subtree_hash
			FROM sboms s
			JOIN sbom_merkle_edges e ON e.subtree_hash = s.root_subtree_hash
			JOIN assets a ON a.id = s.asset_id
			WHERE a.project_id = ANY (?)
		UNION
			SELECT w.asset_id, w.asset_version_name, w.artifact_name,
			       e.component_id, e.direct_dependency_subtree_hash
			FROM walk w
			JOIN sbom_merkle_edges e ON e.subtree_hash = w.direct_dependency_subtree_hash
		)`

	var total int64
	if err := db.Raw(walk+`
		SELECT COUNT(*) FROM (
			SELECT DISTINCT w.asset_id, w.asset_version_name, w.artifact_name, w.component_id
			FROM walk w
			WHERE w.component_id ILIKE ? AND w.component_id LIKE 'pkg:%'
		) matches`, pq.Array(projectIDs), "%"+search+"%").Scan(&total).Error; err != nil {
		return shared.Paged[models.ComponentOccurrence]{}, err
	}

	if total == 0 {
		return shared.NewPaged(pageInfo, 0, occurrences), nil
	}

	limit, offset := -1, 0
	if pageInfo.PageSize > 0 {
		limit = pageInfo.PageSize
		offset = (max(pageInfo.Page, 1) - 1) * pageInfo.PageSize
	}

	if err := db.Raw(walk+`
		SELECT DISTINCT
			projects.id AS project_id,
			projects.name AS project_name,
			projects.slug AS project_slug,
			assets.id AS asset_id,
			assets.name AS asset_name,
			assets.slug AS asset_slug,
			w.asset_version_name AS asset_version_name,
			w.component_id AS dependency_id,
			w.artifact_name AS artifact_name,
			w.asset_version_name AS artifact_asset_version_name
		FROM walk w
		JOIN assets ON w.asset_id = assets.id
		JOIN projects ON assets.project_id = projects.id
		WHERE w.component_id ILIKE ? AND w.component_id LIKE 'pkg:%'
		ORDER BY dependency_id ASC, asset_version_name ASC
		LIMIT NULLIF(?, -1) OFFSET ?`,
		pq.Array(projectIDs), "%"+search+"%", limit, offset,
	).Scan(&occurrences).Error; err != nil {
		return shared.Paged[models.ComponentOccurrence]{}, err
	}

	return shared.NewPaged(pageInfo, total, occurrences), nil
}
