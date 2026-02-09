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
	"fmt"
	"log/slog"
	"strings"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/pkg/errors"
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

func (c *componentRepository) FindAllWithoutLicense() ([]models.Component, error) {
	var components []models.Component
	err := c.db.Where("license IS NULL OR license = ''").Find(&components).Error
	return components, err
}

func (c *componentRepository) CreateComponents(tx *gorm.DB, components []models.ComponentDependency) error {
	if len(components) == 0 {
		return nil
	}

	return c.GetDB(tx).Create(&components).Error
}

// LoadComponents loads all component dependencies for an asset version.
// For artifact-specific filtering, use the returned components with:
//
//	tree := normalize.BuildDependencyTree(root, models.ToNodes(deps), models.BuildDepMap(deps))
//	subtreeIDs := tree.ExtractSubtree("artifact:" + artifactName)
func (c *componentRepository) LoadComponents(tx *gorm.DB, assetVersionName string, assetID uuid.UUID, artifactName *string) ([]models.ComponentDependency, error) {
	db := c.GetDB(tx)

	// Pre-count to allocate slice with correct capacity (reduces slice growing allocations)
	var count int64
	if err := db.Model(&models.ComponentDependency{}).
		Where("asset_version_name = ? AND asset_id = ?", assetVersionName, assetID).
		Count(&count).Error; err != nil {
		return nil, err
	}

	// Pre-allocate slice with known capacity
	components := make([]models.ComponentDependency, 0, count)

	// Use Joins instead of Preload for better performance (single query with JOINs
	// instead of N+1 queries)
	err := db.Model(&models.ComponentDependency{}).
		Joins("Component").
		Joins("Dependency").
		Where("component_dependencies.asset_version_name = ? AND component_dependencies.asset_id = ?", assetVersionName, assetID).
		Find(&components).Error
	if err != nil {
		return nil, err
	}

	return components, err
}

func (c *componentRepository) LoadComponentsWithProject(tx *gorm.DB, overwrittenLicenses []models.LicenseRisk, assetVersionName string, assetID uuid.UUID, pageInfo shared.PageInfo, search string, filter []shared.FilterQuery, sort []shared.SortQuery) (shared.Paged[models.ComponentDependency], error) {

	var componentDependencies []models.ComponentDependency

	query := c.GetDB(tx).Model(&models.ComponentDependency{}).Preload("Dependency").Preload("Component").Preload("Dependency.ComponentProject").Joins("LEFT JOIN components as dependency ON dependency.id = dependency_id").Joins("LEFT JOIN component_projects as dependency_project ON dependency.project_key = dependency_project.project_key").Where("component_dependencies.asset_version_name = ? AND component_dependencies.asset_id = ?", assetVersionName, assetID)

	for _, f := range filter {
		query = query.Where(f.SQL(), f.Value())
	}

	if len(sort) > 0 {
		for _, s := range sort {
			query = query.Order(s.SQL())
		}
	}

	distinctFields := []string{"dependency_id"}
	for _, f := range sort {
		distinctFields = append(distinctFields, f.GetField())
	}

	distinctOnQuery := "DISTINCT ON (" + strings.Join(distinctFields, ",") + ") component_dependencies.*"

	if search != "" {
		query = query.Where("dependency_id ILIKE ?", "pkg:%"+search+"%")
	}

	var total int64
	query.Session(&gorm.Session{}).Distinct("dependency_id").Count(&total)

	if pageInfo.PageSize == -1 {
		slog.Warn("unlimited page size requested - returning all results...", "assetVersionName", assetVersionName, "assetID", assetID)
		err := query.Select(distinctOnQuery).Find(&componentDependencies).Error
		if err != nil {
			return shared.NewPaged(pageInfo, total, componentDependencies), err
		}
	} else {
		err := query.Select(distinctOnQuery).Limit(pageInfo.PageSize).Offset((pageInfo.Page - 1) * pageInfo.PageSize).Find(&componentDependencies).Error
		if err != nil {
			return shared.NewPaged(pageInfo, total, componentDependencies), err
		}
	}

	// Apply license overwrites
	isPurlOverwrittenMap := make(map[string]string, len(overwrittenLicenses))
	for i := range overwrittenLicenses {
		if overwrittenLicenses[i].FinalLicenseDecision != nil {
			isPurlOverwrittenMap[overwrittenLicenses[i].ComponentPurl] = *overwrittenLicenses[i].FinalLicenseDecision
		}
	}

	for i, component := range componentDependencies {
		if license, ok := isPurlOverwrittenMap[componentDependencies[i].DependencyID]; ok {
			componentDependencies[i].Dependency.License = &license
			componentDependencies[i].Dependency.IsLicenseOverwritten = true
		}
		if component.ComponentID != nil {
			if license, ok := isPurlOverwrittenMap[*component.ComponentID]; ok {
				componentDependencies[i].Component.License = &license
				componentDependencies[i].Component.IsLicenseOverwritten = true
			}
		}
	}
	return shared.NewPaged(pageInfo, total, componentDependencies), nil

}

func (c *componentRepository) FindByPurl(tx *gorm.DB, purl string) (models.Component, error) {
	var component models.Component
	err := c.GetDB(tx).Where("purl = ?", purl).First(&component).Error
	return component, err
}

func (c *componentRepository) HandleStateDiff(tx *gorm.DB, assetVersion models.AssetVersion, wholeAssetGraph *normalize.SBOMGraph, diff normalize.GraphDiff) error {
	// Create new components in the database
	if len(diff.AddedNodes) > 0 {
		if err := c.CreateBatch(tx, utils.Map(diff.AddedNodes, func(node *normalize.GraphNode) models.Component {
			return models.Component{
				ID: node.Component.PackageURL,
			}
		})); err != nil {
			return err
		}
	}

	// delete removed components from the database
	removedNodeIDs := diff.RemovedNodeIDs()
	if len(removedNodeIDs) > 0 {
		if err := c.DeleteBatch(tx, utils.Map(removedNodeIDs, func(componentID string) models.Component {
			node := wholeAssetGraph.Node(componentID)
			return models.Component{
				ID: node.Component.PackageURL,
			}
		})); err != nil {
			return err
		}
	}

	// delete the removed edges from the database
	// we can only find them by componentID and dependencyID
	// thus the query needs to be built here

	if len(diff.RemovedEdges) > 0 {
		var valueClauses []string
		for _, edge := range diff.RemovedEdges {
			var componentID string
			if edge[0] == normalize.GraphRootNodeID {
				componentID = "NULL"
			} else {
				componentID = fmt.Sprintf("'%s'", strings.ReplaceAll(edge[0], "'", "''"))
			}

			escapedDep := strings.ReplaceAll(edge[1], "'", "''")
			valueClauses = append(valueClauses, fmt.Sprintf("(%s, '%s')", componentID, escapedDep))
		}
		// Join the value clauses with commas
		values := strings.Join(valueClauses, ",")
		// Escape the asset version name for safe SQL embedding
		escapedVersionName := strings.ReplaceAll(assetVersion.Name, "'", "''")
		// Construct the full SQL query without GORM ? placeholders,
		// because purls in the VALUES can contain ? (e.g. ?arch=x86_64)
		// which GORM would misinterpret as bind parameters.
		query := fmt.Sprintf(`
			DELETE FROM component_dependencies
			WHERE (component_id, dependency_id) IN (VALUES %s)
			AND asset_id = '%s'
			AND asset_version_name = '%s'
		`, values, assetVersion.AssetID.String(), escapedVersionName)
		// execute the query without any GORM bind parameters
		err := c.GetDB(tx).Exec(query).Error

		if err != nil {
			return err
		}
	}

	// for added edges, create them in the database
	deps := []models.ComponentDependency{}
	for _, edge := range diff.AddedEdges {
		c1 := wholeAssetGraph.Node(edge[0])
		c2 := wholeAssetGraph.Node(edge[1])
		var componentID *string
		if c1.Type == normalize.GraphNodeTypeRoot {
			// set to nil for root nodes
			componentID = nil
		} else {
			componentID = utils.Ptr(c1.Component.PackageURL)
		}

		componentDependency := models.ComponentDependency{
			AssetID:          assetVersion.AssetID,
			AssetVersionName: assetVersion.Name,
			ComponentID:      componentID,
			DependencyID:     c2.Component.PackageURL,
		}

		deps = append(deps, componentDependency)
	}

	if err := c.CreateComponents(tx, deps); err != nil {
		return errors.Wrap(err, "could not create component dependencies")
	}
	return nil
}

func (c *componentRepository) GetDependencyCountPerScannerID(assetVersionName string, assetID uuid.UUID) (map[string]int, error) {
	var results []struct {
		ScannerID string `gorm:"column:scanner_ids"`
		Count     int    `gorm:"column:count"`
	}
	err := c.db.Model(&models.Component{}).
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

func (c *componentRepository) FetchInformationSources(artifact *models.Artifact) ([]models.ComponentDependency, error) {
	var result []models.ComponentDependency
	// Information sources are dependencies directly under the artifact root node
	artifactRoot := "artifact:" + artifact.ArtifactName
	if err := c.GetDB(nil).Model(&models.ComponentDependency{}).Where("component_id = ? AND asset_version_name = ? AND asset_id = ?", artifactRoot, artifact.AssetVersionName, artifact.AssetID).Find(&result).Error; err != nil {
		return nil, err
	}
	return result, nil
}

func (c *componentRepository) RemoveInformationSources(artifact *models.Artifact, rootNodePurls []string) error {
	artifactRoot := "artifact:" + artifact.ArtifactName
	return c.GetDB(nil).Where("component_id = ? AND dependency_id IN (?) AND asset_version_name = ? AND asset_id = ?", artifactRoot, rootNodePurls, artifact.AssetVersionName, artifact.AssetID).Delete(&models.ComponentDependency{}).Error
}

func (c *componentRepository) SearchComponentOccurrencesByProject(tx shared.DB, projectIDs []uuid.UUID, pageInfo shared.PageInfo, search string) (shared.Paged[models.ComponentOccurrence], error) {
	occurrences := []models.ComponentOccurrence{}
	search = strings.TrimSpace(search)

	db := c.GetDB(tx)

	base := db.Table("component_dependencies").
		Joins("JOIN assets ON component_dependencies.asset_id = assets.id").
		Joins("JOIN projects ON assets.project_id = projects.id").
		Joins("LEFT JOIN components ON component_dependencies.component_id = components.id").
		Where("projects.id IN ?", projectIDs).
		Where("component_dependencies.dependency_id ILIKE ?", "%"+search+"%").Where("component_dependencies.dependency_id LIKE ?", "pkg:%")

	var total int64
	if err := base.Session(&gorm.Session{}).Count(&total).Error; err != nil {
		return shared.Paged[models.ComponentOccurrence]{}, err
	}

	if total == 0 {
		return shared.NewPaged(pageInfo, 0, occurrences), nil
	}

	// Extract artifact name from component_id using the artifact: prefix
	query := db.Table("component_dependencies").
		Select(`component_dependencies.id AS component_dependency_id,
            projects.id AS project_id,
            projects.name AS project_name,
            projects.slug AS project_slug,
            assets.id AS asset_id,
            assets.name AS asset_name,
            assets.slug AS asset_slug,
            component_dependencies.asset_version_name AS asset_version_name,
            component_dependencies.dependency_id AS dependency_id,
            CASE WHEN component_dependencies.component_id LIKE 'artifact:%'
                 THEN SUBSTRING(component_dependencies.component_id FROM 10)
                 ELSE NULL END AS artifact_name,
            component_dependencies.asset_version_name AS artifact_asset_version_name`).
		Joins("JOIN assets ON component_dependencies.asset_id = assets.id").
		Joins("JOIN projects ON assets.project_id = projects.id").
		Joins("LEFT JOIN components ON component_dependencies.component_id = components.id").
		Where("projects.id IN ?", projectIDs).
		Where("component_dependencies.dependency_id ILIKE ?", "%"+search+"%").
		Where("component_dependencies.dependency_id LIKE ?", "pkg:%").
		Order("component_dependencies.dependency_id ASC, component_dependencies.asset_version_name ASC")

	if pageInfo.PageSize > 0 {
		page := pageInfo.Page
		if page < 1 {
			page = 1
		}
		offset := (page - 1) * pageInfo.PageSize
		query = query.Limit(pageInfo.PageSize).Offset(offset)
	}

	if err := query.Scan(&occurrences).Error; err != nil {
		return shared.Paged[models.ComponentOccurrence]{}, err
	}

	return shared.NewPaged(pageInfo, total, occurrences), nil
}
