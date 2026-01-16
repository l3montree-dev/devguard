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
	"database/sql"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"gorm.io/gorm"
)

type componentRepository struct {
	utils.Repository[string, models.Component, *gorm.DB]
	db *gorm.DB
}

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

func (c *componentRepository) loadComponentsForAllArtifacts(tx *gorm.DB, assetVersionName string, assetID uuid.UUID) ([]models.ComponentDependency, error) {
	var components []models.ComponentDependency

	err := c.GetDB(tx).Model(&models.ComponentDependency{}).
		Preload("Component").
		Preload("Dependency").
		Preload("Artifacts").
		Where("asset_version_name = ? AND asset_id = ?", assetVersionName, assetID).
		Find(&components).Error
	if err != nil {
		return nil, err
	}
	return components, err
}

func (c *componentRepository) LoadComponents(tx *gorm.DB, assetVersionName string, assetID uuid.UUID, artifactName *string) ([]models.ComponentDependency, error) {
	if artifactName == nil {
		return c.loadComponentsForAllArtifacts(tx, assetVersionName, assetID)
	}

	var components []models.ComponentDependency
	err := c.GetDB(tx).Model(&models.ComponentDependency{}).
		Preload("Component").Preload("Dependency").Where(`EXISTS (
        SELECT 1 FROM artifact_component_dependencies acd 
        WHERE acd.component_dependency_id = id 
            AND acd.artifact_artifact_name = ? 
            AND acd.artifact_asset_version_name = ? 
            AND acd.artifact_asset_id = ?
    	)`, artifactName, assetVersionName, assetID).Find(&components).Error

	return components, err
}

// function which returns all dependency_components which lead to the package transmitted via the pURL parameter
func (c *componentRepository) LoadPathToComponent(tx *gorm.DB, assetVersionName string, assetID uuid.UUID, pURL string, artifactName *string) ([]models.ComponentDependency, error) {
	var components []models.ComponentDependency
	var err error

	var query *gorm.DB
	//Find all needed components  recursively until we hit the root component
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	if artifactName == nil {
		// using postgresql CYCLE Keyword to detect possible loops
		query = c.GetDB(tx).WithContext(ctx).Raw(`WITH RECURSIVE components_cte AS (
	SELECT
		cd.component_id,
		cd.dependency_id,
		cd.asset_id,
		0 AS depth,
		ARRAY[cd.dependency_id] AS path
	FROM component_dependencies cd
	JOIN artifact_component_dependencies acd ON acd.component_dependency_id = cd.id
	WHERE
		cd.dependency_id = @pURL AND
		cd.asset_id = @assetID AND
		cd.asset_version_name = @assetVersionName AND
		acd.artifact_asset_version_name = @assetVersionName AND
		acd.artifact_asset_id = @assetID

	UNION ALL

	SELECT
		co.component_id,
		co.dependency_id,
		co.asset_id,
		cte.depth + 1,
		co.dependency_id || cte.path
	FROM component_dependencies co
	INNER JOIN components_cte cte
		ON co.dependency_id = cte.component_id
	WHERE
		co.asset_id = @assetID AND
		co.asset_version_name = @assetVersionName AND
		NOT co.dependency_id = ANY(cte.path) AND cte.depth < 100
),
target_path AS (
	SELECT * FROM components_cte
	ORDER BY depth DESC
)
SELECT * FROM target_path;
`, sql.Named("pURL", pURL), sql.Named("assetID", assetID),
			sql.Named("assetVersionName", assetVersionName))
	} else {
		// using postgresql CYCLE Keyword to detect possible loops
		query = c.GetDB(tx).WithContext(ctx).Raw(`WITH RECURSIVE components_cte AS (
	SELECT
		cd.component_id,
		cd.dependency_id,
		cd.asset_id,
		0 AS depth,
		ARRAY[cd.dependency_id] AS path
	FROM component_dependencies cd
	JOIN artifact_component_dependencies acd ON acd.component_dependency_id = cd.id
	WHERE
		cd.dependency_id = @pURL AND
		cd.asset_id = @assetID AND
		cd.asset_version_name = @assetVersionName AND
		acd.artifact_artifact_name = @artifactName AND
		acd.artifact_asset_version_name = @assetVersionName AND
		acd.artifact_asset_id = @assetID

	UNION ALL

	SELECT
		co.component_id,
		co.dependency_id,
		co.asset_id,
		cte.depth + 1,
		co.dependency_id || cte.path
	FROM component_dependencies co
	INNER JOIN components_cte cte
		ON co.dependency_id = cte.component_id
	JOIN artifact_component_dependencies acd ON acd.component_dependency_id = co.id
	WHERE
		co.asset_id = @assetID AND
		co.asset_version_name = @assetVersionName AND
		acd.artifact_artifact_name = @artifactName AND
		NOT co.dependency_id = ANY(cte.path) AND cte.depth < 100
),
target_path AS (
	SELECT * FROM components_cte
	ORDER BY depth DESC
)
SELECT * FROM target_path;
`, sql.Named("pURL", pURL), sql.Named("assetID", assetID),
			sql.Named("assetVersionName", assetVersionName), sql.Named("artifactName", artifactName))
	}

	// Map the query results to the component model
	err = query.Find(&components).Error
	if err != nil {
		return nil, err
	}

	return components, err
}

func (c *componentRepository) GetLicenseDistribution(tx *gorm.DB, assetVersionName string, assetID uuid.UUID, artifactName *string) (map[string]int, error) {
	type License []struct {
		License string
		Count   int
	}
	var overwrittenLicenses License
	var otherLicenses License
	//We want to get all components with an overwritten license and all components without one and then just merge the two
	//Components WITH an overwrite
	overwrittenLicensesQuery := c.GetDB(tx).Raw(`SELECT
    lr.final_license_decision as license,
    COUNT(DISTINCT cd.dependency_id) AS count
	FROM license_risks AS lr
	JOIN components AS c
		ON lr.component_id = c.id
	JOIN component_dependencies AS cd
		ON c.id = cd.dependency_id
	WHERE lr.state = ?
	AND cd.asset_version_name = ?
	AND cd.asset_id = ?
	GROUP BY lr.final_license_decision`,
		dtos.VulnStateFixed, assetVersionName, assetID)

	//Components WITHOUT an overwrite
	otherLicensesQuery := c.GetDB(tx).Raw(`SELECT c.license, COUNT(DISTINCT cd.component_id) AS count
	FROM components as c
	RIGHT JOIN component_dependencies as cd
	ON c.id = cd.dependency_id
	WHERE NOT EXISTS
	(SELECT final_license_decision FROM license_risks as lr WHERE lr.component_id = c.id AND lr.state = ?)
	AND asset_version_name = ?
	AND asset_id = ?
	GROUP BY c.license`,
		dtos.VulnStateFixed, assetVersionName, assetID)

	//We then still need to filter for the right scanner
	if artifactName != nil {
		overwrittenLicensesQuery = overwrittenLicensesQuery.Where(`EXISTS (
			SELECT 1 FROM artifact_component_dependencies acd 
			JOIN artifacts a ON acd.artifact_artifact_name = a.artifact_name 
				AND acd.artifact_asset_version_name = a.asset_version_name 
				AND acd.artifact_asset_id = a.asset_id
			WHERE acd.component_dependency_id = cd.id 
				AND a.artifact_name = ?
		)`, artifactName)
	}
	//Map the query to the right struct
	err := overwrittenLicensesQuery.Scan(&overwrittenLicenses).Error
	if err != nil {
		return nil, err
	}
	err = otherLicensesQuery.Scan(&otherLicenses).Error
	if err != nil {
		return nil, err
	}

	// convert normal query to map
	overwrittenLicensesMap := licensesToMap(overwrittenLicenses)
	otherLicensesMap := licensesToMap(otherLicenses)

	// merge the two maps
	for k := range otherLicensesMap {
		otherLicensesMap[k] += overwrittenLicensesMap[k]
	}

	for k, v := range overwrittenLicensesMap {
		if _, ok := otherLicensesMap[k]; !ok {
			otherLicensesMap[k] = v
		}
	}

	return otherLicensesMap, nil
}

// this function maps a list of license structs to, well...  a map
func licensesToMap(licenses []struct {
	License string
	Count   int
}) map[string]int {
	licensesMap := make(map[string]int)
	for _, l := range licenses {
		if l.License == "" {
			l.License = "unknown"
		}

		if _, ok := licensesMap[l.License]; !ok {
			licensesMap[l.License] = 0
		}

		licensesMap[l.License] += l.Count
	}

	return licensesMap
}

func (c *componentRepository) LoadComponentsWithProject(tx *gorm.DB, overwrittenLicenses []models.LicenseRisk, assetVersionName string, assetID uuid.UUID, pageInfo shared.PageInfo, search string, filter []shared.FilterQuery, sort []shared.SortQuery) (shared.Paged[models.ComponentDependency], error) {

	var componentDependencies []models.ComponentDependency

	query := c.GetDB(tx).Model(&models.ComponentDependency{}).Preload("Dependency").Preload("Component").Preload("Dependency.ComponentProject").Preload("Artifacts").Joins("JOIN artifact_component_dependencies ON artifact_component_dependencies.component_dependency_id = component_dependencies.id").Joins("JOIN artifacts ON artifact_component_dependencies.artifact_artifact_name = artifacts.artifact_name AND artifact_component_dependencies.artifact_asset_version_name = artifacts.asset_version_name AND artifact_component_dependencies.artifact_asset_id = artifacts.asset_id").Joins("LEFT JOIN components as dependency ON dependency.id = dependency_id").Joins("LEFT JOIN component_projects as dependency_project ON dependency.project_key = dependency_project.project_key").Where("component_dependencies.asset_version_name = ? AND component_dependencies.asset_id = ?", assetVersionName, assetID)

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

	distinctOnQuery := "DISTINCT ON (" + strings.Join(distinctFields, ",") + ") *"

	if search != "" {
		query = query.Where("dependency_id ILIKE ?", "pkg:%"+search+"%")
	}

	var total int64
	query.Session(&gorm.Session{}).Distinct("dependency_id").Count(&total)

	// if page size is -1, we want to return all results
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

	// convert all overwritten licenses to a map which maps a purl to a new license
	isPurlOverwrittenMap := make(map[string]string, len(overwrittenLicenses))
	for i := range overwrittenLicenses {
		if overwrittenLicenses[i].FinalLicenseDecision != nil {
			isPurlOverwrittenMap[overwrittenLicenses[i].ComponentPurl] = *overwrittenLicenses[i].FinalLicenseDecision
		}
	}

	// now we check if a given component (dependency) is present in the overwrittenMap eg. it needs to be overwritten and flagged as such
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

func (c *componentRepository) HandleStateDiff(tx *gorm.DB, assetVersionName string, assetID uuid.UUID, oldState []models.ComponentDependency, newState []models.ComponentDependency, artifactName string) (bool, error) {
	comparison := utils.CompareSlices(oldState, newState, func(dep models.ComponentDependency) string {
		return utils.SafeDereference(dep.ComponentID) + "->" + dep.DependencyID
	})

	artifact := models.Artifact{
		ArtifactName:     artifactName,
		AssetID:          assetID,
		AssetVersionName: assetVersionName,
	}

	removed := comparison.OnlyInA
	added := comparison.OnlyInB

	toRemove := []models.ComponentDependency{}
	toUpdate := []models.ComponentDependency{}
	toAdd := []models.ComponentDependency{}

	// load all dependencies which are already present for the assetID and assetVersionName
	components, err := c.loadComponentsForAllArtifacts(tx, assetVersionName, assetID)
	if err != nil {
		return false, err
	}

	// componentsMap
	componentsMap := make(map[uuid.UUID]models.ComponentDependency)
	for _, comp := range components {
		componentsMap[comp.ID] = comp
	}

	for _, removedDep := range removed {
		if existingComp, ok := componentsMap[removedDep.ID]; ok {
			if len(existingComp.Artifacts) > 1 {
				// we have more than one artifact - therefore we just remove the artifact from the list
				newArtifacts := utils.Filter(existingComp.Artifacts, func(a models.Artifact) bool {
					return a.ArtifactName != artifactName || a.AssetVersionName != assetVersionName || a.AssetID != assetID
				})
				existingComp.Artifacts = newArtifacts
				toUpdate = append(toUpdate, existingComp)
			} else {
				// we only have one artifact - therefore we can delete the whole component dependency
				toRemove = append(toRemove, existingComp)
			}
		}
	}

	for _, addedDep := range added {
		addedDep.AssetID = assetID
		addedDep.AssetVersionName = assetVersionName
		if existingComp, ok := componentsMap[addedDep.ID]; ok {
			// we already have this component dependency - therefore we just need to add the artifact to the list
			newArtifacts := append(existingComp.Artifacts, artifact)
			existingComp.Artifacts = newArtifacts
			toUpdate = append(toUpdate, existingComp)
		} else {
			addedDep.Artifacts = []models.Artifact{artifact}
			// we do not have this component dependency - therefore we need to add it
			toAdd = append(toAdd, addedDep)
		}
	}

	return len(toRemove) > 0 || len(toUpdate) > 0 || len(toAdd) > 0, c.GetDB(tx).Transaction(func(tx *gorm.DB) error {

		if len(toRemove) > 0 {
			err := c.db.Delete(removed).Error
			if err != nil {
				return err
			}
		}

		if len(toUpdate) > 0 {
			for _, update := range toUpdate {
				err := c.db.Save(&update).Error
				if err != nil {
					return err
				}
			}
		}

		if len(toAdd) > 0 {
			err := c.CreateComponents(tx, toAdd)
			if err != nil {
				return err
			}
		}

		return nil
	})
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

	// convert to map
	counts := make(map[string]int)
	for _, r := range results {
		counts[r.ScannerID] = r.Count
	}

	return counts, nil
}

func (c *componentRepository) FetchInformationSources(artifact *models.Artifact) ([]models.ComponentDependency, error) {
	var result []models.ComponentDependency
	if err := c.GetDB(nil).Model(&models.ComponentDependency{}).Where("component_id IS NULL AND EXISTS (SELECT 1 from artifact_component_dependencies WHERE artifact_artifact_name = ? AND asset_version_name = ? AND asset_id = ? AND component_dependencies.asset_version_name = asset_version_name AND asset_id = component_dependencies.asset_id AND component_dependency_id = id)", artifact.ArtifactName, artifact.AssetVersionName, artifact.AssetID).Find(&result).Error; err != nil {
		return nil, err
	}
	return result, nil
}

func (c *componentRepository) RemoveInformationSources(artifact *models.Artifact, rootNodePurls []string) error {
	return c.GetDB(nil).Where("component_id IS NULL AND dependency_id IN (?) AND EXISTS (SELECT 1 from artifact_component_dependencies WHERE artifact_artifact_name = ? AND asset_version_name = ? AND asset_id = ? AND component_dependencies.asset_version_name = asset_version_name AND asset_id = component_dependencies.asset_id)", rootNodePurls, artifact.ArtifactName, artifact.AssetVersionName, artifact.AssetID).Delete(&models.ComponentDependency{}).Error
}

func (c *componentRepository) SearchComponentOccurrencesByProject(tx shared.DB, projectIDs []uuid.UUID, pageInfo shared.PageInfo, search string) (shared.Paged[models.ComponentOccurrence], error) {
	occurrences := []models.ComponentOccurrence{}
	search = strings.TrimSpace(search)

	db := c.GetDB(tx)

	base := db.Table("component_dependencies").
		Joins("JOIN assets ON component_dependencies.asset_id = assets.id").
		Joins("JOIN projects ON assets.project_id = projects.id").
		Joins("LEFT JOIN components ON component_dependencies.component_id = components.id").
		Joins("LEFT JOIN artifact_component_dependencies ON artifact_component_dependencies.component_dependency_id = component_dependencies.id").
		Where("projects.id IN ?", projectIDs).
		Where("component_dependencies.dependency_id ILIKE ?", "%"+search+"%").Where("component_dependencies.dependency_id LIKE ?", "pkg:%")

	var total int64
	if err := base.Session(&gorm.Session{}).Count(&total).Error; err != nil {
		return shared.Paged[models.ComponentOccurrence]{}, err
	}

	if total == 0 {
		return shared.NewPaged(pageInfo, 0, occurrences), nil
	}

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
            artifact_component_dependencies.artifact_artifact_name AS artifact_name,
            artifact_component_dependencies.artifact_asset_version_name AS artifact_asset_version_name`).
		Joins("JOIN assets ON component_dependencies.asset_id = assets.id").
		Joins("JOIN projects ON assets.project_id = projects.id").
		Joins("LEFT JOIN artifact_component_dependencies ON artifact_component_dependencies.component_dependency_id = component_dependencies.id").
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
