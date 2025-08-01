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
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
	"gorm.io/gorm"
)

type componentRepository struct {
	common.Repository[string, models.Component, core.DB]
	db *gorm.DB
}

func NewComponentRepository(db core.DB) *componentRepository {
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

func (c *componentRepository) CreateComponents(tx core.DB, components []models.ComponentDependency) error {
	if len(components) == 0 {
		return nil
	}

	return c.GetDB(tx).Create(&components).Error
}

// returns all component dependencies of the assetVersion  found by scannerID use "" to return all no matter who found it
func (c *componentRepository) LoadComponents(tx core.DB, assetVersionName string, assetID uuid.UUID, scannerID string) ([]models.ComponentDependency, error) {
	var components []models.ComponentDependency
	var err error

	query := c.GetDB(tx).Preload("Component").Preload("Dependency").Where("asset_version_name = ? AND asset_id = ?", assetVersionName, assetID)

	scannerIDs := strings.Split(scannerID, " ")
	if len(scannerIDs) > 0 {
		scannerIDsSubQuery := c.GetDB(tx)
		for i, id := range scannerIDs {
			like := "%" + id + "%"
			if i == 0 {
				scannerIDsSubQuery = scannerIDsSubQuery.Where("scanner_ids LIKE ?", like)
			} else {
				scannerIDsSubQuery = scannerIDsSubQuery.Or("scanner_ids LIKE ?", like)
			}
		}
		query.Where(scannerIDsSubQuery)
	}

	err = query.Find(&components).Error

	if err != nil {
		return nil, err
	}

	return components, err
}

// function which returns all dependency_components which lead to the package transmitted via the pURL parameter
func (c *componentRepository) LoadPathToComponent(tx core.DB, assetVersionName string, assetID uuid.UUID, pURL string, scannerID string) ([]models.ComponentDependency, error) {
	var components []models.ComponentDependency
	var err error

	//Find all needed components  recursively until we hit the root component
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// using postgresql CYCLE Keyword to detect possible loops
	query := c.GetDB(tx).WithContext(ctx).Raw(`WITH RECURSIVE components_cte AS (
  SELECT
    component_purl,
    dependency_purl,
    asset_id,
    scanner_ids,
    0 AS depth,
    ARRAY[dependency_purl] AS path
  FROM component_dependencies
  WHERE
    component_purl IS NULL AND
    asset_id = @assetID AND
    asset_version_name = @assetVersionName AND
    string_to_array(scanner_ids, ' ') && string_to_array(@scannerID, ' ')

  UNION ALL

  SELECT
    co.component_purl,
    co.dependency_purl,
    co.asset_id,
    co.scanner_ids,
    cte.depth + 1,
    cte.path || co.dependency_purl
  FROM component_dependencies AS co
  INNER JOIN components_cte AS cte
    ON co.component_purl = cte.dependency_purl
  WHERE
    co.asset_id = @assetID AND
    co.asset_version_name = @assetVersionName AND
    string_to_array(co.scanner_ids, ' ') && string_to_array(@scannerID, ' ') AND
    NOT co.dependency_purl = ANY(cte.path)
),
target_path AS (
  SELECT * FROM components_cte
  WHERE dependency_purl = @pURL
  ORDER BY depth ASC
),
path_edges AS (
  SELECT
    DISTINCT
    component_purl,
    dependency_purl,
    asset_id,
    scanner_ids,
    depth
  FROM components_cte
  WHERE dependency_purl = ANY((SELECT unnest(path) FROM target_path))
)
SELECT * FROM path_edges
ORDER BY depth;
`, sql.Named("pURL", pURL), sql.Named("assetID", assetID),
		sql.Named("assetVersionName", assetVersionName), sql.Named("scannerID", scannerID))

	//Map the query results to the component model
	err = query.Find(&components).Error
	if err != nil {
		return nil, err
	}

	return components, err
}

func (c *componentRepository) GetLicenseDistribution(tx core.DB, assetVersionName string, assetID uuid.UUID, scannerID string) (map[string]int, error) {
	type License []struct {
		License string
		Count   int
	}
	var overwrittenLicenses License
	var otherLicenses License
	//We want to get all components with an overwritten license and all components without one and then just merge the two
	//Components WITH an overwrite
	overwrittenLicensesQuery := c.GetDB(tx).Raw(`SELECT c.license , COUNT(c.license) as count 
	FROM components as c 
	RIGHT JOIN component_dependencies as cd 
	ON c.purl = cd.dependency_purl 
	WHERE EXISTS 
	(SELECT final_license_decision FROM license_risks as lr WHERE lr.component_purl = c.purl AND lr.state = ?)
	AND asset_version_name = ?
	AND asset_id = ? 
	GROUP BY c.license`,
		models.VulnStateFixed, assetVersionName, assetID)
	//Components WITHOUT an overwrite
	otherLicensesQuery := c.GetDB(tx).Raw(`SELECT c.license , COUNT(c.license) as count 
	FROM components as c 
	RIGHT JOIN component_dependencies as cd 
	ON c.purl = cd.dependency_purl 
	WHERE NOT EXISTS 
	(SELECT final_license_decision FROM license_risks as lr WHERE lr.component_purl = c.purl AND lr.state = ?)
	AND asset_version_name = ?
	AND asset_id = ? 
	GROUP BY c.license`,
		models.VulnStateFixed, assetVersionName, assetID)

	//We then still need to filter for the right scanner
	if scannerID != "" {
		scannerID = "%" + scannerID + "%"
		overwrittenLicensesQuery = overwrittenLicensesQuery.Where("scanner_ids LIKE ?", scannerID)
		otherLicensesQuery = otherLicensesQuery.Where("scanner_ids LIKE ?", scannerID)
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
	for k := range otherLicensesMap {
		otherLicensesMap[k] += overwrittenLicensesMap[k]
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

func (c *componentRepository) LoadComponentsWithProject(tx core.DB, overwrittenLicenses []models.LicenseRisk, assetVersionName string, assetID uuid.UUID, scannerID string, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery) (core.Paged[models.ComponentDependency], error) {
	var componentDependencies []models.ComponentDependency

	query := c.GetDB(tx).Model(&models.ComponentDependency{}).Joins("Dependency").Joins("Dependency.ComponentProject").Where("asset_version_name = ? AND asset_id = ?", assetVersionName, assetID)

	if scannerID != "" {
		scannerID = "%" + scannerID + "%"
		query = query.Where("scanner_ids LIKE ?", scannerID)
	}

	for _, f := range filter {
		query = query.Where(f.SQL(), f.Value())
	}

	if len(sort) > 0 {
		for _, s := range sort {
			query = query.Order(s.SQL())
		}
	}

	distinctFields := []string{"dependency_purl"}
	for _, f := range sort {
		distinctFields = append(distinctFields, f.GetField())
	}

	distinctOnQuery := "DISTINCT ON (" + strings.Join(distinctFields, ",") + ") *"

	if search != "" {
		query = query.Where("dependency_purl ILIKE ?", "pkg:%"+search+"%")
	} else {
		query = query.Where("dependency_purl ILIKE ?", "pkg:%")
	}

	var total int64
	query.Session(&gorm.Session{}).Distinct("dependency_purl").Count(&total)

	err := query.Select(distinctOnQuery).Limit(pageInfo.PageSize).Offset((pageInfo.Page - 1) * pageInfo.PageSize).Scan(&componentDependencies).Error
	if err != nil {
		return core.NewPaged(pageInfo, total, componentDependencies), err
	}

	// convert all overwritten licenses to a map which maps a purl to a new license
	isPurlOverwrittenMap := make(map[string]string, len(overwrittenLicenses))
	for i := range overwrittenLicenses {
		isPurlOverwrittenMap[overwrittenLicenses[i].ComponentPurl] = overwrittenLicenses[i].FinalLicenseDecision
	}

	// now we check if a given component (dependency) is present in the overwrittenMap eg. it needs to be overwritten and flagged as such
	for i, component := range componentDependencies {
		if license, ok := isPurlOverwrittenMap[componentDependencies[i].DependencyPurl]; ok {
			componentDependencies[i].Dependency.License = &license
			componentDependencies[i].Dependency.IsLicenseOverwritten = true
		}
		if component.ComponentPurl != nil {
			if license, ok := isPurlOverwrittenMap[*component.ComponentPurl]; ok {
				componentDependencies[i].Component.License = &license
				componentDependencies[i].Component.IsLicenseOverwritten = true
			}
		}
	}
	return core.NewPaged(pageInfo, total, componentDependencies), nil
}

func (c *componentRepository) FindByPurl(tx core.DB, purl string) (models.Component, error) {
	var component models.Component
	err := c.GetDB(tx).Where("purl = ?", purl).First(&component).Error
	return component, err
}

func (c *componentRepository) HandleStateDiff(tx core.DB, assetVersionName string, assetID uuid.UUID, oldState []models.ComponentDependency, newState []models.ComponentDependency, scannerID string) (bool, error) {
	comparison := utils.CompareSlices(oldState, newState, func(dep models.ComponentDependency) string {
		return utils.SafeDereference(dep.ComponentPurl) + "->" + dep.DependencyPurl
	})

	removed := comparison.OnlyInA
	added := comparison.OnlyInB
	needToBeChanged := comparison.InBoth

	return len(removed) > 0 || len(added) > 0, c.GetDB(tx).Transaction(func(tx *gorm.DB) error {
		//We remove the scanner id from all components in removed and if it was the only scanner id we remove the component
		toDelete, toSave := diffComponents(tx, c, removed, scannerID)

		//Now we want to update the database with the new scanner id values
		if len(toSave) > 0 {
			err := c.db.Save(toSave).Error
			if err != nil {
				return err
			}
		}

		if len(toDelete) > 0 {
			err := c.db.Delete(toDelete).Error
			if err != nil {
				return err
			}
		}

		//Next step is adding the scanner id to all existing component dependencies we just found
		for i := range needToBeChanged {
			if !utils.ContainsInWhitespaceSeparatedStringList(needToBeChanged[i].ScannerIDs, scannerID) {
				needToBeChanged[i].ScannerIDs = utils.AddToWhitespaceSeparatedStringList(needToBeChanged[i].ScannerIDs, scannerID)
			}
		}
		//We also need to update these changes in the database
		if len(needToBeChanged) > 0 {
			err := c.db.Save(needToBeChanged).Error
			if err != nil {
				return err
			}
		}

		// make sure the asset id is set
		for i := range added {
			added[i].AssetID = assetID
			added[i].AssetVersionName = assetVersionName
		}

		//At last we create all the new component dependencies
		return c.CreateComponents(tx, added)
	})
}

func (c *componentRepository) GetDependencyCountPerScanner(assetVersionName string, assetID uuid.UUID) (map[string]int, error) {
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

func diffComponents(tx core.DB, c *componentRepository, components []models.ComponentDependency, scannerID string) ([]models.ComponentDependency, []models.ComponentDependency) {
	var componentsToDelete []models.ComponentDependency
	var componentsToSave []models.ComponentDependency

	for i := range components {
		if strings.TrimSpace(components[i].ScannerIDs) == scannerID {
			componentsToDelete = append(componentsToDelete, components[i])
		} else {
			components[i].ScannerIDs = utils.RemoveFromWhitespaceSeparatedStringList(components[i].ScannerIDs, scannerID)
			componentsToSave = append(componentsToSave, components[i])
		}
	}

	return componentsToDelete, componentsToSave
}
