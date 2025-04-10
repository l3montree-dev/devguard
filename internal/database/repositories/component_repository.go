// Copyright (C) 2024 Tim Bastin, l3montree UG (haftungsbeschränkt)
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
	"strings"

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
	if err := db.AutoMigrate(&models.Component{}, &models.ComponentDependency{}); err != nil {
		panic(err)
	}

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

func (c *componentRepository) LoadComponents(tx core.DB, assetVersionName string, assetID uuid.UUID, scannerID string) ([]models.ComponentDependency, error) {
	var components []models.ComponentDependency
	var err error

	query := c.GetDB(tx).Preload("Component").Preload("Dependency").Where("asset_version_name = ? AND asset_id = ?", assetVersionName, assetID)

	if scannerID != "" {
		scannerID = "%" + scannerID + "%"
		query = query.Where("scanner_ids LIKE ?", scannerID)
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

	scannerID = "%" + scannerID + "%"
	query := c.GetDB(tx).Raw(`WITH RECURSIVE components_cte AS (
			SELECT component_purl,dependency_purl,asset_id,scanner_ids,depth,semver_start,semver_end
			FROM component_dependencies
			WHERE dependency_purl like ? AND asset_id = ? AND asset_version_name = ? AND scanner_ids LIKE ?
			UNION ALL
			SELECT co.component_purl,co.dependency_purl,co.asset_id,co.scanner_ids,co.depth,co.semver_start,co.semver_end
			FROM component_dependencies AS co
			INNER JOIN components_cte AS cte ON co.dependency_purl = cte.component_purl 
 			WHERE co.asset_id = ? AND co.asset_version_name = ? AND co.scanner_ids LIKE ?
		)
		SELECT DISTINCT * FROM components_cte`, pURL, assetID, assetVersionName, scannerID, assetID, assetVersionName, scannerID)

	//Map the query results to the component model
	err = query.Find(&components).Error
	if err != nil {
		return nil, err
	}

	return components, err
}

func (c *componentRepository) GetLicenseDistribution(tx core.DB, assetVersionName string, assetID uuid.UUID, scannerID string) (map[string]int, error) {
	var licenses []struct {
		License string
		Count   int
	}

	var err error

	query := c.GetDB(tx).Table("components").Select("components.license as license, COUNT(components.license) as count").Joins("RIGHT JOIN component_dependencies ON components.purl = component_dependencies.dependency_purl").Where("asset_version_name = ? AND asset_id = ?", assetVersionName, assetID).Group("components.license")

	if scannerID != "" {
		scannerID = "%" + scannerID + "%"
		query = query.Where("scanner_ids LIKE ?", scannerID)
	}

	err = query.Scan(&licenses).Error

	if err != nil {
		return nil, err
	}

	// convert to map
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

	return licensesMap, nil
}

func (c *componentRepository) LoadComponentsWithProject(tx core.DB, assetVersionName string, assetID uuid.UUID, scannerID string, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery) (core.Paged[models.ComponentDependency], error) {
	var components []models.ComponentDependency

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

	err := query.Select(distinctOnQuery).Limit(pageInfo.PageSize).Offset((pageInfo.Page - 1) * pageInfo.PageSize).Scan(&components).Error

	return core.NewPaged(pageInfo, total, components), err
}

func (c *componentRepository) FindByPurl(tx core.DB, purl string) (models.Component, error) {
	var component models.Component
	err := c.GetDB(tx).Where("purl = ?", purl).First(&component).Error
	return component, err
}

func (c *componentRepository) HandleStateDiff(tx core.DB, assetVersionName string, assetID uuid.UUID, oldState []models.ComponentDependency, newState []models.ComponentDependency, scannerID string) error {
	comparison := utils.CompareSlices(oldState, newState, func(dep models.ComponentDependency) string {
		return utils.SafeDereference(dep.ComponentPurl) + "->" + dep.DependencyPurl
	})

	removed := comparison.OnlyInA
	added := comparison.OnlyInB
	needToBeChanged := comparison.InBoth

	return c.GetDB(tx).Transaction(func(tx *gorm.DB) error {
		//We remove the scanner id from all components in removed and if it was the only scanner id we remove the component
		dependenciesToUpdate, err := removeScannerIDFromComponents(tx, c, removed, scannerID)
		if err != nil {
			return err
		}

		//Now we want to update the database with the new scanner id values
		if len(dependenciesToUpdate) > 0 {
			err := c.db.Save(dependenciesToUpdate).Error
			if err != nil {
				return err
			}
		}

		//Next step is adding the scanner id to all existing component dependencies we just found
		for i := range needToBeChanged {
			if !strings.Contains(needToBeChanged[i].ScannerIDs, scannerID) {
				needToBeChanged[i].ScannerIDs = needToBeChanged[i].ScannerIDs + scannerID + " "
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

func removeScannerIDFromComponents(tx core.DB, c *componentRepository, components []models.ComponentDependency, scannerID string) ([]models.ComponentDependency, error) {
	var componentDependeciesToChange []models.ComponentDependency
	scannerID += " "
	for i := range components {

		if components[i].ScannerIDs == scannerID {
			if err := c.GetDB(tx).Delete(&components[i]).Error; err != nil {
				return componentDependeciesToChange, err
			}
		} else {
			components[i].ScannerIDs = strings.Replace(components[i].ScannerIDs, scannerID, "", 1)
			componentDependeciesToChange = append(componentDependeciesToChange, components[i])
		}
	}

	return componentDependeciesToChange, nil
}
