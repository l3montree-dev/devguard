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
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/database"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
	"gorm.io/gorm"
)

type componentRepository struct {
	Repository[string, models.Component, database.DB]
	db *gorm.DB
}

func NewComponentRepository(db database.DB) *componentRepository {
	if err := db.AutoMigrate(&models.Component{}, &models.ComponentDependency{}); err != nil {
		panic(err)
	}

	return &componentRepository{
		Repository: newGormRepository[string, models.Component](db),
		db:         db,
	}
}

func (c *componentRepository) UpdateSemverEnd(tx database.DB, ids []uuid.UUID, version *string) error {
	if len(ids) == 0 {
		return nil
	}

	return c.GetDB(tx).Model(&models.ComponentDependency{}).Where("id IN ?", ids).Update("semver_end", version).Error
}

func (c *componentRepository) CreateAssetComponents(tx database.DB, components []models.ComponentDependency) error {
	if len(components) == 0 {
		return nil
	}

	return c.GetDB(tx).Create(&components).Error
}

func (c *componentRepository) LoadAssetComponents(tx database.DB, asset models.Asset, scanType, version string) ([]models.ComponentDependency, error) {
	var components []models.ComponentDependency
	var err error
	if version == models.LatestVersion {
		err = c.GetDB(tx).Preload("Component").Preload("Dependency").Where("asset_id = ? AND scan_type = ? AND semver_end is NULL", asset.ID, scanType).Find(&components).Error
	} else {
		err = c.GetDB(tx).Preload("Component").Preload("Dependency").Where(`asset_id = ? AND scan_type = ? AND semver_start <= ? AND (semver_end >= ? OR semver_end IS NULL)`, asset.ID, scanType, version, version).Find(&components).Error
	}

	if err != nil {
		return nil, err
	}
	return components, err
}

func (c *componentRepository) GetVersions(tx database.DB, asset models.Asset) ([]string, error) {
	var versions []string
	err := c.GetDB(tx).Model(&models.ComponentDependency{}).Where("asset_id = ?", asset.ID).Distinct("semver_start").Pluck("semver_start", &versions).Error
	return versions, err
}

func (c *componentRepository) FindByPurl(tx database.DB, purl string) (models.Component, error) {
	var component models.Component
	err := c.GetDB(tx).Where("purl = ?", purl).First(&component).Error
	return component, err
}

func (c *componentRepository) HandleStateDiff(tx database.DB, assetID uuid.UUID, version string, oldState []models.ComponentDependency, newState []models.ComponentDependency) error {
	comparison := utils.CompareSlices(oldState, newState, func(dep models.ComponentDependency) string {
		return utils.SafeDereference(dep.ComponentPurl) + "->" + dep.DependencyPurl
	})

	removed := comparison.OnlyInA
	added := comparison.OnlyInB
	both := comparison.InBoth

	// check if we can delete some component. All which would have same SemverStart and SemverEnd
	var toDelete []models.ComponentDependency

	// Disjoin will first return all elements where the predicate is true
	// and then all elements where the predicate is false
	toDelete, removed = utils.Disjoin(removed, func(dep models.ComponentDependency) bool {
		return dep.AssetSemverStart == version
	})

	return c.GetDB(tx).Transaction(func(tx *gorm.DB) error {
		if len(toDelete) != 0 {
			if err := c.GetDB(tx).Delete(&toDelete).Error; err != nil {
				return err
			}
		}

		// update semver end as null for all components which are in both
		if err := c.UpdateSemverEnd(tx, utils.Map(both, func(el models.ComponentDependency) uuid.UUID {
			return el.ID
		}), nil); err != nil {
			return err
		}

		if err := c.UpdateSemverEnd(tx, utils.Map(removed, func(el models.ComponentDependency) uuid.UUID {
			return el.ID
		}), &version); err != nil {
			return err
		}
		// make sure the asset id is set
		for i := range added {
			added[i].AssetID = assetID
		}

		return c.CreateAssetComponents(tx, added)
	})
}

func (c *componentRepository) GetAssetDependenciesGroupedByScanType(asset_ID string) ([]models.AssetAllDependencies, error) {
	var results []models.AssetAllDependencies
	err := c.db.Model(&models.Component{}).
		Select("scan_type , COUNT(*) as count").
		Group("scan_type").
		Where("asset_id = ?", asset_ID).
		Find(&results).Error

	if err != nil {
		return nil, err
	}

	return results, nil
}

func (c *componentRepository) GetPackages(asset_ID string) ([]models.AssetComponents, error) {
	var results []models.AssetComponents
	err := c.db.Model(&models.Component{}).
		Select("SUBSTRING(purl_or_cpe FROM ':(.*?)/') AS pkg , COUNT(*) as count").
		Where("asset_id = ?", asset_ID).
		Group("pkg").
		Find(&results).Error

	if err != nil {
		return nil, err
	}

	return results, nil
}
