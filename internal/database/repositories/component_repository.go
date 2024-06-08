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
	"github.com/l3montree-dev/flawfix/internal/database"
	"github.com/l3montree-dev/flawfix/internal/database/models"
	"github.com/l3montree-dev/flawfix/internal/utils"
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

func (c *componentRepository) UpdateSemverEnd(tx database.DB, ids []uuid.UUID, version string) error {
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

func (c *componentRepository) LoadAssetComponents(tx database.DB, asset models.Asset, version string) ([]models.ComponentDependency, error) {
	var components []models.ComponentDependency
	var err error
	if version == models.LatestVersion {
		err = c.GetDB(tx).Raw(`WITH RECURSIVE dependency_tree AS (
			SELECT
			asset_id, 
			component_purl_or_cpe, 
			dependency_purl_or_cpe, 
			is_direct_asset_dependency, 
			semver_start, 
			semver_end, 
			1 AS depth  FROM component_dependencies
			WHERE asset_id = $1 AND is_direct_asset_dependency = true AND semver_end IS NULL
			UNION ALL
			SELECT 
			dt1.asset_id, 
			dt1.component_purl_or_cpe, 
			dt1.dependency_purl_or_cpe, 
			dt1.is_direct_asset_dependency, 
			dt1.semver_start, 
			dt1.semver_end, 
        	dt.depth + 1 FROM component_dependencies dt1
			JOIN dependency_tree dt ON dt1.asset_id = dt.asset_id AND dt1.component_purl_or_cpe = dt.dependency_purl_or_cpe WHERE dt.depth < 100 AND dt1.semver_end IS NULL
		)
		SELECT * FROM dependency_tree;`, asset.ID).Scan(&components).Error
	} else {
		err = c.GetDB(tx).Raw(`WITH RECURSIVE dependency_tree AS (
			SELECT
			asset_id, 
			component_purl_or_cpe, 
			dependency_purl_or_cpe, 
			is_direct_asset_dependency, 
			semver_start, 
			semver_end, 
			1 AS depth  FROM component_dependencies
			WHERE asset_id = $1 AND is_direct_asset_dependency = true AND semver_start <= $2 AND (semver_end IS NULL OR semver_end >= $2)
			UNION ALL
			SELECT 
			dt1.asset_id, 
			dt1.component_purl_or_cpe, 
			dt1.dependency_purl_or_cpe, 
			dt1.is_direct_asset_dependency, 
			dt1.semver_start, 
			dt1.semver_end, 
        	dt.depth + 1 FROM component_dependencies dt1
			JOIN dependency_tree dt ON dt1.asset_id = dt.asset_id AND dt1.component_purl_or_cpe = dt.dependency_purl_or_cpe WHERE dt.depth < 100 AND (dt1.semver_end IS NULL OR dt1.semver_end >= $2)
		)
		SELECT * FROM dependency_tree;`, asset.ID, version).Scan(&components).Error
	}

	if err != nil {
		return nil, err
	}
	return components, err
}

func (c *componentRepository) FindByPurl(tx database.DB, purl string) (models.Component, error) {
	var component models.Component
	err := c.GetDB(tx).Where("purl_or_cpe = ?", purl).First(&component).Error
	return component, err
}

func (c *componentRepository) HandleStateDiff(tx database.DB, assetID uuid.UUID, version string, oldState []models.ComponentDependency, newState []models.ComponentDependency) error {
	comparison := utils.CompareSlices(oldState, newState, func(dep models.ComponentDependency) string {
		return dep.ComponentPurlOrCpe + "->" + dep.DependencyPurlOrCpe
	})

	removed := comparison.OnlyInA
	added := comparison.OnlyInB

	return c.GetDB(tx).Transaction(func(tx *gorm.DB) error {
		if err := c.UpdateSemverEnd(tx, utils.Map(removed, func(el models.ComponentDependency) uuid.UUID {
			return el.ID
		}), version); err != nil {
			return err
		}
		// make sure the asset id is set
		for i := range added {
			added[i].AssetID = assetID
		}

		return c.CreateAssetComponents(tx, added)
	})
}
