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

func (c *componentRepository) UpdateSemverEnd(tx core.DB, ids []uuid.UUID, version *string) error {
	if len(ids) == 0 {
		return nil
	}

	return c.GetDB(tx).Model(&models.ComponentDependency{}).Where("id IN ?", ids).Update("semver_end", version).Error
}

func (c *componentRepository) CreateComponents(tx core.DB, components []models.ComponentDependency) error {
	if len(components) == 0 {
		return nil
	}

	return c.GetDB(tx).Create(&components).Error
}

func (c *componentRepository) LoadComponents(tx core.DB, assetVersionName string, assetID uuid.UUID, scannerID, version string) ([]models.ComponentDependency, error) {
	var components []models.ComponentDependency
	var err error

	query := c.GetDB(tx).Preload("Component").Preload("Dependency").Where("asset_version_name = ? AND asset_id = ?", assetVersionName, assetID)

	if scannerID != "" {
		query = query.Where("scanner_id = ?", scannerID)
	}

	if version == models.NoVersion || version == "" {
		err = query.Where("semver_end is NULL").Find(&components).Error
	} else {
		err = query.Where("semver_start <= ? AND (semver_end >= ? OR semver_end IS NULL)", version, version).Find(&components).Error
	}

	if err != nil {
		return nil, err
	}

	return components, err
}

func (c *componentRepository) LoadComponentsWithProject(tx core.DB, assetVersionName string, assetID uuid.UUID, scanner, version string, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery) (core.Paged[models.ComponentDependency], error) {
	var components []models.ComponentDependency

	query := c.GetDB(tx).Model(&models.ComponentDependency{}).Preload("Component").Preload("Component.ComponentProject").Where("asset_version_name = ? AND asset_id = ?", assetVersionName, assetID)

	if scanner != "" {
		query = query.Where("scanner_id = ?", scanner)
	}

	if version == models.NoVersion || version == "" {
		query = query.Where("semver_end is NULL")
	} else {
		query = query.Where("semver_start <= ? AND (semver_end >= ? OR semver_end IS NULL)", version, version)
	}

	for _, f := range filter {
		query = query.Where(f.SQL(), f.Value())
	}

	if len(sort) > 0 {
		for _, s := range sort {
			query = query.Order(s.SQL())
		}
	}

	if search != "" {
		query = query.Where("component_purl ILIKE ?", "pkg:%"+search+"%")
	} else {
		query = query.Where("component_purl ILIKE ?", "pkg:%")
	}

	var total int64
	query.Session(&gorm.Session{}).Select("COUNT(DISTINCT component_purl)").Count(&total)

	err := query.Select("DISTINCT ON (component_purl) *").Limit(pageInfo.PageSize).Offset((pageInfo.Page - 1) * pageInfo.PageSize).Find(&components).Error

	return core.NewPaged(pageInfo, total, components), err
}

func (c *componentRepository) LoadAllLatestComponentFromAssetVersion(tx core.DB, assetVersion models.AssetVersion, scannerID string) ([]models.ComponentDependency, error) {
	var component []models.ComponentDependency
	err := c.GetDB(tx).Preload("Component").Preload("Dependency").Where("asset_version_name = ? AND asset_id AND scanner_id = ? AND semver_end is NULL", assetVersion.Name, assetVersion.AssetID).Find(&component).Error
	return component, err
}

func (c *componentRepository) GetVersions(tx core.DB, assetVersion models.AssetVersion) ([]string, error) {
	var versions []string
	err := c.GetDB(tx).Model(&models.ComponentDependency{}).Where("asset_version_name = ? AND asset_id = ?", assetVersion.Name, assetVersion.AssetID).Distinct("semver_start").Pluck("semver_start", &versions).Error
	return versions, err
}

func (c *componentRepository) FindByPurl(tx core.DB, purl string) (models.Component, error) {
	var component models.Component
	err := c.GetDB(tx).Where("purl = ?", purl).First(&component).Error
	return component, err
}

func (c *componentRepository) HandleStateDiff(tx core.DB, assetVersionName string, assetID uuid.UUID, version string, oldState []models.ComponentDependency, newState []models.ComponentDependency) error {
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
			added[i].AssetVersionName = assetVersionName
		}

		return c.CreateComponents(tx, added)
	})
}

func (c *componentRepository) GetDependencyCountPerScanner(assetVersionName string, assetID uuid.UUID) (map[string]int, error) {
	var results []struct {
		ScannerID string `gorm:"column:scanner_id"`
		Count     int    `gorm:"column:count"`
	}
	err := c.db.Model(&models.Component{}).
		Select("scanner_id , COUNT(*) as count").
		Group("scanner_id").
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
