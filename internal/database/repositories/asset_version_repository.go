// Copyright (C) 2023 Tim Bastin, l3montree UG (haftungsbeschränkt)
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
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package repositories

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database"
	"github.com/l3montree-dev/devguard/internal/database/models"
)

type assetVersionRepository struct {
	db database.DB
	Repository[uuid.UUID, models.AssetVersion, core.DB]
}

func NewAssetVersionRepository(db core.DB) *assetVersionRepository {
	err := db.AutoMigrate(&models.AssetVersion{})
	if err != nil {
		panic(err)
	}

	return &assetVersionRepository{
		db:         db,
		Repository: newGormRepository[uuid.UUID, models.AssetVersion](db),
	}
}

func (a *assetVersionRepository) Read(assetVersionName string, assetID uuid.UUID) (models.AssetVersion, error) {
	var asset models.AssetVersion
	err := a.db.First(&asset, "name = ? AND asset_id = ?", assetVersionName, assetID).Error
	return asset, err
}

func (a *assetVersionRepository) FindByName(name string) (models.AssetVersion, error) {
	var app models.AssetVersion
	err := a.db.Where("name = ?", name).First(&app).Error
	if err != nil {
		return app, err
	}
	return app, nil
}

func (a *assetVersionRepository) FindOrCreate(assetVersionName string, assetID uuid.UUID, tag string, defaultBranchName string) (models.AssetVersion, error) {

	var defaultBranch bool
	if defaultBranchName == assetVersionName {
		defaultBranch = true
	}

	var app models.AssetVersion
	err := a.db.Where("name = ? AND asset_id = ?", assetVersionName, assetID).First(&app).Error
	if err != nil {
		var assetVersionType models.AssetVersionType
		if tag == "" {
			assetVersionType = "branch"
		} else {
			assetVersionType = "tag"
		}

		if err = a.db.Create(&models.AssetVersion{Name: assetVersionName, AssetID: assetID, Slug: assetVersionName, Type: assetVersionType, DefaultBranch: defaultBranch}).Error; err != nil {
			return models.AssetVersion{}, err
		}
		return a.FindOrCreate(assetVersionName, assetID, tag, defaultBranchName)
	}
	if app.DefaultBranch != defaultBranch {
		app.DefaultBranch = defaultBranch
		if err = a.db.Save(&app).Error; err != nil {
			return models.AssetVersion{}, err
		}

	}

	return app, nil
}

func (a *assetVersionRepository) GetDefaultAssetVersionsByProjectID(projectID uuid.UUID) ([]models.AssetVersion, error) {
	var apps []models.AssetVersion
	err := a.db.Joins("JOIN assets ON assets.id = asset_versions.asset_id").Where("default_branch = true").
		Joins("JOIN projects ON projects.id = assets.project_id").
		Where("projects.id = ?", projectID).
		Where("assets.deleted_at IS NULL").
		Find(&apps).Error
	if err != nil {
		return nil, err
	}
	return apps, nil
}

func (a *assetVersionRepository) GetDefaultAssetVersionsByProjectIDs(projectIDs []uuid.UUID) ([]models.AssetVersion, error) {
	var apps []models.AssetVersion
	err := a.db.Joins("JOIN assets ON assets.id = asset_versions.asset_id").
		Joins("JOIN projects ON projects.id = assets.project_id").
		Where("default_branch = true").
		Where("assets.deleted_at IS NULL").
		Where("projects.id IN (?)", projectIDs).
		Find(&apps).Error
	if err != nil {
		return nil, err
	}
	return apps, nil
}

func (g *assetVersionRepository) ReadBySlug(AssetID uuid.UUID, slug string) (models.AssetVersion, error) {
	var t models.AssetVersion
	err := g.db.Where("slug = ? AND asset_id = ?", slug, AssetID).First(&t).Error
	return t, err
}

func (g *assetVersionRepository) ReadBySlugUnscoped(projectID uuid.UUID, slug string) (models.AssetVersion, error) {
	var asset models.AssetVersion
	err := g.db.Unscoped().Where("slug = ? AND project_id = ?", slug, projectID).First(&asset).Error
	return asset, err
}

/* func (g *assetVersionRepository) GetAssetVersionIDBySlug(projectID uuid.UUID, slug string) (uuid.UUID, error) {
	app, err := g.ReadBySlug(projectID, slug)
	if err != nil {
		return uuid.UUID{}, err
	}
	return app.ID, nil
} */

func (g *assetVersionRepository) Update(tx core.DB, asset *models.AssetVersion) error {
	return g.db.Save(asset).Error
}

func (g *assetVersionRepository) GetAllAssetsVersionFromDB(tx core.DB) ([]models.AssetVersion, error) {
	var assets []models.AssetVersion
	err := g.db.Find(&assets).Error
	return assets, err
}

func (g *assetVersionRepository) GetAllAssetsVersionFromDBByAssetID(tx core.DB, assetID uuid.UUID) ([]models.AssetVersion, error) {
	var assets []models.AssetVersion
	err := g.db.Where("asset_id = ?", assetID).Find(&assets).Error
	return assets, err
}
