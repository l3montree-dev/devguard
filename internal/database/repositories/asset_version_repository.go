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

func (a *assetVersionRepository) FindByName(name string) (models.AssetVersion, error) {
	var app models.AssetVersion
	err := a.db.Where("name = ?", name).First(&app).Error
	if err != nil {
		return app, err
	}
	return app, nil
}

func (a *assetVersionRepository) FindOrCreate(tx core.DB, name string) (models.AssetVersion, error) {
	app, err := a.FindByName(name)
	if err != nil {
		app = models.AssetVersion{Name: name}
		err = a.Create(tx, &app)
		if err != nil {
			return app, err
		}
	}
	return app, nil
}

func (a *assetVersionRepository) GetByProjectID(projectID uuid.UUID) ([]models.AssetVersion, error) {
	var apps []models.AssetVersion
	err := a.db.Where("project_id = ?", projectID).Find(&apps).Error
	if err != nil {
		return nil, err
	}
	return apps, nil
}

func (a *assetVersionRepository) GetByProjectIDs(projectIDs []uuid.UUID) ([]models.AssetVersion, error) {
	var apps []models.AssetVersion
	err := a.db.Where("project_id IN (?)", projectIDs).Find(&apps).Error
	if err != nil {
		return nil, err
	}
	return apps, nil
}

func (g *assetVersionRepository) ReadBySlug(projectID uuid.UUID, slug string) (models.AssetVersion, error) {
	var t models.AssetVersion
	err := g.db.Where("slug = ? AND project_id = ?", slug, projectID).First(&t).Error
	return t, err
}

func (g *assetVersionRepository) ReadBySlugUnscoped(projectID uuid.UUID, slug string) (models.AssetVersion, error) {
	var asset models.AssetVersion
	err := g.db.Unscoped().Where("slug = ? AND project_id = ?", slug, projectID).First(&asset).Error
	return asset, err
}

func (g *assetVersionRepository) GetAssetIDBySlug(projectID uuid.UUID, slug string) (uuid.UUID, error) {
	app, err := g.ReadBySlug(projectID, slug)
	if err != nil {
		return uuid.UUID{}, err
	}
	return app.ID, nil
}

func (g *assetVersionRepository) Update(tx core.DB, asset *models.AssetVersion) error {
	return g.db.Save(asset).Error
}

func (g *assetVersionRepository) GetAllAssetsFromDB() ([]models.AssetVersion, error) {
	var assets []models.AssetVersion
	err := g.db.Find(&assets).Error
	return assets, err
}
