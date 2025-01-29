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

type assetRepository struct {
	db database.DB
	Repository[uuid.UUID, models.AssetNew, core.DB]
}

func NewAssetRepository(db core.DB) *assetRepository {
	err := db.AutoMigrate(&models.AssetNew{})
	if err != nil {
		panic(err)
	}

	return &assetRepository{
		db:         db,
		Repository: newGormRepository[uuid.UUID, models.AssetNew](db),
	}
}

func (a *assetRepository) FindByName(name string) (models.AssetNew, error) {
	var app models.AssetNew
	err := a.db.Where("name = ?", name).First(&app).Error
	if err != nil {
		return app, err
	}
	return app, nil
}

func (a *assetRepository) FindOrCreate(tx core.DB, name string) (models.AssetNew, error) {
	app, err := a.FindByName(name)
	if err != nil {
		app = models.AssetNew{Name: name}
		err = a.Create(tx, &app)
		if err != nil {
			return app, err
		}
	}
	return app, nil
}

func (a *assetRepository) GetByAssetID(assetID uuid.UUID) (models.AssetNew, error) {
	var app models.AssetNew
	err := a.db.Where("asset_id = ?", assetID).First(&app).Error
	if err != nil {
		return models.AssetNew{}, err
	}
	return app, nil
}

func (a *assetRepository) GetByProjectID(projectID uuid.UUID) ([]models.AssetNew, error) {
	var apps []models.AssetNew
	err := a.db.Where("project_id = ?", projectID).Find(&apps).Error
	if err != nil {
		return nil, err
	}
	return apps, nil
}

func (a *assetRepository) GetByProjectIDs(projectIDs []uuid.UUID) ([]models.AssetNew, error) {
	var apps []models.AssetNew
	err := a.db.Where("project_id IN (?)", projectIDs).Find(&apps).Error
	if err != nil {
		return nil, err
	}
	return apps, nil
}

func (g *assetRepository) ReadBySlug(projectID uuid.UUID, slug string) (models.AssetNew, error) {
	var t models.AssetNew
	err := g.db.Where("slug = ? AND project_id = ?", slug, projectID).First(&t).Error
	return t, err
}

func (g *assetRepository) ReadBySlugUnscoped(projectID uuid.UUID, slug string) (models.AssetNew, error) {
	var asset models.AssetNew
	err := g.db.Unscoped().Where("slug = ? AND project_id = ?", slug, projectID).First(&asset).Error
	return asset, err
}

func (g *assetRepository) GetAssetIDBySlug(projectID uuid.UUID, slug string) (uuid.UUID, error) {
	app, err := g.ReadBySlug(projectID, slug)
	if err != nil {
		return uuid.UUID{}, err
	}
	return app.ID, nil
}

func (g *assetRepository) Update(tx core.DB, asset *models.AssetNew) error {
	return g.db.Save(asset).Error
}

func (g *assetRepository) GetAllAssetsFromDB() ([]models.AssetNew, error) {
	var assets []models.AssetNew
	err := g.db.Find(&assets).Error
	return assets, err
}
