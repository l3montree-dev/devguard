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
	"os"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
)

type assetRepository struct {
	db core.DB
	common.Repository[uuid.UUID, models.Asset, core.DB]
}

func NewAssetRepository(db core.DB) *assetRepository {
	if os.Getenv("DISABLE_AUTOMIGRATE") != "true" {
		err := db.AutoMigrate(&models.Asset{})
		if err != nil {
			panic(err)
		}
	}

	return &assetRepository{
		db:         db,
		Repository: newGormRepository[uuid.UUID, models.Asset](db),
	}
}

func (r *assetRepository) FindAssetByExternalProviderId(externalEntityProviderID string, externalEntityID string) (*models.Asset, error) {
	var asset models.Asset
	err := r.db.Where("external_entity_provider_id = ? AND external_entity_id = ?", externalEntityProviderID, externalEntityID).First(&asset).Error
	return &asset, err
}

func (a *assetRepository) GetFQNByID(id uuid.UUID) (string, error) {
	var fqn struct {
		FQN string `gorm:"column:fqn"`
	}
	// the fully qualified name (FQN) is the slug of the asset - including the project slug and the organization slug
	// using the fqn an asset is addressable through the API
	err := a.db.Model(&models.Asset{}).
		Select("CONCAT(organizations.slug, '/', projects.slug, '/', assets.slug) AS fqn").
		Joins("JOIN projects ON assets.project_id = projects.id").
		Joins("JOIN organizations ON projects.organization_id = organizations.id").
		Where("assets.id = ?", id).
		First(&fqn).Error
	if err != nil {
		return "", err
	}
	return fqn.FQN, nil
}

func (a *assetRepository) FindByName(name string) (models.Asset, error) {
	var app models.Asset
	err := a.db.Where("name = ?", name).First(&app).Error
	if err != nil {
		return app, err
	}
	return app, nil
}

func (a *assetRepository) FindOrCreate(tx core.DB, name string) (models.Asset, error) {
	app, err := a.FindByName(name)
	if err != nil {
		app = models.Asset{Name: name}
		err = a.Create(tx, &app)
		if err != nil {
			return app, err
		}
	}
	return app, nil
}

func (a *assetRepository) GetByProjectID(projectID uuid.UUID) ([]models.Asset, error) {
	var apps []models.Asset
	err := a.db.Where("project_id = ?", projectID).Find(&apps).Error
	if err != nil {
		return nil, err
	}
	return apps, nil
}

func (a *assetRepository) GetByOrgID(orgID uuid.UUID) ([]models.Asset, error) {
	var apps []models.Asset
	err := a.db.Where("project_id IN (SELECT id from projects where organization_id = ?)", orgID).Preload("AssetVersions").Find(&apps).Error
	if err != nil {
		return nil, err
	}
	return apps, nil
}

func (a *assetRepository) GetByProjectIDs(projectIDs []uuid.UUID) ([]models.Asset, error) {
	var apps []models.Asset
	err := a.db.Where("project_id IN (?)", projectIDs).Find(&apps).Error
	if err != nil {
		return nil, err
	}
	return apps, nil
}

func (g *assetRepository) ReadBySlug(projectID uuid.UUID, slug string) (models.Asset, error) {
	var t models.Asset
	err := g.db.Where("slug = ? AND project_id = ?", slug, projectID).Preload("AssetVersions").First(&t).Error
	return t, err
}

func (g *assetRepository) ReadBySlugUnscoped(projectID uuid.UUID, slug string) (models.Asset, error) {
	var asset models.Asset
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

func (g *assetRepository) Update(tx core.DB, asset *models.Asset) error {
	return g.db.Save(asset).Error
}

func (g *assetRepository) GetAllAssetsFromDB() ([]models.Asset, error) {
	var assets []models.Asset
	err := g.db.Preload("AssetVersions").Find(&assets).Error
	return assets, err
}

func (g *assetRepository) GetAssetByAssetVersionID(assetVersionID uuid.UUID) (models.Asset, error) {
	var asset models.Asset
	err := g.db.Model(&models.AssetVersion{}).
		Select("assets.*").
		Joins("JOIN assets ON assets.id = asset_versions.asset_id").
		Where("asset_versions.id = ?", assetVersionID).
		First(&asset).Error
	return asset, err
}

func (g *assetRepository) Delete(tx core.DB, id uuid.UUID) error {
	asset := models.Asset{Model: models.Model{ID: id}}
	return g.db.Select("AssetVersions").Delete(&asset).Error
}

func (g *assetRepository) GetAssetIDByBadgeSecret(badgeSecret uuid.UUID) (models.Asset, error) {
	var asset models.Asset
	err := g.db.Debug().Where("badge_secret = ?", badgeSecret).First(&asset).Error
	if err != nil {
		return models.Asset{}, err
	}
	return asset, nil
}

func (g *assetRepository) ReadWithAssetVersions(assetID uuid.UUID) (models.Asset, error) {
	var asset models.Asset
	err := g.db.Preload("AssetVersions").Where("id = ?", assetID).First(&asset).Error
	if err != nil {
		return models.Asset{}, err
	}
	return asset, nil
}
