// Copyright (C) 2023 Tim Bastin, l3montree GmbH
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
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/google/uuid"
	"github.com/gosimple/slug"
	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
)

type assetVersionRepository struct {
	db core.DB
	common.Repository[uuid.UUID, models.AssetVersion, core.DB]
}

func NewAssetVersionRepository(db core.DB) *assetVersionRepository {
	if os.Getenv("DISABLE_AUTOMIGRATE") != "true" {
		err := db.AutoMigrate(&models.AssetVersion{})
		if err != nil {
			panic(err)
		}
	}

	return &assetVersionRepository{
		db:         db,
		Repository: newGormRepository[uuid.UUID, models.AssetVersion](db),
	}
}

func (a *assetVersionRepository) All() ([]models.AssetVersion, error) {
	var result []models.AssetVersion

	err := a.db.Model(models.AssetVersion{}).Preload("Asset").Find(&result).Error
	return result, err
}

func (a *assetVersionRepository) Read(assetVersionName string, assetID uuid.UUID) (models.AssetVersion, error) {
	var asset models.AssetVersion
	err := a.db.First(&asset, "name = ? AND asset_id = ?", assetVersionName, assetID).Error
	return asset, err
}

func (a *assetVersionRepository) Delete(tx core.DB, assetVersion *models.AssetVersion) error {
	err := a.db.Delete(assetVersion).Error //Call db delete function with the provided asset version
	if err != nil {
		slog.Error("error when deleting asset in database", "err", err)
		return err
	}
	return err

}

func (a *assetVersionRepository) FindByName(name string) (models.AssetVersion, error) {
	var app models.AssetVersion
	err := a.db.Where("name = ?", name).First(&app).Error
	if err != nil {
		return app, err
	}
	return app, nil
}

func (a *assetVersionRepository) findByAssetVersionNameAndAssetID(name string, assetID uuid.UUID) (models.AssetVersion, error) {
	var app models.AssetVersion
	err := a.db.Where("name = ? AND asset_id = ?", name, assetID).First(&app).Error
	if err != nil {
		return app, err
	}
	return app, nil
}

func (a *assetVersionRepository) FindOrCreate(assetVersionName string, assetID uuid.UUID, isTag bool, defaultBranchName *string) (models.AssetVersion, error) {
	var assetVersion models.AssetVersion
	assetVersion, err := a.findByAssetVersionNameAndAssetID(assetVersionName, assetID)
	if err != nil {
		var assetVersionType models.AssetVersionType
		if isTag {
			assetVersionType = "tag"
		} else {
			assetVersionType = "branch"
		}

		assetVersion = models.AssetVersion{
			Name:    assetVersionName,
			AssetID: assetID,
			Slug:    slug.Make(assetVersionName),
			Type:    assetVersionType,
		}

		if assetVersion.Name == "" || assetVersion.Slug == "" {
			return assetVersion, fmt.Errorf("assetVersions with an empty name or an empty slug are not allowed")
		}

		err := a.db.Create(&assetVersion).Error
		//Check if the given assetVersion already exists if thats the case don't want to add a new entry to the db but instead update the existing one
		if err != nil && strings.Contains(err.Error(), "duplicate key value violates") {
			a.db.Unscoped().Model(&assetVersion).Where("name", assetVersionName).Update("deleted_at", nil) //Update 'deleted_at' to NULL to revert the previous soft delete
		} else if err != nil {
			return models.AssetVersion{}, err
		}
	}

	// check if defaultBranchName is defined
	if defaultBranchName != nil {
		assetVersion.DefaultBranch = *defaultBranchName == assetVersion.Name
		// update the asset version with this branch name and set defaultBranch to true - if there is no asset version with this name just ignore
		if err := a.updateAssetDefaultBranch(assetID, *defaultBranchName); err != nil {
			slog.Error("error updating asset default branch", "err", err, "assetID", assetID, "defaultBranchName", defaultBranchName)
			// just swallow the error here - we don't want to fail the whole operation if we can't set the default branch
		}
	}

	return assetVersion, nil
}

func (a *assetVersionRepository) updateAssetDefaultBranch(assetID uuid.UUID, defaultBranch string) error {
	return a.db.Transaction(func(tx core.DB) error {
		// reset the default branch for all versions of this asset
		if err := tx.Model(&models.AssetVersion{}).Where("asset_id = ?", assetID).Update("default_branch", false).Error; err != nil {
			slog.Error("error resetting default branch for asset versions", "err", err, "assetID", assetID)
			return err
		}
		// update the specific asset version to be the default branch
		if err := tx.Model(&models.AssetVersion{}).Where("name = ? AND asset_id = ?", defaultBranch, assetID).
			Update("default_branch", true).Error; err != nil {
			slog.Error("error setting default branch for asset version", "err", err, "assetVersionName", defaultBranch, "assetID", assetID)
			return err
		}
		return nil
	})
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

func (a *assetVersionRepository) GetDefaultAssetVersion(assetID uuid.UUID) (models.AssetVersion, error) {
	var app models.AssetVersion
	err := a.db.Model(&models.AssetVersion{}).Where("default_branch = true AND asset_id = ?", assetID).First(&app).Error
	return app, err
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

func (g *assetVersionRepository) DeleteOldAssetVersions(day int) (int64, error) {

	interval := fmt.Sprintf("INTERVAL '%d days'", day)
	query := fmt.Sprintf("updated_at < NOW() - %s AND default_branch = false", interval)

	var count int64
	count = 0
	err := g.db.Model(&models.AssetVersion{}).
		Where(query).
		Count(&count).Error
	if err != nil {
		return 0, err
	}

	if count > 0 {
		err = g.db.Unscoped().Where(query).
			Delete(&models.AssetVersion{}).Error
		if err != nil {
			return 0, err
		}
	}

	return count, nil
}
