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
	"strings"

	"github.com/google/uuid"
	"github.com/gosimple/slug"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"gorm.io/gorm"
)

type assetVersionRepository struct {
	db *gorm.DB
	utils.Repository[uuid.UUID, models.AssetVersion, *gorm.DB]
}

func NewAssetVersionRepository(db *gorm.DB) *assetVersionRepository {
	return &assetVersionRepository{
		db:         db,
		Repository: newGormRepository[uuid.UUID, models.AssetVersion](db),
	}
}

var _ shared.AssetVersionRepository = (*assetVersionRepository)(nil)

func (repository *assetVersionRepository) All() ([]models.AssetVersion, error) {
	var result []models.AssetVersion

	err := repository.db.Model(models.AssetVersion{}).Preload("Asset").Find(&result).Error
	return result, err
}

func (repository *assetVersionRepository) Read(assetVersionName string, assetID uuid.UUID) (models.AssetVersion, error) {
	var asset models.AssetVersion
	err := repository.db.First(&asset, "name = ? AND asset_id = ?", assetVersionName, assetID).Error
	return asset, err
}

func (repository *assetVersionRepository) Delete(tx *gorm.DB, assetVersion *models.AssetVersion) error {
	// Use a transaction to ensure both artifact deletion and asset version deletion succeed or fail together
	return repository.GetDB(tx).Transaction(func(dbTx *gorm.DB) error {
		// First, explicitly delete all related artifacts to ensure proper cleanup
		if err := dbTx.Where("asset_version_name = ? AND asset_id = ?", assetVersion.Name, assetVersion.AssetID).Delete(&models.Artifact{}).Error; err != nil {
			slog.Error("error deleting artifacts for asset version", "err", err, "assetVersion", assetVersion.Name)
			return err
		}

		// Delete the asset version itself - this will cascade to delete other related records
		if err := dbTx.Delete(assetVersion).Error; err != nil {
			slog.Error("error when deleting asset version in database", "err", err, "assetVersion", assetVersion.Name)
			return err
		}

		go func() {
			sql := CleanupOrphanedRecordsSQL
			err := repository.db.Exec(sql).Error
			if err != nil {
				slog.Error("Failed to clean up orphaned records after deleting artifact", "err", err)
			}
		}() //nolint:errcheck
		slog.Info("successfully deleted asset version and all related artifacts", "assetVersion", assetVersion.Name)
		return nil
	})
}

func (repository *assetVersionRepository) FindByName(name string) (models.AssetVersion, error) {
	var app models.AssetVersion
	err := repository.db.Where("name = ?", name).First(&app).Error
	if err != nil {
		return app, err
	}
	return app, nil
}

func (repository *assetVersionRepository) findByAssetVersionNameAndAssetID(name string, assetID uuid.UUID) (models.AssetVersion, error) {
	var app models.AssetVersion
	err := repository.db.Where("name = ? AND asset_id = ?", name, assetID).First(&app).Error
	if err != nil {
		return app, err
	}
	return app, nil
}

func (repository *assetVersionRepository) FindOrCreate(assetVersionName string, assetID uuid.UUID, isTag bool, defaultBranchName *string) (models.AssetVersion, error) {
	var assetVersion models.AssetVersion
	assetVersion, err := repository.findByAssetVersionNameAndAssetID(assetVersionName, assetID)
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

		err := repository.db.Create(&assetVersion).Error
		//Check if the given assetVersion already exists if thats the case don't want to add repository new entry to the db but instead update the existing one
		if err != nil && strings.Contains(err.Error(), "duplicate key value violates") {
			repository.db.Unscoped().Model(&assetVersion).Where("name", assetVersionName)
		} else if err != nil {
			return models.AssetVersion{}, err
		}
	}

	// check if defaultBranchName is defined
	if defaultBranchName != nil {
		assetVersion.DefaultBranch = *defaultBranchName == assetVersion.Name
		// update the asset version with this branch name and set defaultBranch to true - if there is no asset version with this name just ignore
		if err := repository.UpdateAssetDefaultBranch(assetID, *defaultBranchName); err != nil {
			slog.Error("error updating asset default branch", "err", err, "assetID", assetID, "defaultBranchName", defaultBranchName)
			// just swallow the error here - we don't want to fail the whole operation if we can't set the default branch
		}
	}

	return assetVersion, nil
}

func (repository *assetVersionRepository) UpdateAssetDefaultBranch(assetID uuid.UUID, defaultBranch string) error {
	return repository.db.Transaction(func(tx *gorm.DB) error {
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

func (repository *assetVersionRepository) GetDefaultAssetVersionsByProjectID(projectID uuid.UUID) ([]models.AssetVersion, error) {
	var apps []models.AssetVersion
	err := repository.db.Joins("JOIN assets ON assets.id = asset_versions.asset_id").Where("default_branch = true").
		Joins("JOIN projects ON projects.id = assets.project_id").
		Where("projects.id = ?", projectID).
		Find(&apps).Error
	if err != nil {
		return nil, err
	}
	return apps, nil
}

func (repository *assetVersionRepository) GetDefaultAssetVersion(assetID uuid.UUID) (models.AssetVersion, error) {
	var app models.AssetVersion
	err := repository.db.Model(&models.AssetVersion{}).Where("default_branch = true AND asset_id = ?", assetID).First(&app).Error
	return app, err
}

func (repository *assetVersionRepository) GetDefaultAssetVersionsByProjectIDs(projectIDs []uuid.UUID) ([]models.AssetVersion, error) {
	var apps []models.AssetVersion
	err := repository.db.Joins("JOIN assets ON assets.id = asset_versions.asset_id").
		Joins("JOIN projects ON projects.id = assets.project_id").
		Where("default_branch = true").
		Where("projects.id IN (?)", projectIDs).
		Find(&apps).Error
	if err != nil {
		return nil, err
	}
	return apps, nil
}

func (repository *assetVersionRepository) ReadBySlug(AssetID uuid.UUID, slug string) (models.AssetVersion, error) {
	var t models.AssetVersion
	err := repository.db.Where("slug = ? AND asset_id = ?", slug, AssetID).First(&t).Error
	return t, err
}

func (repository *assetVersionRepository) ReadBySlugUnscoped(projectID uuid.UUID, slug string) (models.AssetVersion, error) {
	var asset models.AssetVersion
	err := repository.db.Unscoped().Where("slug = ? AND project_id = ?", slug, projectID).First(&asset).Error
	return asset, err
}

/* func (repository *assetVersionRepository) GetAssetVersionIDBySlug(projectID uuid.UUID, slug string) (uuid.UUID, error) {
	app, err := repository.ReadBySlug(projectID, slug)
	if err != nil {
		return uuid.UUID{}, err
	}
	return app.ID, nil
} */

func (repository *assetVersionRepository) Update(tx *gorm.DB, asset *models.AssetVersion) error {
	return repository.db.Save(asset).Error
}

func (repository *assetVersionRepository) GetAllAssetsVersionFromDB(tx *gorm.DB) ([]models.AssetVersion, error) {
	var assets []models.AssetVersion
	err := repository.db.Find(&assets).Error
	return assets, err
}

func (repository *assetVersionRepository) GetAssetVersionsByAssetID(tx *gorm.DB, assetID uuid.UUID) ([]models.AssetVersion, error) {
	var assets []models.AssetVersion
	err := repository.db.Where("asset_id = ?", assetID).Find(&assets).Error
	return assets, err
}

func (repository *assetVersionRepository) GetAssetVersionsByAssetIDWithArtifacts(tx *gorm.DB, assetID uuid.UUID) ([]models.AssetVersion, error) {
	var assetVersion []models.AssetVersion
	err := repository.db.Preload("Artifacts").Where("asset_id = ?", assetID).Find(&assetVersion).Error
	return assetVersion, err
}

func (repository *assetVersionRepository) DeleteOldAssetVersions(day int) (int64, error) {
	//this is not exploitable because the day is an int and golang is statically typed
	interval := fmt.Sprintf("INTERVAL '%d days'", day)
	query := fmt.Sprintf("last_accessed_at < NOW() - %s AND default_branch = false AND type = 'branch'", interval)

	var count int64
	err := repository.db.Model(&models.AssetVersion{}).
		Where(query).
		Count(&count).Error
	if err != nil {
		return 0, err
	}

	if count > 0 {
		// Use a transaction to ensure both artifact deletion and asset version deletion succeed or fail together
		err = repository.db.Transaction(func(tx *gorm.DB) error {
			// Delete all artifacts for the asset versions being deleted in a single query
			artifactDeleteQuery := `
				DELETE FROM artifacts 
				WHERE (asset_version_name, asset_id) IN (
					SELECT name, asset_id 
					FROM asset_versions 
					WHERE last_accessed_at < NOW() - INTERVAL '` + fmt.Sprintf("%d", day) + ` days' 
					AND default_branch = false 
					AND type = 'branch'
				)`

			if err := tx.Exec(artifactDeleteQuery).Error; err != nil {
				slog.Error("error deleting artifacts for old asset versions", "err", err)
				return err
			}

			// Now delete the asset versions, which should cascade to delete other related records
			if err := tx.Unscoped().Where(query).Delete(&models.AssetVersion{}).Error; err != nil {
				slog.Error("error deleting old asset versions", "err", err)
				return err
			}

			return nil
		})

		if err != nil {
			return 0, err
		}
		go func() {
			sql := CleanupOrphanedRecordsSQL
			err = repository.db.Exec(sql).Error
			if err != nil {
				slog.Error("Failed to clean up orphaned records after deleting artifact", "err", err)
			}
		}() //nolint:errcheck

	}

	return count, nil
}

func (repository *assetVersionRepository) DeleteOldAssetVersionsOfAsset(assetID uuid.UUID, day int) (int64, error) {

	//this is not exploitable because the day is an int and golang is statically typed
	interval := fmt.Sprintf("INTERVAL '%d days'", day)
	query := fmt.Sprintf("last_accessed_at < NOW() - %s AND default_branch = false AND type = 'branch' AND asset_id = ?", interval)

	var count int64
	err := repository.db.Model(&models.AssetVersion{}).
		Where(query, assetID).
		Count(&count).Error
	if err != nil {
		return 0, err
	}

	if count > 0 {

		// Use a transaction to ensure both artifact deletion and asset version deletion succeed or fail together
		err = repository.db.Transaction(func(tx *gorm.DB) error {
			// Delete all artifacts for the asset versions being deleted in a single query
			artifactDeleteQuery := `
				DELETE FROM artifacts 
				WHERE (asset_version_name, asset_id) IN (
					SELECT name, asset_id 
					FROM asset_versions 
					WHERE last_accessed_at < NOW() - INTERVAL '` + fmt.Sprintf("%d", day) + ` days' 
					AND default_branch = false 
					AND type = 'branch'
					AND asset_id = ?
				)`

			if err := tx.Exec(artifactDeleteQuery, assetID).Error; err != nil {
				slog.Error("error deleting artifacts for old asset versions", "err", err)
				return err
			}

			// Now delete the asset versions, which should cascade to delete other related records
			if err := tx.Unscoped().Where(query, assetID).Delete(&models.AssetVersion{}).Error; err != nil {
				slog.Error("error deleting old asset versions", "err", err)
				return err
			}

			return nil
		})

		if err != nil {
			return 0, err
		}
		go func() {
			sql := CleanupOrphanedRecordsSQL
			err = repository.db.Exec(sql).Error
			if err != nil {
				slog.Error("Failed to clean up orphaned records after deleting artifact", "err", err)
			}
		}() //nolint:errcheck
	}
	return count, nil
}

func (repository *assetVersionRepository) GetAllTagsAndDefaultBranchForAsset(tx *gorm.DB, assetID uuid.UUID) ([]models.AssetVersion, error) {
	var assetVersions []models.AssetVersion
	err := repository.Repository.GetDB(tx).Raw("SELECT * FROM asset_versions WHERE asset_id = ? AND (default_branch = true OR type = 'tag')", assetID).Find(&assetVersions).Error
	if err != nil {
		return nil, err
	}
	return assetVersions, nil
}
