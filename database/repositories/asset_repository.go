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

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/common"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/lib/pq"
	"gorm.io/gorm/clause"
)

type assetRepository struct {
	db shared.DB
	common.Repository[uuid.UUID, models.Asset, shared.DB]
}

func NewAssetRepository(db shared.DB) *assetRepository {
	return &assetRepository{
		db:         db,
		Repository: newGormRepository[uuid.UUID, models.Asset](db),
	}
}

func (repository *assetRepository) prepareUniqueSlugs(projectID uuid.UUID, assets []*models.Asset) error {
	if len(assets) == 0 {
		return nil
	}

	// Collect slug base patterns for LIKE search
	patterns := make([]string, 0, len(assets))

	for _, p := range assets {
		patterns = append(patterns, p.Slug+"%")
	}

	// Fetch existing slugs safely using ANY()
	var existing []*models.Asset
	err := repository.db.Model(&models.Asset{}).
		Where("project_id = ? AND slug LIKE ANY(?)", projectID, pq.Array(patterns)).Find(&existing).Error
	if err != nil {
		return err
	}

	// Inject unique slugs into the projects
	if err := injectUniqueSlugs(existing, assets); err != nil {
		return fmt.Errorf("failed to inject unique slugs: %w", err)
	}

	return nil
}

func (repository *assetRepository) Upsert(t *[]*models.Asset, conflictingColumns []clause.Column, updateOnly []string) error {
	if len(*t) == 0 {
		return nil
	}

	err := repository.prepareUniqueSlugs((*t)[0].ProjectID, *t)
	if err != nil {
		return fmt.Errorf("failed to prepare unique slugs: %w", err)
	}

	if len(conflictingColumns) == 0 {
		if len(updateOnly) > 0 {
			return repository.db.Clauses(clause.OnConflict{DoUpdates: clause.AssignmentColumns(updateOnly)}).Create(t).Error
		}
		return repository.db.Clauses(clause.OnConflict{UpdateAll: true}).Create(t).Error
	}

	if len(updateOnly) > 0 {
		return repository.db.Clauses(clause.OnConflict{
			DoUpdates: clause.AssignmentColumns(updateOnly),
			Columns:   conflictingColumns,
		}).Create(t).Error
	}

	return repository.db.Clauses(clause.OnConflict{UpdateAll: true, Columns: conflictingColumns}).Create(t).Error
}

func (repository *assetRepository) Create(db shared.DB, asset *models.Asset) error {
	// get the next slug for the asset
	firstFreeSlug, err := repository.firstFreeSlug(asset.ProjectID, asset.Slug)
	if err != nil {
		return fmt.Errorf("failed to get next slug: %w", err)
	}
	asset.Slug = firstFreeSlug

	if err := repository.GetDB(db).Create(asset).Error; err != nil {
		return err
	}
	return nil
}

func (repository *assetRepository) Save(db shared.DB, asset *models.Asset) error {
	if asset.ID == uuid.Nil {
		// get the next slug for the asset
		firstFreeSlug, err := repository.firstFreeSlug(asset.ProjectID, asset.Slug)
		if err != nil {
			return fmt.Errorf("failed to get next slug: %w", err)
		}
		asset.Slug = firstFreeSlug
	}

	if err := repository.GetDB(db).Save(asset).Error; err != nil {
		return err
	}
	return nil
}

func (repository *assetRepository) FindAssetByExternalProviderID(externalEntityProviderID string, externalEntityID string) (*models.Asset, error) {
	var asset models.Asset
	err := repository.db.Where("external_entity_provider_id = ? AND external_entity_id = ?", externalEntityProviderID, externalEntityID).First(&asset).Error
	return &asset, err
}

func (repository *assetRepository) GetFQNByID(id uuid.UUID) (string, error) {
	var fqn struct {
		FQN string `gorm:"column:fqn"`
	}
	// the fully qualified name (FQN) is the slug of the asset - including the project slug and the organization slug
	// using the fqn an asset is addressable through the API
	err := repository.db.Model(&models.Asset{}).
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

func (repository *assetRepository) FindByName(name string) (models.Asset, error) {
	var app models.Asset
	err := repository.db.Where("name = ?", name).First(&app).Error
	if err != nil {
		return app, err
	}
	return app, nil
}

func (repository *assetRepository) GetAllowedAssetsByProjectID(allowedAssetIDs []string, projectID uuid.UUID) ([]models.Asset, error) {
	var apps []models.Asset
	err := repository.db.Where("project_id = ? AND id IN (?)", projectID, allowedAssetIDs).Or("project_id = ? AND is_public = true", projectID).Find(&apps).Error
	if err != nil {
		return nil, err
	}
	return apps, nil
}

func (repository *assetRepository) GetByProjectID(projectID uuid.UUID) ([]models.Asset, error) {
	var apps []models.Asset
	err := repository.db.Where("project_id = ?", projectID).Find(&apps).Error
	if err != nil {
		return nil, err
	}
	return apps, nil
}

func (repository *assetRepository) GetByOrgID(orgID uuid.UUID) ([]models.Asset, error) {
	var apps []models.Asset
	err := repository.db.Where("project_id IN (SELECT id from projects where organization_id = ?)", orgID).Preload("AssetVersions").Find(&apps).Error
	if err != nil {
		return nil, err
	}
	return apps, nil
}

func (repository *assetRepository) GetByProjectIDs(projectIDs []uuid.UUID) ([]models.Asset, error) {
	var apps []models.Asset
	err := repository.db.Where("project_id IN (?)", projectIDs).Find(&apps).Error
	if err != nil {
		return nil, err
	}
	return apps, nil
}

func (repository *assetRepository) ReadBySlug(projectID uuid.UUID, slug string) (models.Asset, error) {
	var t models.Asset
	err := repository.db.Where("slug = ? AND project_id = ?", slug, projectID).Preload("AssetVersions").First(&t).Error
	return t, err
}

func (repository *assetRepository) ReadBySlugUnscoped(projectID uuid.UUID, slug string) (models.Asset, error) {
	var asset models.Asset
	err := repository.db.Unscoped().Where("slug = ? AND project_id = ?", slug, projectID).First(&asset).Error
	return asset, err
}

func (repository *assetRepository) GetAssetIDBySlug(projectID uuid.UUID, slug string) (uuid.UUID, error) {
	app, err := repository.ReadBySlug(projectID, slug)
	if err != nil {
		return uuid.UUID{}, err
	}
	return app.ID, nil
}

func (repository *assetRepository) Update(tx shared.DB, asset *models.Asset) error {
	return repository.db.Save(asset).Error
}

func (repository *assetRepository) GetAllAssetsFromDB() ([]models.Asset, error) {
	var assets []models.Asset
	err := repository.db.Preload("AssetVersions").Find(&assets).Error
	return assets, err
}

func (repository *assetRepository) GetAssetByAssetVersionID(assetVersionID uuid.UUID) (models.Asset, error) {
	var asset models.Asset
	err := repository.db.Model(&models.AssetVersion{}).
		Select("assets.*").
		Joins("JOIN assets ON assets.id = asset_versions.asset_id").
		Where("asset_versions.id = ?", assetVersionID).
		First(&asset).Error
	return asset, err
}

func (repository *assetRepository) Delete(tx shared.DB, id uuid.UUID) error {
	asset := models.Asset{Model: models.Model{ID: id}}
	return repository.db.Select("AssetVersions").Delete(&asset).Error
}

func (repository *assetRepository) GetAssetIDByBadgeSecret(badgeSecret uuid.UUID) (models.Asset, error) {
	var asset models.Asset
	err := repository.db.Where("badge_secret = ?", badgeSecret).First(&asset).Error
	if err != nil {
		return models.Asset{}, err
	}
	return asset, nil
}

func (repository *assetRepository) ReadWithAssetVersions(assetID uuid.UUID) (models.Asset, error) {
	var asset models.Asset
	err := repository.db.Preload("AssetVersions").Where("id = ?", assetID).First(&asset).Error
	if err != nil {
		return models.Asset{}, err
	}
	return asset, nil
}

func (repository *assetRepository) firstFreeSlug(projectID uuid.UUID, assetSlug string) (string, error) {
	var slugs []string
	err := repository.db.Model(&models.Asset{}).
		Where("project_id = ? AND slug LIKE ?", projectID, assetSlug+"%").
		Pluck("slug", &slugs).Error
	if err != nil {
		return "", err
	}

	baseTaken := false
	existing := make(map[string]bool)
	for _, s := range slugs {
		existing[s] = true
		if s == assetSlug {
			baseTaken = true
		}
	}

	if !baseTaken {
		return assetSlug, nil
	}

	for i := 1; ; i++ {
		candidate := fmt.Sprintf("%s-%d", assetSlug, i)
		if !existing[candidate] {
			return candidate, nil
		}
	}
}

func (repository *assetRepository) GetAssetsWithVulnSharingEnabled(orgID uuid.UUID) ([]models.Asset, error) {
	var assets []models.Asset
	err := repository.db.Where("shares_information = true").Where(
		"EXISTS (SELECT 1 from projects where projects.id = assets.project_id AND projects.organization_id = ?)", orgID,
	).Preload("Project").Find(&assets).Error
	return assets, err
}
